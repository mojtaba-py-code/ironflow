"""Text-file connectors: CSV, JSON/JSON Lines and XML.

Transactional file writes
-------------------------
File sinks stage output in a sibling temporary file and only publish it in
:meth:`commit` - ``os.replace`` for overwrite (atomic on POSIX and on Windows),
an append of the staged bytes for append mode.  A crash or a validation failure
therefore leaves the previous file untouched instead of a half-written CSV that
the next job happily consumes.  ``rollback`` just deletes the staging file.

Security
--------
* Every path goes through :meth:`ConnectorRuntime.resolve_path`, which confines
  it to the configured data roots.
* XML is parsed with :mod:`defusedxml`, closing the billion-laughs / quadratic
  blowup / external-entity (XXE) class of attacks that the stock
  :mod:`xml.etree` parser is vulnerable to.
* CSV writing escapes leading ``= + - @`` so a value like ``=cmd|'/c calc'!A1``
  cannot become a formula when the export is opened in Excel (CSV injection).
* Reads are size-capped so a hostile 500 GB file cannot fill the disk cache.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ironflow.config.models import ConnectorSpec
from ironflow.connectors.base import BaseSink, BaseSource, ConnectorRuntime, sink, source
from ironflow.core.context import ExecutionContext, new_id
from ironflow.core.errors import ConfigurationError, ExtractionError, LoadingError
from ironflow.core.types import (
    DatasetSchema,
    LoadMode,
    Record,
    RecordBatch,
    RecordStream,
    infer_schema,
)

logger = logging.getLogger(__name__)

# csv.field_size_limit defaults to 131072; raise it but keep it bounded so a
# single pathological field cannot consume all available memory.
csv.field_size_limit(min(10 * 1024 * 1024, sys.maxsize))

#: Characters Excel interprets as the start of a formula.
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class FileConnectorMixin:
    """Path resolution and encoding options shared by file connectors."""

    def _resolve(self: Any, *, must_exist: bool) -> Path:
        raw = self.option("path", required=True)
        return self.runtime.resolve_path(str(raw), must_exist=must_exist)

    def _encoding(self: Any) -> str:
        return self.str_option("encoding", "utf-8")

    def _max_bytes(self: Any) -> int:
        return self.int_option("max_bytes", 5 * 1024**3, minimum=1)


# --------------------------------------------------------------------------- #
# CSV
# --------------------------------------------------------------------------- #
@source("csv")
class CsvSource(FileConnectorMixin, BaseSource):
    """Stream a delimited text file.

    Options: ``path`` (required), ``delimiter``, ``quotechar``, ``encoding``,
    ``skip_rows``, ``columns`` (explicit header for headerless files),
    ``has_header``, ``null_values``, ``strip_whitespace``, ``max_bytes``.
    """

    def read(self, context: ExecutionContext) -> RecordStream:
        path = self._resolve(must_exist=True)
        size = path.stat().st_size
        if size > self._max_bytes():
            raise ExtractionError(
                "source file exceeds the configured size limit",
                context={"path": str(path), "size": size, "limit": self._max_bytes()},
            )

        delimiter = self.str_option("delimiter", ",")
        if len(delimiter) != 1:
            raise ConfigurationError("delimiter must be a single character")
        quotechar = self.str_option("quotechar", '"') or '"'
        skip_rows = self.int_option("skip_rows", 0, minimum=0)
        has_header = self.bool_option("has_header", True)
        columns = self.list_option("columns")
        nulls = set(self.list_option("null_values", ["", "NULL", "null", "NA", "N/A"]))
        strip = self.bool_option("strip_whitespace", True)
        batch_size = self.batch_size

        def generate() -> Iterator[RecordBatch]:
            with path.open("r", encoding=self._encoding(), newline="", errors="replace") as handle:
                for _ in range(skip_rows):
                    handle.readline()

                reader = csv.DictReader(
                    handle,
                    delimiter=delimiter,
                    quotechar=quotechar,
                    fieldnames=columns or None,
                    restkey="__extra__",
                    restval=None,
                )
                if columns and has_header:
                    next(reader, None)  # explicit columns given: discard the header row

                buffer: list[Record] = []
                sequence = 0
                for row in reader:
                    context.cancellation.raise_if_cancelled()
                    buffer.append(_clean_row(row, nulls=nulls, strip=strip))
                    if len(buffer) >= batch_size:
                        yield RecordBatch(buffer, sequence=sequence, source=self.name)
                        sequence += 1
                        buffer = []
                if buffer:
                    yield RecordBatch(buffer, sequence=sequence, source=self.name)

        return generate()

    def describe(self) -> DatasetSchema:
        """Infer the schema from the first 200 rows without reading the file twice."""
        path = self._resolve(must_exist=True)
        delimiter = self.str_option("delimiter", ",")
        sample: list[Record] = []
        with path.open("r", encoding=self._encoding(), newline="", errors="replace") as handle:
            reader = csv.DictReader(handle, delimiter=delimiter)
            for index, row in enumerate(reader):
                if index >= 200:
                    break
                sample.append(dict(row))
        return infer_schema(sample)


def _clean_row(row: dict[str, Any], *, nulls: set[str], strip: bool) -> Record:
    """Normalise a raw CSV row: trim, map null tokens, drop the overflow key."""
    cleaned: Record = {}
    for key, value in row.items():
        if key == "__extra__" or key is None:
            continue
        if isinstance(value, str):
            text = value.strip() if strip else value
            cleaned[key] = None if text in nulls else text
        else:
            cleaned[key] = value
    return cleaned


class _StagedFileSink(FileConnectorMixin, BaseSink):
    """Base for sinks that stage to a temp file and publish on commit."""

    transactional = True

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._target: Path | None = None
        self._staging: Path | None = None
        self._handle: io.TextIOWrapper | None = None

    def _on_open(self, context: ExecutionContext) -> None:
        target = self._resolve(must_exist=False)
        target.parent.mkdir(parents=True, exist_ok=True)
        if self.mode is LoadMode.ERROR_IF_EXISTS and target.exists():
            raise LoadingError(
                "destination already exists and mode is error_if_exists",
                context={"path": str(target)},
            )
        self._target = target
        self._staging = target.with_name(f".{target.name}.{new_id()}.staging")
        self._handle = self._staging.open(
            "w", encoding=self._encoding(), newline="", errors="strict"
        )
        self.rows_written = 0

    def commit(self) -> None:
        """Publish the staged file atomically."""
        if self._handle is None or self._staging is None or self._target is None:
            return
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._handle.close()
        self._handle = None

        if self.mode is LoadMode.APPEND and self._target.exists():
            with (
                self._staging.open("r", encoding=self._encoding()) as src,
                self._target.open("a", encoding=self._encoding(), newline="") as dst,
            ):
                for chunk in iter(lambda: src.read(1024 * 1024), ""):
                    dst.write(chunk)
            self._staging.unlink(missing_ok=True)
        else:
            # Path.replace is os.replace: atomic on POSIX and on Windows.
            self._staging.replace(self._target)

        logger.info(
            "published %d rows to %s",
            self.rows_written,
            self._target.name,
            extra={"connector": self.name, "rows": self.rows_written},
        )

    def rollback(self) -> None:
        """Discard the staged file; the destination is untouched."""
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        if self._staging is not None:
            self._staging.unlink(missing_ok=True)
            logger.warning("rolled back %d staged rows for %s", self.rows_written, self.name)
        self.rows_written = 0

    def _on_close(self) -> None:
        if self._handle is not None:
            self._handle.close()
            self._handle = None
        # A staging file still present at close means neither commit nor
        # rollback ran (hard failure); do not leave litter behind.
        if self._staging is not None and self._staging.exists():
            self._staging.unlink(missing_ok=True)

    @property
    def target_exists_and_nonempty(self) -> bool:
        return (
            self._target is not None and self._target.exists() and self._target.stat().st_size > 0
        )


@sink("csv")
class CsvSink(_StagedFileSink):
    """Write records to a delimited text file.

    Options: ``path`` (required), ``delimiter``, ``encoding``, ``columns``,
    ``write_header``, ``escape_formulas``, ``null_value``.
    """

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._writer: csv.DictWriter[str] | None = None
        self._columns: list[str] = []
        self._dropped_columns: set[str] = set()

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        self._assert_writable()
        if batch.is_empty:
            return 0
        if self._writer is None:
            self._initialise_writer(batch)
        assert self._writer is not None

        escape = self.bool_option("escape_formulas", True)
        null_value = self.str_option("null_value", "")
        known = set(self._columns)

        for record in batch.records:
            extra = set(record) - known
            if extra:
                self._dropped_columns |= extra
            self._writer.writerow(
                {
                    column: _csv_value(record.get(column), null_value, escape)
                    for column in self._columns
                }
            )
        self.rows_written += len(batch)
        return len(batch)

    def _initialise_writer(self, batch: RecordBatch) -> None:
        assert self._handle is not None
        configured = self.list_option("columns")
        self._columns = configured or list(batch.columns())
        if not self._columns:
            raise LoadingError("cannot determine output columns", context={"sink": self.name})

        self._writer = csv.DictWriter(
            self._handle,
            fieldnames=self._columns,
            delimiter=self.str_option("delimiter", ","),
            extrasaction="ignore",
            lineterminator="\n",
        )
        write_header = self.bool_option("write_header", True)
        if write_header and not (self.mode is LoadMode.APPEND and self.target_exists_and_nonempty):
            self._writer.writeheader()

    def commit(self) -> None:
        if self._dropped_columns:
            # Loud, once, with the column names: silently dropping data is the
            # kind of bug that is found months later in a reconciliation.
            logger.warning(
                "columns not present in the CSV header were dropped: %s",
                sorted(self._dropped_columns),
                extra={"connector": self.name},
            )
        super().commit()


def _csv_value(value: Any, null_value: str, escape_formulas: bool) -> str:
    """Render a value for CSV, neutralising spreadsheet formula injection."""
    if value is None:
        return null_value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        text = json.dumps(value, ensure_ascii=False, default=str)
    else:
        text = str(value)
    if escape_formulas and text.startswith(_FORMULA_PREFIXES):
        # Leading apostrophe is the conventional Excel/LibreOffice neutraliser.
        return "'" + text
    return text


# --------------------------------------------------------------------------- #
# JSON / JSON Lines
# --------------------------------------------------------------------------- #
@source("json", "jsonl", "ndjson")
class JsonSource(FileConnectorMixin, BaseSource):
    """Read JSON Lines (streaming) or a JSON array/object (buffered).

    Options: ``path`` (required), ``format`` (``lines``|``array``|``auto``),
    ``root`` (dotted path to the array inside an object), ``encoding``.
    """

    def read(self, context: ExecutionContext) -> RecordStream:
        path = self._resolve(must_exist=True)
        fmt = self.str_option("format", "auto").lower()
        if fmt == "auto":
            fmt = "lines" if path.suffix.lower() in {".jsonl", ".ndjson"} else "array"

        if fmt == "lines":
            return self._read_lines(path, context)
        return self._read_array(path, context)

    def _read_lines(self, path: Path, context: ExecutionContext) -> RecordStream:
        batch_size = self.batch_size
        encoding = self._encoding()
        strict = self.bool_option("strict", True)

        def generate() -> Iterator[RecordBatch]:
            buffer: list[Record] = []
            sequence = 0
            with path.open("r", encoding=encoding, errors="replace") as handle:
                for line_number, line in enumerate(handle, start=1):
                    context.cancellation.raise_if_cancelled()
                    text = line.strip()
                    if not text:
                        continue
                    try:
                        record = json.loads(text)
                    except json.JSONDecodeError as exc:
                        if strict:
                            raise ExtractionError(
                                "malformed JSON line",
                                context={"path": str(path), "line": line_number},
                                cause=exc,
                            ) from exc
                        logger.warning("skipping malformed JSON at line %d", line_number)
                        continue
                    buffer.append(_as_record(record))
                    if len(buffer) >= batch_size:
                        yield RecordBatch(buffer, sequence=sequence, source=self.name)
                        sequence += 1
                        buffer = []
            if buffer:
                yield RecordBatch(buffer, sequence=sequence, source=self.name)

        return generate()

    def _read_array(self, path: Path, context: ExecutionContext) -> RecordStream:
        size = path.stat().st_size
        limit = self._max_bytes()
        if size > limit:
            raise ExtractionError(
                "JSON array files are read into memory; file exceeds max_bytes. "
                "Convert the export to JSON Lines to stream it.",
                context={"path": str(path), "size": size, "limit": limit},
            )
        try:
            payload = json.loads(path.read_text(encoding=self._encoding()))
        except json.JSONDecodeError as exc:
            raise ExtractionError(
                "file is not valid JSON", context={"path": str(path)}, cause=exc
            ) from exc

        root = self.str_option("root", "")
        if root:
            for part in root.split("."):
                if not isinstance(payload, dict) or part not in payload:
                    raise ExtractionError(
                        "root path not found in JSON document",
                        context={"path": str(path), "root": root},
                    )
                payload = payload[part]

        records = payload if isinstance(payload, list) else [payload]
        batch_size = self.batch_size

        def generate() -> Iterator[RecordBatch]:
            for index in range(0, len(records), batch_size):
                context.cancellation.raise_if_cancelled()
                chunk = [_as_record(item) for item in records[index : index + batch_size]]
                yield RecordBatch(chunk, sequence=index // batch_size, source=self.name)

        return generate()


def _as_record(value: Any) -> Record:
    """Wrap non-object JSON values so every record is a mapping."""
    if isinstance(value, dict):
        return value
    return {"value": value}


@sink("json", "jsonl", "ndjson")
class JsonSink(_StagedFileSink):
    """Write JSON Lines (default) or a JSON array.

    Options: ``path`` (required), ``format``, ``indent``, ``ensure_ascii``.
    JSON Lines is the default because it appends and streams; a JSON array
    cannot be appended to without rewriting the file.
    """

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._first = True

    @property
    def _format(self) -> str:
        fmt = self.str_option("format", "auto").lower()
        if fmt != "auto":
            return fmt
        path = str(self.option("path", ""))
        return "lines" if path.lower().endswith((".jsonl", ".ndjson")) else "array"

    def _on_open(self, context: ExecutionContext) -> None:
        super()._on_open(context)
        self._first = True
        if self._format == "array":
            assert self._handle is not None
            self._handle.write("[")

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        self._assert_writable()
        assert self._handle is not None
        ensure_ascii = self.bool_option("ensure_ascii", False)
        indent = self.option("indent")
        as_array = self._format == "array"

        for record in batch.records:
            text = json.dumps(
                record,
                ensure_ascii=ensure_ascii,
                default=str,
                indent=int(indent) if indent and as_array else None,
            )
            if as_array:
                self._handle.write(("" if self._first else ",\n") + text)
            else:
                self._handle.write(text + "\n")
            self._first = False

        self.rows_written += len(batch)
        return len(batch)

    def commit(self) -> None:
        if self._format == "array" and self._handle is not None:
            self._handle.write("]")
        super().commit()


# --------------------------------------------------------------------------- #
# XML
# --------------------------------------------------------------------------- #
@source("xml")
class XmlSource(FileConnectorMixin, BaseSource):
    """Stream records out of an XML document.

    Options: ``path`` (required), ``record_tag`` (required), ``attributes``
    (include element attributes, default true), ``text_key``.

    Parsed with ``defusedxml`` and freed incrementally: each matched element is
    cleared after conversion so peak memory stays proportional to one record,
    not to the document.
    """

    def read(self, context: ExecutionContext) -> RecordStream:
        try:
            from defusedxml.ElementTree import iterparse
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise ExtractionError(
                "the XML connector requires 'defusedxml' (pip install defusedxml)"
            ) from exc

        path = self._resolve(must_exist=True)
        record_tag = self.str_option("record_tag", required=True)
        include_attributes = self.bool_option("attributes", True)
        text_key = self.str_option("text_key", "#text")
        batch_size = self.batch_size

        def generate() -> Iterator[RecordBatch]:
            buffer: list[Record] = []
            sequence = 0
            # ``end`` events only: the element is complete and safe to convert.
            for _event, element in iterparse(str(path), events=("end",)):
                if _local_name(element.tag) != record_tag:
                    continue
                context.cancellation.raise_if_cancelled()
                buffer.append(
                    _element_to_record(
                        element, include_attributes=include_attributes, text_key=text_key
                    )
                )
                element.clear()  # release the subtree immediately
                if len(buffer) >= batch_size:
                    yield RecordBatch(buffer, sequence=sequence, source=self.name)
                    sequence += 1
                    buffer = []
            if buffer:
                yield RecordBatch(buffer, sequence=sequence, source=self.name)

        return generate()


def _local_name(tag: str) -> str:
    """Strip the ``{namespace}`` prefix ElementTree prepends to tags."""
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _element_to_record(element: Any, *, include_attributes: bool, text_key: str) -> Record:
    """Convert an XML element into a flat-ish mapping."""
    record: Record = {}
    if include_attributes:
        for key, attribute in element.attrib.items():
            record[f"@{_local_name(key)}"] = attribute

    children = list(element)
    if not children:
        text = (element.text or "").strip()
        if record:
            if text:
                record[text_key] = text
            return record
        return {text_key: text or None}

    for child in children:
        name = _local_name(child.tag)
        value: Any
        grandchildren = list(child)
        if grandchildren or child.attrib:
            value = _element_to_record(
                child, include_attributes=include_attributes, text_key=text_key
            )
        else:
            stripped = (child.text or "").strip()
            value = stripped or None
        if name in record:
            # Repeated tags become a list rather than overwriting.
            existing = record[name]
            record[name] = [*existing, value] if isinstance(existing, list) else [existing, value]
        else:
            record[name] = value
    return record


@sink("xml")
class XmlSink(_StagedFileSink):
    """Write records as a simple XML document.

    Options: ``path`` (required), ``root_tag``, ``record_tag``.
    Values are escaped with :func:`xml.sax.saxutils.escape`; element names are
    sanitised so a hostile column name cannot inject markup.
    """

    def _on_open(self, context: ExecutionContext) -> None:
        super()._on_open(context)
        assert self._handle is not None
        self._handle.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        self._handle.write(f"<{self.str_option('root_tag', 'records')}>\n")

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        from xml.sax.saxutils import escape

        self._assert_writable()
        assert self._handle is not None
        record_tag = _safe_tag(self.str_option("record_tag", "record"))

        for record in batch.records:
            self._handle.write(f"  <{record_tag}>\n")
            for key, value in record.items():
                tag = _safe_tag(key)
                text = "" if value is None else escape(str(value))
                self._handle.write(f"    <{tag}>{text}</{tag}>\n")
            self._handle.write(f"  </{record_tag}>\n")

        self.rows_written += len(batch)
        return len(batch)

    def commit(self) -> None:
        if self._handle is not None:
            self._handle.write(f"</{self.str_option('root_tag', 'records')}>\n")
        super().commit()


def _safe_tag(name: str) -> str:
    """Coerce an arbitrary column name into a valid XML element name."""
    cleaned = "".join(c if (c.isalnum() or c in "._-") else "_" for c in str(name))
    if not cleaned or not (cleaned[0].isalpha() or cleaned[0] == "_"):
        cleaned = f"_{cleaned}"
    return cleaned[:100]


__all__ = [
    "CsvSink",
    "CsvSource",
    "JsonSink",
    "JsonSource",
    "XmlSink",
    "XmlSource",
]
