"""Text-file connectors: CSV, JSON/JSON Lines and XML.

Transactional file writes
-------------------------
File sinks stage output in a sibling temporary file and only publish it in
:meth:`commit` - ``os.replace`` for overwrite (atomic on POSIX and on Windows),
an append of the staged text for append mode.  A crash or a validation failure
therefore leaves the previous file untouched instead of a half-written CSV that
the next job happily consumes.  ``rollback`` deletes the staging file, and
withdraws an append that was already published if a later destination in the
same load fails.  Everything that can fail short of the publish - closing the
document, flushing, fsync, opening the target for append - happens in
:meth:`prepare`, before any destination of the load is published.

Security
--------
* Every path goes through :meth:`ConnectorRuntime.resolve_path`, which confines
  it to the configured data roots.
* XML is parsed with :mod:`defusedxml`, closing the billion-laughs / quadratic
  blowup / external-entity (XXE) class of attacks that the stock
  :mod:`xml.etree` parser is vulnerable to.
* CSV writing escapes a leading ``= + - @``, TAB or CR - in values and in the
  header, whose names come from the data too - so ``=cmd|'/c calc'!A1`` cannot
  become a formula when the export is opened in Excel (CSV injection).
* Reads are size-capped so a hostile 500 GB file cannot fill the disk cache,
  and a delimited file's width is capped so a wide header cannot multiply the
  memory of every short row padded against it.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import sys
from collections.abc import Iterator
from functools import lru_cache
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

#: Default ``max_columns`` for delimited files: MySQL's hard limit and well past
#: any real table.  Each short row is padded to the header's width, so without a
#: cap a header of a million empty fields makes every one-byte row a
#: million-key record.
_DEFAULT_MAX_COLUMNS = 4096

#: Cells a batch may hold for every row of ``batch_size``.  Delimited and
#: spreadsheet records are rectangular - padded to the header - so a wide file
#: multiplies the memory of every row; its batches are cut shorter to stay within
#: ``batch_size * 256`` cells.  Files up to 256 columns wide get full batches.
_CELLS_PER_BATCH_ROW = 256

#: ``skip_rows`` discards preamble lines before the header; a million lines of
#: preamble is not a preamble.
_MAX_SKIP_ROWS = 1_000_000

#: Default ``max_bytes`` for a JSON array or object.  The standard library cannot
#: stream one, and the parsed document costs four to five times the file in
#: memory, so the 5 GiB default of the streaming formats would be an OOM switch;
#: this keeps a whole-document read to about half a gigabyte.
_JSON_DOCUMENT_MAX_BYTES = 100 * 1024**2

#: ``\uD800``-``\uDFFF`` escapes in JSON text: the only way a lone surrogate - a
#: string no UTF-8 encoder, Arrow or database driver accepts - reaches a record.
_SURROGATE_ESCAPE = re.compile(r"\\u[dD][89abcdefABCDEF]")
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")

#: XML 1.0's EncName production - the only shape an encoding declaration takes.
_XML_ENCODING_NAME = re.compile(r"[A-Za-z][A-Za-z0-9._-]*")

#: Characters XML 1.0 forbids anywhere in a document, escaped or not: C0 controls
#: other than TAB/LF/CR, lone surrogates, and the non-characters U+FFFE/U+FFFF.
#: Listed rather than written as the complement of the legal ranges: that form
#: needs astral ranges, which UTF-16-based analysers split into surrogate pairs.
_XML_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")


def _rows_per_batch(batch_size: int, width: int) -> int:
    """Rows per batch for rectangular records ``width`` cells wide."""
    return max(1, min(batch_size, batch_size * _CELLS_PER_BATCH_ROW // max(width, 1)))


def _replace_lone_surrogates(value: Any) -> Any:
    """Replace lone UTF-16 surrogates with U+FFFD throughout a decoded JSON value.

    ``json.loads`` turns a legal ``"\\ud83d"`` escape into a code point that no
    writer can encode: left in place, one such value fails the load on every
    retry and blocks the feed.  U+FFFD is what the lenient byte decoding
    (``errors="replace"``) already produces for undecodable input.
    """
    if isinstance(value, str):
        return value if value.isascii() else _LONE_SURROGATE.sub("\ufffd", value)
    if isinstance(value, dict):
        return {
            _replace_lone_surrogates(key): _replace_lone_surrogates(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_replace_lone_surrogates(item) for item in value]
    return value


def _xml_text(text: str) -> str:
    """Make ``text`` representable in XML 1.0 (and so in an .xlsx part).

    Escaping cannot help here: ``&#1;`` is as ill-formed as the raw control
    character.  The replacement is U+FFFD rather than nothing so the loss is
    visible in the output.
    """
    return _XML_ILLEGAL.sub("\ufffd", text)


def _refuse_directory_target(target: Path | None) -> None:
    """Fail ``prepare`` - not the publish - when a directory occupies the target."""
    if target is not None and target.is_dir():
        raise LoadingError("destination path is a directory", context={"path": str(target)})


def _report_unwithdrawable(sink: BaseSink, published: bool, target: Path | None) -> None:
    """Log that a rolled-back sink had already replaced its target.

    Reached when this sink is a load's reject destination: rejects are published
    before the main data, and a replaced file cannot be put back if the main
    publish then fails.  A retry replaces it again, so nothing accumulates.
    """
    if published and target is not None:
        logger.warning(
            "%s was already published to %s and cannot be withdrawn", sink.name, target.name
        )


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
    ``skip_rows`` (preamble lines before the header, at most 1,000,000),
    ``columns`` (explicit header for headerless files), ``has_header``,
    ``null_values``, ``strip_whitespace``, ``max_bytes``, ``max_columns``
    (default 4096).

    Memory per batch is bounded whatever the file's shape: the header may not be
    wider than ``max_columns``, and batches of files wider than 256 columns are
    cut proportionally shorter than ``batch_size``.
    """

    supports_incremental = False

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        # Checked here rather than at read time so ``pipeline validate`` reports them.
        self._skip_rows()
        self._max_columns()

    def _skip_rows(self) -> int:
        return self.int_option("skip_rows", 0, minimum=0, maximum=_MAX_SKIP_ROWS)

    def _max_columns(self) -> int:
        return self.int_option("max_columns", _DEFAULT_MAX_COLUMNS, minimum=1)

    def _check_width(self, path: Path, fieldnames: Any) -> int:
        width = len(fieldnames or ())
        if width > self._max_columns():
            raise ExtractionError(
                "the CSV header has more columns than 'max_columns' allows; raise the "
                "option if the file is genuinely this wide",
                context={"path": str(path), "columns": width, "max_columns": self._max_columns()},
            )
        return width

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
        skip_rows = self._skip_rows()
        has_header = self.bool_option("has_header", True)
        columns = self.list_option("columns")
        nulls = set(self.list_option("null_values", ["", "NULL", "null", "NA", "N/A"]))
        strip = self.bool_option("strip_whitespace", True)
        batch_size = self.batch_size

        def generate() -> Iterator[RecordBatch]:
            with path.open("r", encoding=self._encoding(), newline="", errors="replace") as handle:
                _skip_lines(handle, skip_rows, context)

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
                rows_per_batch = _rows_per_batch(
                    batch_size, self._check_width(path, reader.fieldnames)
                )

                buffer: list[Record] = []
                sequence = 0
                for row in reader:
                    context.cancellation.raise_if_cancelled()
                    buffer.append(_clean_row(row, nulls=nulls, strip=strip))
                    if len(buffer) >= rows_per_batch:
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
            self._check_width(path, reader.fieldnames)
            for index, row in enumerate(reader):
                if index >= 200:
                    break
                sample.append(dict(row))
        return infer_schema(sample)


def _skip_lines(handle: io.TextIOWrapper, count: int, context: ExecutionContext) -> None:
    """Discard up to ``count`` preamble lines.

    This runs before the first batch - so before the task timeout is ever
    checked - which is why it stops at end of file and polls for cancellation
    instead of trusting ``count``.
    """
    for skipped in range(count):
        if skipped % 1024 == 0:
            context.cancellation.raise_if_cancelled()
        if not handle.readline():
            return


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
    supported_modes = frozenset({LoadMode.APPEND, LoadMode.OVERWRITE, LoadMode.ERROR_IF_EXISTS})

    #: What happens to text the output encoding cannot represent - in UTF-8 only
    #: a lone surrogate (a JSON ``\ud83d`` escape that reached the sink from a
    #: source that does not clean them), in a legacy encoding anything outside
    #: it.  ``strict`` failed the load on every retry of the same row and blocked
    #: the feed; a backslash escape keeps the row, visibly, and inside a JSON
    #: string it is exactly the JSON escape the value arrived as.
    _encoding_errors = "backslashreplace"

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._target: Path | None = None
        self._staging: Path | None = None
        self._handle: io.TextIOWrapper | None = None
        self._append_handle: io.TextIOWrapper | None = None
        #: Size of the target before our append started; set while an append
        #: can still be withdrawn by truncating back to it.
        self._append_offset: int | None = None
        self._prepared = False
        self._published = False

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
            "w", encoding=self._encoding(), newline="", errors=self._encoding_errors
        )
        self.rows_written = 0

    def _finish_document(self, handle: io.TextIOWrapper) -> None:
        """Write whatever closes the document (a JSON array's ``]``, XML's end tag)."""

    def prepare(self) -> None:
        """Finish and fsync the staged file and make sure the target can take it."""
        if self._prepared or self._handle is None or self._target is None:
            return
        self._finish_document(self._handle)
        self._handle.flush()
        os.fsync(self._handle.fileno())
        self._handle.close()
        self._handle = None

        _refuse_directory_target(self._target)
        if self.mode is LoadMode.APPEND and self._target.exists():
            # Opened now, not at publish time: a target that cannot be appended
            # to (read-only, locked by another process on Windows) must fail
            # while no destination of the load has been published yet.
            self._append_handle = self._target.open("a", encoding=self._encoding(), newline="")
        self._prepared = True

    def commit(self) -> None:
        """Publish the staged file: replace the target atomically, or append to it."""
        self.prepare()
        if not self._prepared or self._published:
            return
        assert self._staging is not None and self._target is not None
        if self._append_handle is not None:
            self._append_staged(self._append_handle)
        else:
            # Path.replace is os.replace: atomic on POSIX and on Windows.
            self._staging.replace(self._target)
        self._published = True

        logger.info(
            "published %d rows to %s",
            self.rows_written,
            self._target.name,
            extra={"connector": self.name, "rows": self.rows_written},
        )

    def _append_staged(self, target: io.TextIOWrapper) -> None:
        assert self._staging is not None
        self._append_offset = os.fstat(target.fileno()).st_size
        # newline="" on the read side too: universal-newline decoding turned the
        # CRLF inside a quoted CSV field into LF, altering appended values.
        with self._staging.open("r", encoding=self._encoding(), newline="") as staged:
            for chunk in iter(lambda: staged.read(1024 * 1024), ""):
                target.write(chunk)
        target.flush()
        os.fsync(target.fileno())
        target.close()
        self._append_handle = None
        self._staging.unlink(missing_ok=True)

    def rollback(self) -> None:
        """Discard the staged file and withdraw an append this sink published.

        The load engine publishes the reject destination before the main one;
        if the main publish then fails, this is what takes the appended rejects
        back out, so a retry does not append them a second time.  A replaced
        file cannot be withdrawn - the previous version is gone - and says so.
        """
        self._close_handles()
        if self._append_offset is not None and self._target is not None:
            os.truncate(self._target, self._append_offset)
            self._append_offset = None
            logger.warning(
                "%s: withdrew the %d rows it had appended to %s",
                self.name,
                self.rows_written,
                self._target.name,
            )
        else:
            _report_unwithdrawable(self, self._published, self._target)
        if self._staging is not None:
            self._staging.unlink(missing_ok=True)
            logger.warning("rolled back %d staged rows for %s", self.rows_written, self.name)
        self.rows_written = 0

    def _close_handles(self) -> None:
        for handle in (self._handle, self._append_handle):
            if handle is not None:
                try:
                    handle.close()
                except OSError:
                    # Closing flushes; after a failed write (a full disk) that
                    # fails again.  The descriptor is released regardless.
                    logger.debug("closing a handle of %s failed", self.name, exc_info=True)
        self._handle = None
        self._append_handle = None

    def _on_close(self) -> None:
        self._close_handles()
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
            # Column names come from the data - a CSV header, JSON keys - so they
            # are as untrusted as the values and get the same neutralisation.
            escape = self.bool_option("escape_formulas", True)
            self._writer.writerow(
                {column: _csv_value(column, "", escape) for column in self._columns}
            )

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
    """Read JSON Lines (streaming) or a JSON array/object (whole document).

    Options: ``path`` (required), ``format`` (``lines``|``array``|``auto``),
    ``root`` (dotted path to the array inside an object), ``encoding``,
    ``strict``, ``max_bytes``.

    JSON Lines is the streaming format: memory follows ``batch_size``.  A JSON
    array or object cannot be streamed with the standard library - it is parsed
    whole, at four to five times the file size in memory - so its ``max_bytes``
    defaults to 100 MiB instead of 5 GiB.  Convert large exports to JSON Lines.

    Lone surrogates (``"\\ud83d"``, legal JSON that no encoder accepts) are
    replaced with U+FFFD as the file is decoded.
    """

    supports_incremental = False

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
                    if _SURROGATE_ESCAPE.search(text):
                        record = _replace_lone_surrogates(record)
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
        limit = self.int_option("max_bytes", _JSON_DOCUMENT_MAX_BYTES, minimum=1)
        if size > limit:
            raise ExtractionError(
                "JSON array files are read into memory; file exceeds max_bytes. "
                "Convert the export to JSON Lines to stream it.",
                context={"path": str(path), "size": size, "limit": limit},
            )
        # errors="replace" as for JSON Lines: one undecodable byte must not fail
        # every run of the feed with a raw UnicodeDecodeError.
        text = path.read_text(encoding=self._encoding(), errors="replace")
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as exc:
            raise ExtractionError(
                "file is not valid JSON", context={"path": str(path)}, cause=exc
            ) from exc
        has_surrogates = _SURROGATE_ESCAPE.search(text) is not None
        del text  # the parsed payload is the only copy worth keeping

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
                chunk = records[index : index + batch_size]
                if has_surrogates:
                    chunk = [_replace_lone_surrogates(item) for item in chunk]
                yield RecordBatch(
                    [_as_record(item) for item in chunk],
                    sequence=index // batch_size,
                    source=self.name,
                )

        return generate()


def _as_record(value: Any) -> Record:
    """Wrap non-object JSON values so every record is a mapping."""
    if isinstance(value, dict):
        return value
    return {"value": value}


@sink("json", "jsonl", "ndjson")
class JsonSink(_StagedFileSink):
    """Write JSON Lines or a JSON array.

    Options: ``path`` (required), ``format``, ``indent``, ``ensure_ascii``.
    JSON Lines (``.jsonl``/``.ndjson`` or ``format: lines``) appends and
    streams.  A JSON array cannot be appended to without rewriting the file -
    appending produced ``[...][...]`` - so it supports ``overwrite`` (its
    default) and ``error_if_exists`` only.
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

    def accepted_modes(self) -> frozenset[LoadMode]:
        if self._format == "array":
            return frozenset({LoadMode.OVERWRITE, LoadMode.ERROR_IF_EXISTS})
        return self.supported_modes

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

    def _finish_document(self, handle: io.TextIOWrapper) -> None:
        if self._format == "array":
            handle.write("]")


# --------------------------------------------------------------------------- #
# XML
# --------------------------------------------------------------------------- #
@source("xml")
class XmlSource(FileConnectorMixin, BaseSource):
    """Stream records out of an XML document.

    Options: ``path`` (required), ``record_tag`` (required), ``attributes``
    (include element attributes, default true), ``text_key``, ``max_bytes``.

    Parsed with ``defusedxml`` and freed incrementally: once a record has been
    converted - or any element outside a record has ended - it is cleared *and*
    detached from its parent, so peak memory stays proportional to one record,
    not to the document.  ``clear()`` alone empties an element but leaves it
    attached, and a million emptied records hanging off the root is still a
    million objects.
    """

    supports_incremental = False

    def read(self, context: ExecutionContext) -> RecordStream:
        try:
            from defusedxml.ElementTree import iterparse
        except ImportError as exc:  # pragma: no cover - dependency guard
            raise ExtractionError(
                "the XML connector requires 'defusedxml' (pip install defusedxml)"
            ) from exc

        path = self._resolve(must_exist=True)
        size = path.stat().st_size
        if size > self._max_bytes():
            raise ExtractionError(
                "source file exceeds the configured size limit",
                context={"path": str(path), "size": size, "limit": self._max_bytes()},
            )
        record_tag = self.str_option("record_tag", required=True)
        include_attributes = self.bool_option("attributes", True)
        text_key = self.str_option("text_key", "#text")
        batch_size = self.batch_size

        def generate() -> Iterator[RecordBatch]:
            buffer: list[Record] = []
            sequence = 0
            ancestors: list[Any] = []  # the open elements; the last is the parent
            open_records = 0
            for event, element in iterparse(str(path), events=("start", "end")):
                is_record = _local_name(element.tag) == record_tag
                if event == "start":
                    ancestors.append(element)
                    if is_record:
                        open_records += 1
                    continue
                ancestors.pop()
                if is_record:
                    open_records -= 1
                    context.cancellation.raise_if_cancelled()
                    buffer.append(
                        _element_to_record(
                            element, include_attributes=include_attributes, text_key=text_key
                        )
                    )
                elif open_records:
                    continue  # a field of a record still being parsed
                element.clear()
                if ancestors:
                    ancestors[-1].remove(element)
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
    The output is always well-formed: values are escaped with
    :func:`xml.sax.saxutils.escape` after characters XML 1.0 cannot carry at all
    (``\\x01``, lone surrogates) are replaced with U+FFFD, and every element
    name - columns, ``record_tag`` and ``root_tag`` alike - is sanitised so a
    hostile name cannot inject markup.  A document cannot be appended to, so
    the modes are ``overwrite`` (the default) and ``error_if_exists``.
    """

    supported_modes = frozenset({LoadMode.OVERWRITE, LoadMode.ERROR_IF_EXISTS})
    #: Character references are XML's own lossless escape for a character the
    #: file's encoding lacks.
    _encoding_errors = "xmlcharrefreplace"

    @property
    def _root_tag(self) -> str:
        return _safe_tag(self.str_option("root_tag", "records"))

    def _on_open(self, context: ExecutionContext) -> None:
        # The declaration names the encoding the file is actually written in -
        # it used to say UTF-8 whatever `encoding` was, which a strict parser
        # reads as a corrupt document. The name comes from the pipeline file,
        # so it must match XML's own EncName grammar before it is written into
        # the prolog.
        encoding = self._encoding()
        if not _XML_ENCODING_NAME.fullmatch(encoding):
            raise ConfigurationError(
                "encoding is not a valid XML encoding name",
                context={"sink": self.name, "encoding": encoding[:40]},
            )
        super()._on_open(context)
        assert self._handle is not None
        self._handle.write(f'<?xml version="1.0" encoding="{encoding}"?>\n')
        self._handle.write(f"<{self._root_tag}>\n")

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        from xml.sax.saxutils import escape

        self._assert_writable()
        assert self._handle is not None
        record_tag = _safe_tag(self.str_option("record_tag", "record"))

        for record in batch.records:
            self._handle.write(f"  <{record_tag}>\n")
            for key, value in record.items():
                tag = _safe_tag(key)
                text = "" if value is None else escape(_xml_text(str(value)))
                self._handle.write(f"    <{tag}>{text}</{tag}>\n")
            self._handle.write(f"  </{record_tag}>\n")

        self.rows_written += len(batch)
        return len(batch)

    def _finish_document(self, handle: io.TextIOWrapper) -> None:
        handle.write(f"</{self._root_tag}>\n")


@lru_cache(maxsize=4096, typed=True)
def _safe_tag(name: str) -> str:
    """Coerce an arbitrary column name into a valid XML element name.

    Cached: it runs for every key of every record, over a handful of names.
    """
    cleaned = "".join(c if (c.isalnum() or c in "._-") else "_" for c in str(name))
    if not cleaned or not (cleaned[0].isalpha() or cleaned[0] == "_"):
        cleaned = f"_{cleaned}"
    cleaned = cleaned[:100]
    if not cleaned.isascii() and not _is_xml_name(cleaned):
        # ``str.isalnum`` is Unicode-wide and XML's name rules are narrower: a
        # superscript digit, the micro sign or a titlecase digraph passes the
        # first and fails the parser.  Keep any name the parser accepts - accented
        # Latin, CJK - and fall back to ASCII for the rest.  The first character
        # is already a letter or "_", so it stays a valid name start.
        cleaned = "".join(c if c.isascii() else "_" for c in cleaned)
    return cleaned


def _is_xml_name(name: str) -> bool:
    """True when the XML parser accepts ``name`` as an element name.

    ``name`` only holds letters, digits and ``._-`` here, so the probe document
    cannot contain markup of its own.
    """
    from defusedxml.ElementTree import ParseError, fromstring

    try:
        fromstring(f"<{name}/>")
    except ParseError:
        return False
    return True


__all__ = [
    "CsvSink",
    "CsvSource",
    "JsonSink",
    "JsonSource",
    "XmlSink",
    "XmlSource",
]
