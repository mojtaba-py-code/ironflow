"""Columnar and spreadsheet connectors: Parquet and Excel.

Both depend on optional extras (``columnar`` and ``excel``).  The
imports are deferred to the first read/write so that a deployment that only
moves CSV and SQL data does not carry ``pyarrow`` (~90 MB) in its image.

Parquet
-------
Read in batches - a file row-group by row-group, a directory as a dataset
scanned batch by batch - rather than whole, so memory stays bounded even for
multi-gigabyte inputs.  Written through a staging file and published on commit,
matching the transactional behaviour of the text sinks.

Excel
-----
Read with ``openpyxl``'s ``read_only`` mode, which uses a streaming XML parser
instead of building the whole workbook object graph; rows are read no wider
than the header.  On write, values and header cells that begin with a formula
character are prefixed so an exported cell cannot execute as a formula, and
``write_only`` mode keeps memory flat.

Excel's hard limit of 1,048,576 rows per sheet is enforced explicitly - silently
truncating an export is far worse than failing it.

Both formats are written whole, so neither can be appended to: their sinks
support ``overwrite`` (the default) and ``error_if_exists``.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable, Iterator
from datetime import date, datetime, time
from decimal import Decimal
from pathlib import Path
from typing import Any

from ironflow.config.models import ConnectorSpec
from ironflow.connectors.base import BaseSink, BaseSource, ConnectorRuntime, sink, source
from ironflow.connectors.files import (
    _FORMULA_PREFIXES,
    FileConnectorMixin,
    _refuse_directory_target,
    _report_unwithdrawable,
    _rows_per_batch,
    _xml_text,
)
from ironflow.core.context import ExecutionContext, new_id
from ironflow.core.errors import ExtractionError, LoadingError
from ironflow.core.extras import install_hint
from ironflow.core.types import DatasetSchema, LoadMode, Record, RecordBatch, RecordStream

logger = logging.getLogger(__name__)

EXCEL_MAX_ROWS = 1_048_576


def _require(module: str, extra: str) -> Any:
    """Import an optional dependency with an actionable error message."""
    import importlib

    try:
        return importlib.import_module(module)
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise ExtractionError(
            f"this connector requires the '{extra}' extra: {install_hint(extra)}",
            context={"module": module},
        ) from exc


# --------------------------------------------------------------------------- #
# Parquet
# --------------------------------------------------------------------------- #
@source("parquet")
class ParquetSource(FileConnectorMixin, BaseSource):
    """Read a Parquet file, or a directory of them, in batches.

    Options: ``path`` (required), ``columns`` (projection pushdown).

    A directory is read as a dataset - hive-style ``key=value`` sub-directories
    become columns, names starting with ``.`` or ``_`` are skipped, as pyarrow
    does - but its files are listed here and each one is confined to the data
    roots before it is opened.  Confining only the directory let a symlink or
    junction inside it read any file on the host.
    """

    supports_incremental = False

    def read(self, context: ExecutionContext) -> RecordStream:
        pq = _require("pyarrow.parquet", "columnar")
        path = self._resolve(must_exist=True)
        columns = self.list_option("columns") or None
        batch_size = self.batch_size

        def generate() -> Iterator[RecordBatch]:
            # Projection is pushed into the reader: unread columns are never
            # decompressed, which is the main reason to use Parquet at all.
            if path.is_file():
                batches = pq.ParquetFile(str(path)).iter_batches(
                    batch_size=batch_size, columns=columns
                )
            else:
                # Minimal read-ahead: the defaults keep up to 16 batches of each
                # of 4 files in flight, several times the memory batch_size promises.
                batches = self._dataset(path).to_batches(
                    columns=columns, batch_size=batch_size, batch_readahead=1, fragment_readahead=1
                )
            sequence = 0
            for record_batch in batches:
                context.cancellation.raise_if_cancelled()
                if record_batch.num_rows == 0:
                    continue
                yield RecordBatch(record_batch.to_pylist(), sequence=sequence, source=self.name)
                sequence += 1

        return generate()

    def _dataset(self, directory: Path) -> Any:
        ds = _require("pyarrow.dataset", "columnar")
        files = _dataset_files(directory, self.runtime.resolve_path)
        return ds.dataset(
            [str(file) for file in files],
            format="parquet",
            # infer_dictionary matches what pq.read_table produced for a directory.
            partitioning=ds.HivePartitioning.discover(infer_dictionary=True),
            partition_base_dir=str(directory),
        )

    def describe(self) -> DatasetSchema:
        pq = _require("pyarrow.parquet", "columnar")
        from ironflow.core.types import FieldSchema, FieldType

        path = self._resolve(must_exist=True)
        # read_schema only takes a file; handed a directory it failed outright.
        arrow_schema = pq.read_schema(str(path)) if path.is_file() else self._dataset(path).schema
        mapping = {
            "int": FieldType.INTEGER,
            "float": FieldType.FLOAT,
            "double": FieldType.FLOAT,
            "bool": FieldType.BOOLEAN,
            "string": FieldType.STRING,
            "date": FieldType.DATE,
            "timestamp": FieldType.DATETIME,
            "decimal": FieldType.DECIMAL,
        }
        fields = []
        for field in arrow_schema:
            arrow_type = str(field.type)
            logical = next(
                (v for k, v in mapping.items() if arrow_type.startswith(k)), FieldType.UNKNOWN
            )
            fields.append(FieldSchema(name=field.name, type=logical, nullable=field.nullable))
        return DatasetSchema(tuple(fields))

    def count(self) -> int | None:
        pq = _require("pyarrow.parquet", "columnar")
        path = self._resolve(must_exist=True)
        if path.is_file():
            return int(pq.ParquetFile(str(path)).metadata.num_rows)
        return None


def _dataset_files(directory: Path, resolve: Callable[..., Path]) -> list[Path]:
    """List a Parquet dataset's files, each resolved inside the data roots.

    Walks like pyarrow's discovery - recursively, skipping names that start with
    ``.`` or ``_`` (``_SUCCESS``, ``.crc``, ``_temporary/``) - and passes every
    directory and file through ``resolve``, so a link pointing out of the roots
    fails the read instead of being followed.  Resolved directories are
    remembered, so a link back to an ancestor cannot make the walk endless.
    """
    files: list[Path] = []
    visited: set[Path] = set()
    for current, dirnames, filenames in os.walk(directory, followlinks=True):
        real = resolve(current, must_exist=True)
        if real in visited:
            dirnames[:] = []
            continue
        visited.add(real)
        dirnames[:] = sorted(name for name in dirnames if not name.startswith((".", "_")))
        files.extend(
            resolve(Path(current) / name, must_exist=True)
            for name in sorted(filenames)
            if not name.startswith((".", "_"))
        )
    return files


@sink("parquet")
class ParquetSink(FileConnectorMixin, BaseSink):
    """Write Parquet with compression, staged and published on commit.

    Options: ``path`` (required), ``compression`` (default ``snappy``),
    ``row_group_size``.  A Parquet file cannot be appended to - it would have to
    be rewritten - so the modes are ``overwrite`` (the default) and
    ``error_if_exists``; for incremental output write one file per run into a
    partitioned directory.
    """

    transactional = True
    supported_modes = frozenset({LoadMode.OVERWRITE, LoadMode.ERROR_IF_EXISTS})

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._writer: Any = None
        self._target: Path | None = None
        self._staging: Path | None = None
        self._schema: Any = None
        self._published = False

    def _on_open(self, context: ExecutionContext) -> None:
        target = self._resolve(must_exist=False)
        target.parent.mkdir(parents=True, exist_ok=True)
        if self.mode is LoadMode.ERROR_IF_EXISTS and target.exists():
            raise LoadingError("destination already exists", context={"path": str(target)})
        self._target = target
        self._staging = target.with_name(f".{target.name}.{new_id()}.staging")
        self.rows_written = 0

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        self._assert_writable()
        if batch.is_empty:
            return 0
        pa = _require("pyarrow", "columnar")
        pq = _require("pyarrow.parquet", "columnar")

        table = pa.Table.from_pylist(batch.records)
        if self._writer is None:
            self._schema = table.schema
            self._writer = pq.ParquetWriter(
                str(self._staging),
                self._schema,
                compression=self.str_option("compression", "snappy"),
            )
        elif not table.schema.equals(self._schema):
            # Late-arriving columns would corrupt the file; cast to the schema
            # fixed by the first batch and report the drift.
            try:
                table = table.cast(self._schema)
            # pyarrow raises a plain ValueError when the *field names* differ and
            # an ArrowError when only the types do; catching just the Arrow ones
            # let a mismatched-columns batch escape as a raw traceback.
            except (pa.ArrowInvalid, pa.ArrowNotImplementedError, ValueError, TypeError) as exc:
                raise LoadingError(
                    "batch schema is incompatible with the file schema; "
                    "add a 'select_columns' transformation to stabilise it",
                    context={"sink": self.name, "detail": str(exc)[:200]},
                    cause=exc,
                ) from exc

        self._writer.write_table(table, row_group_size=self.int_option("row_group_size", 50_000))
        self.rows_written += len(batch)
        return len(batch)

    def prepare(self) -> None:
        """Write the footer - the step that can still fail - without publishing."""
        if self._writer is not None:
            self._writer.close()
            self._writer = None
        _refuse_directory_target(self._target)

    def commit(self) -> None:
        self.prepare()
        if self._staging is not None and self._staging.exists() and self._target is not None:
            self._staging.replace(self._target)  # atomic on POSIX and Windows
            self._published = True
            logger.info("published %d rows to %s", self.rows_written, self._target.name)

    def rollback(self) -> None:
        if self._writer is not None:
            self._writer.close()
            self._writer = None
        if self._staging is not None:
            self._staging.unlink(missing_ok=True)
        _report_unwithdrawable(self, self._published, self._target)
        self.rows_written = 0

    def _on_close(self) -> None:
        if self._writer is not None:
            self._writer.close()
            self._writer = None
        if self._staging is not None and self._staging.exists():
            self._staging.unlink(missing_ok=True)


# --------------------------------------------------------------------------- #
# Excel
# --------------------------------------------------------------------------- #
@source("excel", "xlsx")
class ExcelSource(FileConnectorMixin, BaseSource):
    """Read a worksheet in streaming (read-only) mode.

    Options: ``path`` (required), ``sheet`` (name or index, default first),
    ``header_row`` (1-based, default 1), ``skip_rows``, ``columns``.

    Records are exactly as wide as the header (or ``columns``): cells to its
    right are ignored, as a CSV reader ignores fields beyond its header.
    """

    supports_incremental = False

    def read(self, context: ExecutionContext) -> RecordStream:
        openpyxl = _require("openpyxl", "excel")
        path = self._resolve(must_exist=True)
        sheet_ref = self.option("sheet")
        header_row = self.int_option("header_row", 1, minimum=1)
        skip_rows = self.int_option("skip_rows", 0, minimum=0)
        batch_size = self.batch_size
        configured_columns = self.list_option("columns")

        def generate() -> Iterator[RecordBatch]:
            # read_only + data_only: stream cells, and read cached formula
            # results rather than the formula text.
            workbook = openpyxl.load_workbook(
                str(path), read_only=True, data_only=True, keep_links=False
            )
            try:
                worksheet = _select_sheet(workbook, sheet_ref)
                headers = list(configured_columns) or _excel_headers(
                    next(
                        worksheet.iter_rows(
                            min_row=header_row, max_row=header_row, values_only=True
                        ),
                        (),
                    )
                )
                if not headers:
                    _refuse_headerless(worksheet, header_row, path)
                    return
                rows_per_batch = _rows_per_batch(batch_size, len(headers))
                buffer: list[Record] = []
                sequence = 0
                data_rows_seen = 0

                # openpyxl pads every row to the sheet's widest used column: one
                # stray cell in column XFD made each record 16,384 keys wide.
                # Bounding the read to the header keeps a record header-sized.
                for row in worksheet.iter_rows(
                    min_row=header_row + 1, max_col=len(headers), values_only=True
                ):
                    context.cancellation.raise_if_cancelled()
                    if all(cell is None for cell in row):
                        continue
                    data_rows_seen += 1
                    if data_rows_seen <= skip_rows:
                        continue

                    # Excel does not store trailing empty cells, so a short row
                    # is padded against the header to keep records rectangular.
                    buffer.append(
                        {
                            name: _excel_value(row[position] if position < len(row) else None)
                            for position, name in enumerate(headers)
                        }
                    )
                    if len(buffer) >= rows_per_batch:
                        yield RecordBatch(buffer, sequence=sequence, source=self.name)
                        sequence += 1
                        buffer = []
                if buffer:
                    yield RecordBatch(buffer, sequence=sequence, source=self.name)
            finally:
                workbook.close()

        return generate()


def _excel_headers(cells: tuple[Any, ...]) -> list[str]:
    """Column names from the header row, which openpyxl pads to the sheet width.

    Trailing empty cells are that padding, not columns; an empty cell between
    two names becomes ``column_<n>``.
    """
    width = len(cells)
    while width and cells[width - 1] is None:
        width -= 1
    return [
        str(cell).strip() if cell is not None else f"column_{position}"
        for position, cell in enumerate(cells[:width], start=1)
    ]


def _refuse_headerless(worksheet: Any, header_row: int, path: Path) -> None:
    """An empty header row is fine on an empty sheet and a mistake above data.

    Without names there is no width to bound the rows by, and reading them
    unbounded is exactly the padding problem the header width exists to stop.
    """
    if next(worksheet.iter_rows(min_row=header_row + 1, max_col=1, values_only=True), None):
        raise ExtractionError(
            "the header row is empty; set 'header_row' to the row holding the column "
            "names, or list them in 'columns'",
            context={"path": str(path), "header_row": header_row},
        )


def _select_sheet(workbook: Any, reference: Any) -> Any:
    if reference is None:
        return workbook.worksheets[0]
    if isinstance(reference, int):
        try:
            return workbook.worksheets[reference]
        except IndexError as exc:
            raise ExtractionError(
                "worksheet index out of range", context={"index": reference}
            ) from exc
    name = str(reference)
    if name not in workbook.sheetnames:
        raise ExtractionError(
            "worksheet not found",
            context={"sheet": name, "available": list(workbook.sheetnames)},
        )
    return workbook[name]


def _excel_value(value: Any) -> Any:
    """Normalise openpyxl cell values into JSON-friendly Python types."""
    if isinstance(value, (datetime, date, time)):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, str):
        stripped = value.strip()
        return stripped or None
    return value


@sink("excel", "xlsx")
class ExcelSink(FileConnectorMixin, BaseSink):
    """Write a worksheet in write-only (streaming) mode.

    Options: ``path`` (required), ``sheet``, ``columns``, ``write_header``,
    ``escape_formulas``, ``freeze_header``.  A workbook is written whole, so the
    modes are ``overwrite`` (the default) and ``error_if_exists``; ``append``
    used to replace the file without a word.
    """

    transactional = True
    supported_modes = frozenset({LoadMode.OVERWRITE, LoadMode.ERROR_IF_EXISTS})

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._workbook: Any = None
        self._worksheet: Any = None
        self._columns: list[str] = []
        self._target: Path | None = None
        self._staging: Path | None = None
        self._published = False

    def _on_open(self, context: ExecutionContext) -> None:
        openpyxl = _require("openpyxl", "excel")
        target = self._resolve(must_exist=False)
        target.parent.mkdir(parents=True, exist_ok=True)
        if self.mode is LoadMode.ERROR_IF_EXISTS and target.exists():
            raise LoadingError("destination already exists", context={"path": str(target)})
        self._target = target
        self._staging = target.with_name(f".{target.name}.{new_id()}.staging")
        self._workbook = openpyxl.Workbook(write_only=True)
        self._worksheet = self._workbook.create_sheet(self.str_option("sheet", "Sheet1"))
        self._columns = self.list_option("columns")
        self._header_written = False
        self.rows_written = 0

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        self._assert_writable()
        if batch.is_empty:
            return 0
        escape = self.bool_option("escape_formulas", True)
        if not self._columns:
            self._columns = list(batch.columns())
        if not self._header_written:
            # Written whether the columns came from `columns:` or from the data;
            # with `columns:` set, the sheet used to start at the first data row.
            self._header_written = True
            if self.bool_option("write_header", True):
                # Column names come from the data, and openpyxl stores any string
                # starting with "=" as a live formula - header cells included.
                self._worksheet.append([_excel_out(column, escape) for column in self._columns])

        if self.rows_written + len(batch) > EXCEL_MAX_ROWS:
            raise LoadingError(
                "output exceeds Excel's row limit; write Parquet or CSV instead",
                context={"limit": EXCEL_MAX_ROWS, "rows": self.rows_written + len(batch)},
            )

        for record in batch.records:
            self._worksheet.append(
                [_excel_out(record.get(column), escape) for column in self._columns]
            )
        self.rows_written += len(batch)
        return len(batch)

    def prepare(self) -> None:
        """Serialise the workbook to the staging file - the step that can fail."""
        if self._workbook is not None and self._staging is not None:
            self._workbook.save(str(self._staging))
            self._workbook.close()
            self._workbook = None
        _refuse_directory_target(self._target)

    def commit(self) -> None:
        self.prepare()
        if self._staging is None or self._target is None or not self._staging.exists():
            return
        self._staging.replace(self._target)  # atomic on POSIX and Windows
        self._published = True
        logger.info("published %d rows to %s", self.rows_written, self._target.name)

    def rollback(self) -> None:
        if self._workbook is not None:
            self._workbook.close()
            self._workbook = None
        if self._staging is not None:
            self._staging.unlink(missing_ok=True)
        _report_unwithdrawable(self, self._published, self._target)
        self.rows_written = 0

    def _on_close(self) -> None:
        if self._workbook is not None:
            self._workbook.close()
            self._workbook = None
        if self._staging is not None and self._staging.exists():
            self._staging.unlink(missing_ok=True)


def _excel_out(value: Any, escape_formulas: bool) -> Any:
    """Coerce a value into something openpyxl accepts, neutralising formulas.

    Characters XML 1.0 cannot carry are replaced first: openpyxl raises
    ``IllegalCharacterError`` for a control character - after which the
    write-only sheet is unusable - so one such value failed every retry.
    """
    if value is None or isinstance(value, (int, float, bool, datetime, date, time)):
        return value
    if isinstance(value, Decimal):
        return float(value)
    text = _xml_text(str(value) if not isinstance(value, (dict, list)) else _json(value))
    if escape_formulas and text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def _json(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, default=str)


__all__ = ["ExcelSink", "ExcelSource", "ParquetSink", "ParquetSource"]
