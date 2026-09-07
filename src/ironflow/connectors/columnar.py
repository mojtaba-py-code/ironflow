"""Columnar and spreadsheet connectors: Parquet and Excel.

Both depend on optional extras (``pip install 'ironflow[columnar,excel]'``).  The
imports are deferred to the first read/write so that a deployment that only
moves CSV and SQL data does not carry ``pyarrow`` (~90 MB) in its image.

Parquet
-------
Read row-group by row-group rather than whole-file, so memory stays bounded even
for multi-gigabyte files.  Written through a staging file and published on
commit, matching the transactional behaviour of the text sinks.

Excel
-----
Read with ``openpyxl``'s ``read_only`` mode, which uses a streaming XML parser
instead of building the whole workbook object graph.  On write, values that
begin with a formula character are prefixed so an exported cell cannot execute
as a formula, and ``write_only`` mode keeps memory flat.

Excel's hard limit of 1,048,576 rows per sheet is enforced explicitly - silently
truncating an export is far worse than failing it.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from datetime import date, datetime, time
from decimal import Decimal
from pathlib import Path
from typing import Any

from ironflow.config.models import ConnectorSpec
from ironflow.connectors.base import BaseSink, BaseSource, ConnectorRuntime, sink, source
from ironflow.connectors.files import _FORMULA_PREFIXES, FileConnectorMixin
from ironflow.core.context import ExecutionContext, new_id
from ironflow.core.errors import ExtractionError, LoadingError
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
            f"this connector requires the '{extra}' extra: pip install 'ironflow[{extra}]'",
            context={"module": module},
        ) from exc


# --------------------------------------------------------------------------- #
# Parquet
# --------------------------------------------------------------------------- #
@source("parquet")
class ParquetSource(FileConnectorMixin, BaseSource):
    """Read a Parquet file (or a directory of them) row-group at a time.

    Options: ``path`` (required), ``columns`` (projection pushdown).
    """

    def read(self, context: ExecutionContext) -> RecordStream:
        pq = _require("pyarrow.parquet", "columnar")
        path = self._resolve(must_exist=True)
        columns = self.list_option("columns") or None
        batch_size = self.batch_size

        def generate() -> Iterator[RecordBatch]:
            dataset = pq.ParquetFile(str(path)) if path.is_file() else None
            sequence = 0
            if dataset is not None:
                # Projection is pushed into the reader: unread columns are never
                # decompressed, which is the main reason to use Parquet at all.
                for record_batch in dataset.iter_batches(batch_size=batch_size, columns=columns):
                    context.cancellation.raise_if_cancelled()
                    rows = record_batch.to_pylist()
                    yield RecordBatch(rows, sequence=sequence, source=self.name)
                    sequence += 1
            else:
                table = pq.read_table(str(path), columns=columns)
                for offset in range(0, table.num_rows, batch_size):
                    context.cancellation.raise_if_cancelled()
                    rows = table.slice(offset, batch_size).to_pylist()
                    yield RecordBatch(rows, sequence=sequence, source=self.name)
                    sequence += 1

        return generate()

    def describe(self) -> DatasetSchema:
        pq = _require("pyarrow.parquet", "columnar")
        from ironflow.core.types import FieldSchema, FieldType

        path = self._resolve(must_exist=True)
        arrow_schema = pq.read_schema(str(path))
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


@sink("parquet")
class ParquetSink(FileConnectorMixin, BaseSink):
    """Write Parquet with compression, staged and published on commit.

    Options: ``path`` (required), ``compression`` (default ``snappy``),
    ``row_group_size``.
    """

    transactional = True

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._writer: Any = None
        self._target: Path | None = None
        self._staging: Path | None = None
        self._schema: Any = None

    def _on_open(self, context: ExecutionContext) -> None:
        target = self._resolve(must_exist=False)
        target.parent.mkdir(parents=True, exist_ok=True)
        if self.mode is LoadMode.ERROR_IF_EXISTS and target.exists():
            raise LoadingError("destination already exists", context={"path": str(target)})
        if self.mode is LoadMode.APPEND and target.exists():
            # Parquet files are immutable; appending means rewriting.
            logger.warning(
                "parquet does not support append; %s will be replaced. "
                "Use a directory + date partition for incremental output.",
                target.name,
            )
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

    def commit(self) -> None:

        if self._writer is not None:
            self._writer.close()
            self._writer = None
        if self._staging is not None and self._staging.exists() and self._target is not None:
            self._staging.replace(self._target)  # atomic on POSIX and Windows
            logger.info("published %d rows to %s", self.rows_written, self._target.name)

    def rollback(self) -> None:
        if self._writer is not None:
            self._writer.close()
            self._writer = None
        if self._staging is not None:
            self._staging.unlink(missing_ok=True)
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
    """

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
                headers: list[str] = list(configured_columns)
                buffer: list[Record] = []
                sequence = 0
                data_rows_seen = 0

                # A single pass: rows before ``header_row`` are preamble, the
                # header row supplies the column names (unless configured), the
                # rest are data.
                for index, row in enumerate(worksheet.iter_rows(values_only=True), start=1):
                    context.cancellation.raise_if_cancelled()
                    if index < header_row:
                        continue
                    if index == header_row and not configured_columns:
                        headers = [
                            str(cell).strip() if cell is not None else f"column_{position}"
                            for position, cell in enumerate(row, start=1)
                        ]
                        continue
                    if index == header_row and configured_columns:
                        continue
                    if all(cell is None for cell in row):
                        continue
                    data_rows_seen += 1
                    if data_rows_seen <= skip_rows:
                        continue

                    # Excel does not store trailing empty cells, so a short row
                    # is padded against the header to keep records rectangular.
                    width = max(len(headers), len(row))
                    record: Record = {}
                    for position in range(width):
                        name = (
                            headers[position]
                            if position < len(headers)
                            else f"column_{position + 1}"
                        )
                        record[name] = _excel_value(row[position] if position < len(row) else None)
                    buffer.append(record)
                    if len(buffer) >= batch_size:
                        yield RecordBatch(buffer, sequence=sequence, source=self.name)
                        sequence += 1
                        buffer = []
                if buffer:
                    yield RecordBatch(buffer, sequence=sequence, source=self.name)
            finally:
                workbook.close()

        return generate()


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
    ``escape_formulas``, ``freeze_header``.
    """

    transactional = True

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._workbook: Any = None
        self._worksheet: Any = None
        self._columns: list[str] = []
        self._target: Path | None = None
        self._staging: Path | None = None

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
        self.rows_written = 0

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        self._assert_writable()
        if batch.is_empty:
            return 0
        if not self._columns:
            self._columns = list(batch.columns())
            if self.bool_option("write_header", True):
                self._worksheet.append(self._columns)

        if self.rows_written + len(batch) > EXCEL_MAX_ROWS:
            raise LoadingError(
                "output exceeds Excel's row limit; write Parquet or CSV instead",
                context={"limit": EXCEL_MAX_ROWS, "rows": self.rows_written + len(batch)},
            )

        escape = self.bool_option("escape_formulas", True)
        for record in batch.records:
            self._worksheet.append(
                [_excel_out(record.get(column), escape) for column in self._columns]
            )
        self.rows_written += len(batch)
        return len(batch)

    def commit(self) -> None:

        if self._workbook is None or self._staging is None or self._target is None:
            return
        self._workbook.save(str(self._staging))
        self._workbook.close()
        self._workbook = None
        self._staging.replace(self._target)  # atomic on POSIX and Windows
        logger.info("published %d rows to %s", self.rows_written, self._target.name)

    def rollback(self) -> None:
        if self._workbook is not None:
            self._workbook.close()
            self._workbook = None
        if self._staging is not None:
            self._staging.unlink(missing_ok=True)
        self.rows_written = 0

    def _on_close(self) -> None:
        if self._workbook is not None:
            self._workbook.close()
            self._workbook = None
        if self._staging is not None and self._staging.exists():
            self._staging.unlink(missing_ok=True)


def _excel_out(value: Any, escape_formulas: bool) -> Any:
    """Coerce a value into something openpyxl accepts, neutralising formulas."""
    if value is None or isinstance(value, (int, float, bool, datetime, date, time)):
        return value
    if isinstance(value, Decimal):
        return float(value)
    text = str(value) if not isinstance(value, (dict, list)) else _json(value)
    if escape_formulas and text.startswith(_FORMULA_PREFIXES):
        return "'" + text
    return text


def _json(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, default=str)


__all__ = ["ExcelSink", "ExcelSource", "ParquetSink", "ParquetSource"]
