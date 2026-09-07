"""Streaming transformations - the per-batch operations.

Every class here processes one batch and returns one batch, so memory stays
proportional to ``batch_size`` regardless of dataset size.

The security-relevant members of this module are the last three:
:class:`HashColumns`, :class:`EncryptColumns` and :class:`MaskPii`.  They are
what allow a pipeline to move production data into an analytics environment
without moving the PII with it, and they are applied *before* the load, so the
plaintext never reaches the destination.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from collections.abc import Callable
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation
from typing import Any, ClassVar

from ironflow.config.models import TransformSpec
from ironflow.core.context import ExecutionContext, utcnow
from ironflow.core.errors import ConfigurationError, TransformationError
from ironflow.core.types import FieldType, Record, RecordBatch
from ironflow.expressions import compile_expression, record_scope
from ironflow.security.masking import (
    ALLOWED_HASH_ALGORITHMS,
    hash_value,
    mask,
    mask_auto,
    mask_card,
    mask_email,
)
from ironflow.transformation.base import (
    RecordTransformation,
    Transformation,
    transformation,
)

logger = logging.getLogger(__name__)


# --------------------------------------------------------------------------- #
# Column shape
# --------------------------------------------------------------------------- #
@transformation("rename", "rename_columns")
class RenameColumns(RecordTransformation):
    """Rename columns.

    Options: ``mapping`` (``{old: new}``, required), ``strict`` (fail when a
    source column is absent).
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._mapping = {
            str(k): str(v) for k, v in self.dict_option("mapping", required=True).items()
        }
        self._strict = self.bool_option("strict", False)

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        if self._strict:
            missing = [k for k in self._mapping if k not in record]
            if missing:
                raise TransformationError(
                    "cannot rename columns that are not present",
                    context={"missing": missing, "transformation": self.name},
                )
        return {self._mapping.get(key, key): value for key, value in record.items()}


@transformation("drop", "drop_columns")
class DropColumns(RecordTransformation):
    """Remove columns.  Options: ``columns`` (required).

    The recommended way to keep a column out of a downstream system entirely -
    unlike masking, it removes the value rather than obscuring it.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._columns = set(self.list_option("columns", required=True))

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        return {k: v for k, v in record.items() if k not in self._columns}


@transformation("select", "select_columns", "project")
class SelectColumns(RecordTransformation):
    """Keep only the named columns, in the order given.

    Options: ``columns`` (required), ``fill_missing`` (default true).

    Pinning the column set here is what makes a downstream Parquet or SQL load
    schema-stable even when the source adds columns.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._columns = self.list_option("columns", required=True)
        self._fill = self.bool_option("fill_missing", True)

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        if self._fill:
            return {column: record.get(column) for column in self._columns}
        return {column: record[column] for column in self._columns if column in record}


@transformation("normalize_columns", "clean_column_names")
class NormalizeColumnNames(RecordTransformation):
    """Normalise column names to ``snake_case`` ASCII.

    Options: ``case`` (``snake``|``lower``|``upper``), ``strip_accents``.

    Applied right after extraction, this removes the whole class of bugs caused
    by ``"Order Date"`` vs ``"order_date"`` vs ``"OrderDate"`` across sources.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._case = self.str_option("case", "snake").lower()
        self._strip_accents = self.bool_option("strip_accents", True)

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        return {self._normalise(key): value for key, value in record.items()}

    def _normalise(self, name: str) -> str:
        text = str(name).strip()
        if self._strip_accents:
            text = "".join(
                c for c in unicodedata.normalize("NFKD", text) if not unicodedata.combining(c)
            )
        if self._case == "snake":
            text = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", text)
            text = re.sub(r"[^0-9a-zA-Z]+", "_", text).strip("_").lower()
            text = re.sub(r"_+", "_", text)
        elif self._case == "lower":
            text = text.lower()
        elif self._case == "upper":
            text = text.upper()
        return text or "column"


# --------------------------------------------------------------------------- #
# Values
# --------------------------------------------------------------------------- #
@transformation("add_column", "constant")
class AddColumn(RecordTransformation):
    """Add a column with a constant or templated value.

    Options: ``column`` (required), ``value``, ``overwrite`` (default true).
    ``value`` may reference ``${execution_id}``, ``${pipeline_id}``,
    ``${task_id}`` and ``${now}``.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._column = self.str_option("column", required=True)
        self._value = self.option("value")
        self._overwrite = self.bool_option("overwrite", True)

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        if not self._overwrite and self._column in record:
            return record
        return {**record, self._column: self._render(context)}

    def _render(self, context: ExecutionContext) -> Any:
        if not isinstance(self._value, str) or "${" not in self._value:
            return self._value
        replacements = {
            "${execution_id}": context.execution_id,
            "${pipeline_id}": context.pipeline_id,
            "${task_id}": context.task_id,
            "${correlation_id}": context.correlation_id,
            "${now}": utcnow().isoformat(),
        }
        rendered = self._value
        for token, value in replacements.items():
            rendered = rendered.replace(token, value)
        return rendered


@transformation("derive", "calculate", "computed_column")
class DeriveColumn(RecordTransformation):
    """Compute a column from a sandboxed expression.

    Options: ``column`` (required), ``expression`` (required),
    ``on_error`` (``null``|``fail``|``keep``).

    Example::

        - type: derive
          column: line_total
          expression: "round(quantity * unit_price * (1 - coalesce(discount, 0)), 2)"
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._column = self.str_option("column", required=True)
        self._expression = compile_expression(self.str_option("expression", required=True))
        self._on_error = self.str_option("on_error", "null").lower()
        self._errors = 0

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        try:
            value = self._expression.evaluate(
                record_scope(record, params=context.parameters, state=context.state)
            )
        except TransformationError:
            if self._on_error == "fail":
                raise
            self._errors += 1
            if self._errors in (1, 100, 10_000):
                # Log at a geometric cadence: enough to notice, not enough to
                # turn a bad column into a gigabyte of log output.
                logger.warning(
                    "expression for column %r failed on %d record(s)", self._column, self._errors
                )
            if self._on_error == "keep":
                return record
            value = None
        return {**record, self._column: value}


@transformation("cast", "convert_types", "astype")
class CastColumns(RecordTransformation):
    """Convert columns to declared types.

    Options: ``columns`` (``{name: type}``, required), ``on_error``
    (``null``|``fail``|``keep``), ``date_format``.

    Doing conversion here rather than relying on the destination's implicit
    coercion means a bad value is a data-quality event, not a silent ``0``.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        raw = self.dict_option("columns", required=True)
        self._columns: dict[str, FieldType] = {}
        for column, type_name in raw.items():
            try:
                self._columns[str(column)] = FieldType(str(type_name).lower())
            except ValueError as exc:
                raise ConfigurationError(
                    "unknown target type",
                    context={
                        "column": column,
                        "type": type_name,
                        "supported": [t.value for t in FieldType],
                    },
                ) from exc
        self._on_error = self.str_option("on_error", "null").lower()
        self._date_format = self.str_option("date_format", "")

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        out = dict(record)
        for column, target in self._columns.items():
            if column not in out:
                continue
            value = out[column]
            if value is None:
                continue
            converted = _convert(value, target, self._date_format)
            if converted is _FAILED:
                if self._on_error == "fail":
                    raise TransformationError(
                        "type conversion failed",
                        context={
                            "column": column,
                            "target": target.value,
                            "value": str(value)[:60],
                        },
                    )
                out[column] = value if self._on_error == "keep" else None
            else:
                out[column] = converted
        return out


class _Failed:
    __slots__ = ()


_FAILED = _Failed()

_TRUE = {"true", "1", "yes", "y", "t", "on"}
_FALSE = {"false", "0", "no", "n", "f", "off"}


def _convert(value: Any, target: FieldType, date_format: str) -> Any:
    """Convert a single value; returns the ``_FAILED`` sentinel on failure."""
    try:
        if target is FieldType.STRING:
            return str(value)
        if target is FieldType.BOOLEAN:
            if isinstance(value, bool):
                return value
            text = str(value).strip().lower()
            if text in _TRUE:
                return True
            if text in _FALSE:
                return False
            return _FAILED
        if target is FieldType.INTEGER:
            if isinstance(value, bool):
                return int(value)
            return int(float(str(value).strip().replace(",", "")))
        if target is FieldType.FLOAT:
            return float(str(value).strip().replace(",", ""))
        if target is FieldType.DECIMAL:
            return Decimal(str(value).strip().replace(",", ""))
        if target in (FieldType.DATE, FieldType.DATETIME):
            parsed = _parse_datetime(value, date_format)
            if parsed is None:
                return _FAILED
            return parsed.date().isoformat() if target is FieldType.DATE else parsed.isoformat()
        if target is FieldType.JSON:
            if isinstance(value, (dict, list)):
                return value
            import json

            return json.loads(str(value))
    except (TypeError, ValueError, InvalidOperation):
        return _FAILED
    return value


def _parse_datetime(value: Any, date_format: str = "") -> datetime | None:
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    if date_format:
        try:
            return datetime.strptime(text, date_format)
        except ValueError:
            return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%Y%m%d"):
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


@transformation("fill_null", "fillna", "default_value")
class FillNull(RecordTransformation):
    """Replace nulls with defaults.

    Options: ``columns`` (``{name: default}``) or ``value`` + ``columns`` list,
    ``treat_empty_as_null`` (default true).
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        raw = self.option("columns")
        if isinstance(raw, dict):
            self._defaults = {str(k): v for k, v in raw.items()}
        else:
            default = self.option("value")
            self._defaults = dict.fromkeys(self.list_option("columns", required=True), default)
        self._empty_is_null = self.bool_option("treat_empty_as_null", True)

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        out = dict(record)
        for column, default in self._defaults.items():
            value = out.get(column)
            blank = value is None or (
                self._empty_is_null and isinstance(value, str) and not value.strip()
            )
            if blank:
                out[column] = default
        return out


@transformation("map_values", "replace_values", "lookup")
class MapValues(RecordTransformation):
    """Translate values through a lookup table.

    Options: ``column`` (required), ``mapping`` (required), ``default``,
    ``keep_unmapped`` (default true), ``target`` (write to a different column).
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._column = self.str_option("column", required=True)
        self._mapping = {str(k): v for k, v in self.dict_option("mapping", required=True).items()}
        self._default = self.option("default")
        self._keep = self.bool_option("keep_unmapped", True)
        self._target = self.str_option("target", "") or self._column

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        if self._column not in record:
            return record
        key = str(record[self._column])
        if key in self._mapping:
            value = self._mapping[key]
        elif self._keep and self._default is None:
            value = record[self._column]
        else:
            value = self._default
        return {**record, self._target: value}


@transformation("string_ops", "text")
class StringOps(RecordTransformation):
    """Apply string operations to columns.

    Options: ``columns`` (required), ``operations`` (list of ``trim``,
    ``lower``, ``upper``, ``title``, ``collapse_spaces``, ``remove_accents``,
    ``digits_only``, ``alnum_only``), ``max_length``.
    """

    _OPERATIONS: ClassVar[dict[str, Callable[..., str]]] = {
        "trim": lambda s: s.strip(),
        "lower": lambda s: s.lower(),
        "upper": lambda s: s.upper(),
        "title": lambda s: s.title(),
        "capitalize": lambda s: s.capitalize(),
        "collapse_spaces": lambda s: re.sub(r"\s+", " ", s).strip(),
        "remove_accents": lambda s: "".join(
            c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c)
        ),
        "digits_only": lambda s: re.sub(r"\D", "", s),
        "alnum_only": lambda s: re.sub(r"[^0-9A-Za-z ]", "", s),
    }

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._columns = self.list_option("columns", required=True)
        names = self.list_option("operations", ["trim"])
        unknown = [n for n in names if n not in self._OPERATIONS]
        if unknown:
            raise ConfigurationError(
                "unknown string operation",
                context={"unknown": unknown, "supported": sorted(self._OPERATIONS)},
            )
        self._operations = [self._OPERATIONS[n] for n in names]
        self._max_length = self.int_option("max_length", 0)

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        out = dict(record)
        for column in self._columns:
            value = out.get(column)
            if value is None:
                continue
            text = str(value)
            for operation in self._operations:
                text = operation(text)
            if self._max_length > 0:
                text = text[: self._max_length]
            out[column] = text
        return out


@transformation("split_column")
class SplitColumn(RecordTransformation):
    """Split one column into several.

    Options: ``column`` (required), ``separator``, ``into`` (list of new column
    names, required), ``keep_original`` (default false), ``maxsplit``.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._column = self.str_option("column", required=True)
        self._separator = self.str_option("separator", " ")
        self._into = self.list_option("into", required=True)
        self._keep = self.bool_option("keep_original", False)

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        out = dict(record)
        value = out.get(self._column)
        parts = str(value).split(self._separator, len(self._into) - 1) if value is not None else []
        for index, name in enumerate(self._into):
            out[name] = parts[index].strip() if index < len(parts) else None
        if not self._keep:
            out.pop(self._column, None)
        return out


@transformation("concat_columns", "combine")
class ConcatColumns(RecordTransformation):
    """Join several columns into one.

    Options: ``columns`` (required), ``target`` (required), ``separator``,
    ``skip_null`` (default true).
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._columns = self.list_option("columns", required=True)
        self._target = self.str_option("target", required=True)
        self._separator = self.str_option("separator", " ")
        self._skip_null = self.bool_option("skip_null", True)

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        values = [record.get(c) for c in self._columns]
        if self._skip_null:
            values = [v for v in values if v is not None and str(v).strip()]
        return {**record, self._target: self._separator.join(str(v) for v in values)}


@transformation("flatten", "flatten_json")
class FlattenJson(RecordTransformation):
    """Flatten nested objects into dotted columns.

    Options: ``separator`` (default ``.``), ``max_depth`` (default 5),
    ``columns`` (restrict to these top-level keys), ``keep_lists``.

    Depth is capped so a deeply or cyclically nested API payload cannot expand
    into millions of columns.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._separator = self.str_option("separator", ".")
        self._max_depth = max(1, self.int_option("max_depth", 5))
        self._only = set(self.list_option("columns"))
        self._keep_lists = self.bool_option("keep_lists", True)

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        out: Record = {}
        for key, value in record.items():
            if self._only and key not in self._only:
                out[key] = value
                continue
            self._flatten(key, value, out, depth=1)
        return out

    def _flatten(self, prefix: str, value: Any, out: Record, *, depth: int) -> None:
        if isinstance(value, dict) and depth <= self._max_depth:
            if not value:
                out[prefix] = None
                return
            for key, item in value.items():
                self._flatten(f"{prefix}{self._separator}{key}", item, out, depth=depth + 1)
        elif isinstance(value, list) and not self._keep_lists and depth <= self._max_depth:
            for index, item in enumerate(value):
                self._flatten(f"{prefix}{self._separator}{index}", item, out, depth=depth + 1)
        else:
            out[prefix] = value


# --------------------------------------------------------------------------- #
# Dates, timezones, currency
# --------------------------------------------------------------------------- #
@transformation("parse_date", "date_parse")
class ParseDate(RecordTransformation):
    """Parse date/datetime strings into ISO-8601.

    Options: ``columns`` (required), ``format``, ``output_format``,
    ``on_error``.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._columns = self.list_option("columns", required=True)
        self._format = self.str_option("format", "")
        self._output = self.str_option("output_format", "")
        self._on_error = self.str_option("on_error", "null").lower()

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        out = dict(record)
        for column in self._columns:
            value = out.get(column)
            if value is None or value == "":
                continue
            parsed = _parse_datetime(value, self._format)
            if parsed is None:
                if self._on_error == "fail":
                    raise TransformationError(
                        "unable to parse date",
                        context={"column": column, "value": str(value)[:60]},
                    )
                out[column] = value if self._on_error == "keep" else None
                continue
            out[column] = parsed.strftime(self._output) if self._output else parsed.isoformat()
        return out


@transformation("convert_timezone", "timezone")
class ConvertTimezone(RecordTransformation):
    """Convert timestamps between time zones.

    Options: ``columns`` (required), ``from`` (assumed zone for naive values,
    default UTC), ``to`` (default UTC).

    Zones are given as fixed UTC offsets (``+02:00``) or IANA names when
    :mod:`zoneinfo` has a database available.  Naive timestamps are localised to
    ``from`` rather than guessed - guessing is how an hour of data goes missing
    twice a year.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._columns = self.list_option("columns", required=True)
        self._from = _resolve_timezone(self.str_option("from", "UTC"))
        self._to = _resolve_timezone(self.str_option("to", "UTC"))

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        out = dict(record)
        for column in self._columns:
            value = out.get(column)
            if value is None:
                continue
            parsed = _parse_datetime(value)
            if parsed is None:
                continue
            localised = parsed.replace(tzinfo=self._from) if parsed.tzinfo is None else parsed
            out[column] = localised.astimezone(self._to).isoformat()
        return out


def _resolve_timezone(name: str) -> Any:
    text = name.strip()
    if not text or text.upper() == "UTC":
        return UTC
    match = re.fullmatch(r"([+-])(\d{2}):?(\d{2})", text)
    if match:
        sign = 1 if match.group(1) == "+" else -1
        return timezone(sign * timedelta(hours=int(match.group(2)), minutes=int(match.group(3))))
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(text)
    except Exception as exc:
        raise ConfigurationError(
            "unknown timezone; use an IANA name or a fixed offset like +02:00",
            context={"timezone": text},
        ) from exc


@transformation("convert_currency", "currency")
class ConvertCurrency(RecordTransformation):
    """Convert monetary amounts using a supplied rate table.

    Options: ``columns`` (required), ``rates`` (``{code: rate_to_base}``,
    required), ``currency_column`` (per-row currency) or ``from`` (fixed),
    ``target_column_suffix``, ``precision`` (default 2).

    Rates are configuration, not fetched at run time: a pipeline whose output
    changes because a rate API moved is not reproducible, and reproducibility is
    what makes a financial reconciliation possible.  Arithmetic uses
    :class:`~decimal.Decimal` - binary floats cannot represent 0.10 and the
    rounding error is real money.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._columns = self.list_option("columns", required=True)
        rates = self.dict_option("rates", required=True)
        self._rates = {str(k).upper(): Decimal(str(v)) for k, v in rates.items()}
        self._currency_column = self.str_option("currency_column", "")
        self._fixed = self.str_option("from", "").upper()
        self._suffix = self.str_option("target_column_suffix", "")
        self._precision = self.int_option("precision", 2)
        if not self._currency_column and not self._fixed:
            raise ConfigurationError(
                "specify either 'currency_column' or 'from'",
                context={"transformation": self.name},
            )

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        code = (
            str(record.get(self._currency_column, "")).upper()
            if self._currency_column
            else self._fixed
        )
        rate = self._rates.get(code)
        out = dict(record)
        if rate is None:
            return out
        quantum = Decimal(10) ** -self._precision
        for column in self._columns:
            value = out.get(column)
            if value is None:
                continue
            try:
                amount = Decimal(str(value))
            except (InvalidOperation, TypeError, ValueError):
                continue
            converted = (amount * rate).quantize(quantum)
            out[f"{column}{self._suffix}" if self._suffix else column] = float(converted)
        return out


# --------------------------------------------------------------------------- #
# Filtering and metadata
# --------------------------------------------------------------------------- #
@transformation("filter", "where")
class FilterRecords(RecordTransformation):
    """Keep records matching a sandboxed boolean expression.

    Options: ``expression`` (required), ``invert`` (default false).

    Filtering as early as possible in the chain is the cheapest optimisation
    available: every downstream step then processes fewer rows.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._expression = compile_expression(self.str_option("expression", required=True))
        self._invert = self.bool_option("invert", False)
        self.dropped = 0

    def transform_record(self, record: Record, context: ExecutionContext) -> Record | None:
        keep = self._expression.evaluate_bool(
            record_scope(record, params=context.parameters, state=context.state)
        )
        if self._invert:
            keep = not keep
        if keep:
            return record
        self.dropped += 1
        return None


@transformation("add_metadata", "lineage")
class AddMetadata(Transformation):
    """Stamp lineage columns onto every record.

    Options: ``prefix`` (default ``_``), ``include`` (subset of
    ``execution_id``, ``pipeline_id``, ``task_id``, ``loaded_at``, ``source``,
    ``batch``, ``row_number``).

    Lineage columns are what let an analyst answer "which run produced this
    row?" months later, and what makes a targeted re-load possible without
    truncating the table.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._prefix = self.str_option("prefix", "_")
        self._include = set(
            self.list_option("include", ["execution_id", "pipeline_id", "loaded_at"])
        )
        self._row_number = 0

    def apply(self, batch: RecordBatch, context: ExecutionContext) -> RecordBatch:
        loaded_at = utcnow().isoformat()
        available = {
            "execution_id": context.execution_id,
            "pipeline_id": context.pipeline_id,
            "task_id": context.task_id,
            "correlation_id": context.correlation_id,
            "loaded_at": loaded_at,
            "source": batch.source,
            "batch": batch.sequence,
        }
        static = {
            f"{self._prefix}{key}": value
            for key, value in available.items()
            if key in self._include
        }
        include_row_number = "row_number" in self._include

        out: list[Record] = []
        for record in batch.records:
            enriched = {**record, **static}
            if include_row_number:
                self._row_number += 1
                enriched[f"{self._prefix}row_number"] = self._row_number
            out.append(enriched)
        return batch.replace(out)


@transformation("dedupe_batch", "deduplicate_batch")
class DeduplicateBatch(Transformation):
    """Drop duplicates *within* each batch.

    Options: ``columns`` (defaults to the whole record).

    Constant memory, but only catches duplicates that land in the same batch.
    Use the blocking ``deduplicate`` transformation for whole-dataset semantics;
    this one exists because it is free and removes the common case of a source
    repeating rows in a single page.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._columns = self.list_option("columns")
        self.dropped = 0

    def apply(self, batch: RecordBatch, context: ExecutionContext) -> RecordBatch:
        seen: set[int] = set()
        out: list[Record] = []
        for record in batch.records:
            key = _record_key(record, self._columns)
            if key in seen:
                self.dropped += 1
                continue
            seen.add(key)
            out.append(record)
        return batch.replace(out)


def _record_key(record: Record, columns: list[str]) -> int:
    import json

    payload = {c: record.get(c) for c in columns} if columns else record
    return hash(json.dumps(payload, sort_keys=True, default=str))


# --------------------------------------------------------------------------- #
# Privacy
# --------------------------------------------------------------------------- #
@transformation("hash_columns", "pseudonymize")
class HashColumns(RecordTransformation):
    """Replace values with a keyed HMAC digest.

    Options: ``columns`` (required), ``key`` (secret reference - strongly
    recommended), ``algorithm``, ``target_suffix``, ``keep_original``.

    With a key this is pseudonymisation: joins on the token still work, but the
    original value cannot be recovered or brute-forced from a dictionary.
    Without a key it is a plain digest, which for a low-entropy input such as an
    email address is trivially reversible by enumeration - so a warning is
    emitted once.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._columns = self.list_option("columns", required=True)
        self._key = self.option("key")
        self._algorithm = self.str_option("algorithm", "sha256")
        # Checked here rather than at the first record: the algorithm is static
        # configuration, so `ironflow pipeline validate` should reject it before
        # a run starts instead of failing halfway through one.
        if self._algorithm not in ALLOWED_HASH_ALGORITHMS:
            raise ConfigurationError(
                "hash algorithm is not allowed for pseudonymisation",
                context={
                    "transformation": self.name,
                    "algorithm": self._algorithm,
                    "allowed": sorted(ALLOWED_HASH_ALGORITHMS),
                },
            )
        self._suffix = self.str_option("target_suffix", "")
        self._keep = self.bool_option("keep_original", False)
        self._resolved_key: str | None = None
        self._warned = False

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        if self._resolved_key is None and self._key is not None:
            from ironflow.security.secrets import SecretResolver

            self._resolved_key = SecretResolver().reveal(self._key, name=f"{self.name}.key")
        if self._key is None and not self._warned:
            logger.warning(
                "hash_columns is running without a key; an unkeyed digest of a "
                "low-entropy value (email, phone, national id) is reversible by "
                "enumeration. Set 'key: env:IRONFLOW_HASH_KEY'."
            )
            self._warned = True

        out = dict(record)
        for column in self._columns:
            if column not in out or out[column] is None:
                continue
            digest = hash_value(out[column], key=self._resolved_key, algorithm=self._algorithm)
            target = f"{column}{self._suffix}" if self._suffix else column
            if self._keep and target == column:
                target = f"{column}_hash"
            out[target] = digest
            if not self._keep and target != column:
                out.pop(column, None)
        return out


@transformation("encrypt_columns", "encrypt")
class EncryptColumns(RecordTransformation):
    """Encrypt column values with the platform key.

    Options: ``columns`` (required), ``key`` (defaults to
    ``IRONFLOW_ENCRYPTION_KEY``).

    Reversible by design, for fields a downstream operator must occasionally be
    able to read (a support agent looking up an account).  Ciphertext expands
    the value ~3x and destroys sort order and indexability - prefer
    ``hash_columns`` unless reversibility is genuinely required.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._columns = self.list_option("columns", required=True)
        self._key_ref = self.option("key")
        self._crypto: Any = None

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        if self._crypto is None:
            from ironflow.security.crypto import CryptoService
            from ironflow.security.secrets import SecretResolver

            if self._key_ref is not None:
                key = SecretResolver().reveal(self._key_ref, name=f"{self.name}.key")
                self._crypto = CryptoService.from_key(str(key))
            else:
                self._crypto = CryptoService.from_env()

        out = dict(record)
        for column in self._columns:
            value = out.get(column)
            if value is None:
                continue
            out[column] = self._crypto.encrypt(str(value))
        return out


@transformation("mask_pii", "mask")
class MaskPii(RecordTransformation):
    """Irreversibly mask sensitive values while keeping them recognisable.

    Options: ``columns`` (required), ``strategy`` (``auto``|``partial``|
    ``email``|``card``|``full``), ``keep_start``, ``keep_end``, ``mask_char``.

    The right choice for non-production environments: a developer debugging an
    order flow needs to see *an* email address, not *the* email address.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._columns = self.list_option("columns", required=True)
        self._strategy = self.str_option("strategy", "auto").lower()
        self._keep_start = self.int_option("keep_start", 0)
        self._keep_end = self.int_option("keep_end", 4)
        self._mask_char = self.str_option("mask_char", "*")[:1] or "*"

    def transform_record(self, record: Record, context: ExecutionContext) -> Record:
        out = dict(record)
        for column in self._columns:
            value = out.get(column)
            if value is None:
                continue
            out[column] = self._mask(value)
        return out

    def _mask(self, value: Any) -> str:
        if self._strategy == "email":
            return mask_email(value)
        if self._strategy == "card":
            return mask_card(value)
        if self._strategy == "full":
            return self._mask_char * len(str(value))
        if self._strategy == "partial":
            return mask(
                value,
                keep_start=self._keep_start,
                keep_end=self._keep_end,
                mask_char=self._mask_char,
            )
        return mask_auto(value)


__all__ = [
    "AddColumn",
    "AddMetadata",
    "CastColumns",
    "ConcatColumns",
    "ConvertCurrency",
    "ConvertTimezone",
    "DeduplicateBatch",
    "DeriveColumn",
    "DropColumns",
    "EncryptColumns",
    "FillNull",
    "FilterRecords",
    "FlattenJson",
    "HashColumns",
    "MapValues",
    "MaskPii",
    "NormalizeColumnNames",
    "ParseDate",
    "RenameColumns",
    "SelectColumns",
    "SplitColumn",
    "StringOps",
]
