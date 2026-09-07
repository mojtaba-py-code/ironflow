"""Domain primitives shared by every stage of the pipeline.

Why record batches instead of DataFrames
----------------------------------------
The core of IronFlow moves ``list[dict[str, Any]]`` batches through an iterator
chain rather than materialising a DataFrame.  Three reasons:

1. **Memory.**  A batch of 10k rows is bounded; a DataFrame of a 40 GB export is
   not.  Streaming batches means peak RSS is a function of ``batch_size``, not
   of the source size.
2. **Heterogeneity.**  REST, GraphQL, XML and JSON sources produce ragged,
   nested records.  Forcing them through a rectangular container up front loses
   information and costs a copy.
3. **Dependency isolation.**  ``pandas``/``pyarrow`` stay optional extras used
   only by the columnar connectors, so a slim container image can run the
   CSV/SQL/REST paths without them.

Aggregations, joins and sorts genuinely need the whole dataset; those are
implemented as explicitly *blocking* transformations that document their memory
behaviour instead of pretending to stream.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, TypeAlias

#: A single row.  Keys are column names; values are Python scalars or nested
#: containers.  Deliberately permissive - normalisation is a transformation.
Record: TypeAlias = dict[str, Any]


class RunStatus(str, enum.Enum):
    """Lifecycle of a pipeline or task run."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"
    PARTIAL = "partial"

    @property
    def is_terminal(self) -> bool:
        return self in _TERMINAL_STATUSES

    @property
    def is_failure(self) -> bool:
        return self in (RunStatus.FAILED, RunStatus.CANCELLED)


_TERMINAL_STATUSES = frozenset(
    {
        RunStatus.SUCCESS,
        RunStatus.FAILED,
        RunStatus.SKIPPED,
        RunStatus.CANCELLED,
        RunStatus.PARTIAL,
    }
)


class LoadMode(str, enum.Enum):
    """How a destination should treat pre-existing data."""

    APPEND = "append"
    OVERWRITE = "overwrite"
    UPSERT = "upsert"
    ERROR_IF_EXISTS = "error_if_exists"


class LoadStrategy(str, enum.Enum):
    """How much of the source is read on each run."""

    FULL = "full"
    INCREMENTAL = "incremental"
    CDC = "cdc"


class Severity(str, enum.Enum):
    """Severity of a data-quality finding."""

    INFO = "info"
    WARNING = "warning"
    ERROR = "error"

    @property
    def blocks_record(self) -> bool:
        return self is Severity.ERROR


class OnViolation(str, enum.Enum):
    """Policy applied when a record fails validation."""

    FAIL = "fail"
    """Abort the task immediately (transactional destinations roll back)."""

    QUARANTINE = "quarantine"
    """Divert the record to the reject sink and keep processing."""

    DROP = "drop"
    """Discard the record silently but count it."""

    WARN = "warn"
    """Keep the record, record the violation, continue."""


class FieldType(str, enum.Enum):
    """Logical column types understood by the schema layer."""

    STRING = "string"
    INTEGER = "integer"
    FLOAT = "float"
    BOOLEAN = "boolean"
    DATE = "date"
    DATETIME = "datetime"
    DECIMAL = "decimal"
    JSON = "json"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class FieldSchema:
    """Description of a single column."""

    name: str
    type: FieldType = FieldType.UNKNOWN
    nullable: bool = True
    description: str | None = None
    sensitive: bool = False
    """Marks PII/secret columns so masking and log redaction can find them."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type.value,
            "nullable": self.nullable,
            "description": self.description,
            "sensitive": self.sensitive,
        }


@dataclass(frozen=True, slots=True)
class DatasetSchema:
    """An ordered collection of :class:`FieldSchema` describing a dataset."""

    fields: tuple[FieldSchema, ...] = ()

    @classmethod
    def from_iterable(cls, fields: Iterable[FieldSchema]) -> DatasetSchema:
        return cls(tuple(fields))

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.fields)

    @property
    def sensitive_names(self) -> tuple[str, ...]:
        return tuple(f.name for f in self.fields if f.sensitive)

    def get(self, name: str) -> FieldSchema | None:
        return next((f for f in self.fields if f.name == name), None)

    def diff(self, other: DatasetSchema) -> SchemaDiff:
        """Compare ``self`` (previous) with ``other`` (observed)."""
        mine = {f.name: f for f in self.fields}
        theirs = {f.name: f for f in other.fields}
        added = tuple(sorted(set(theirs) - set(mine)))
        removed = tuple(sorted(set(mine) - set(theirs)))
        changed = tuple(
            sorted(
                name
                for name in set(mine) & set(theirs)
                if mine[name].type is not theirs[name].type
                and FieldType.UNKNOWN not in (mine[name].type, theirs[name].type)
            )
        )
        return SchemaDiff(added=added, removed=removed, type_changed=changed)

    def to_dict(self) -> dict[str, Any]:
        return {"fields": [f.to_dict() for f in self.fields]}


@dataclass(frozen=True, slots=True)
class SchemaDiff:
    """Result of comparing two schemas - drives schema-evolution policy."""

    added: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()
    type_changed: tuple[str, ...] = ()

    @property
    def is_empty(self) -> bool:
        return not (self.added or self.removed or self.type_changed)

    @property
    def is_backward_compatible(self) -> bool:
        """Additive-only changes never break a downstream consumer."""
        return not (self.removed or self.type_changed)

    def to_dict(self) -> dict[str, Any]:
        return {
            "added": list(self.added),
            "removed": list(self.removed),
            "type_changed": list(self.type_changed),
        }


@dataclass(slots=True)
class RecordBatch:
    """A bounded chunk of records travelling through the pipeline."""

    records: list[Record]
    sequence: int = 0
    source: str = "unknown"
    metadata: dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.records)

    def __iter__(self) -> Iterator[Record]:
        return iter(self.records)

    def __bool__(self) -> bool:
        return bool(self.records)

    @property
    def is_empty(self) -> bool:
        return not self.records

    def replace(self, records: list[Record]) -> RecordBatch:
        """Return a sibling batch carrying ``records`` and the same lineage."""
        return RecordBatch(
            records=records,
            sequence=self.sequence,
            source=self.source,
            metadata=dict(self.metadata),
        )

    def columns(self) -> tuple[str, ...]:
        """Union of keys across the batch, preserving first-seen order."""
        seen: dict[str, None] = {}
        for record in self.records:
            for key in record:
                seen.setdefault(key, None)
        return tuple(seen)

    def infer_schema(self, sample: int = 200) -> DatasetSchema:
        """Infer a :class:`DatasetSchema` from up to ``sample`` records."""
        return infer_schema(self.records[:sample])


#: A lazily produced sequence of batches - the pipeline's transport type.
RecordStream: TypeAlias = Iterator[RecordBatch]


@dataclass(slots=True)
class Violation:
    """A single data-quality finding attached to a record."""

    rule: str
    field: str | None
    message: str
    severity: Severity = Severity.ERROR
    record_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "field": self.field,
            "message": self.message,
            "severity": self.severity.value,
            "record_index": self.record_index,
        }


@dataclass(slots=True)
class StageMetrics:
    """Counters accumulated by one stage of one task."""

    rows_in: int = 0
    rows_out: int = 0
    rows_failed: int = 0
    rows_skipped: int = 0
    batches: int = 0
    bytes_processed: int = 0
    duration_seconds: float = 0.0

    def merge(self, other: StageMetrics) -> None:
        self.rows_in += other.rows_in
        self.rows_out += other.rows_out
        self.rows_failed += other.rows_failed
        self.rows_skipped += other.rows_skipped
        self.batches += other.batches
        self.bytes_processed += other.bytes_processed
        self.duration_seconds += other.duration_seconds

    @property
    def throughput_rows_per_second(self) -> float:
        if self.duration_seconds <= 0:
            return 0.0
        return self.rows_out / self.duration_seconds

    @property
    def success_rate(self) -> float:
        total = self.rows_in
        if total <= 0:
            return 1.0
        return max(0.0, (total - self.rows_failed) / total)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rows_in": self.rows_in,
            "rows_out": self.rows_out,
            "rows_failed": self.rows_failed,
            "rows_skipped": self.rows_skipped,
            "batches": self.batches,
            "bytes_processed": self.bytes_processed,
            "duration_seconds": round(self.duration_seconds, 6),
            "throughput_rows_per_second": round(self.throughput_rows_per_second, 2),
            "success_rate": round(self.success_rate, 6),
        }


# --------------------------------------------------------------------------- #
# Schema inference
# --------------------------------------------------------------------------- #
def _infer_field_type(values: Sequence[Any]) -> FieldType:
    """Pick the narrowest logical type that describes every non-null value."""
    seen: set[FieldType] = set()
    for value in values:
        if value is None:
            continue
        if isinstance(value, bool):
            seen.add(FieldType.BOOLEAN)
        elif isinstance(value, int):
            seen.add(FieldType.INTEGER)
        elif isinstance(value, float):
            seen.add(FieldType.FLOAT)
        elif isinstance(value, datetime):
            seen.add(FieldType.DATETIME)
        elif isinstance(value, (dict, list)):
            seen.add(FieldType.JSON)
        elif isinstance(value, str):
            seen.add(FieldType.STRING)
        else:
            seen.add(FieldType.UNKNOWN)

    if not seen:
        return FieldType.UNKNOWN
    if len(seen) == 1:
        return next(iter(seen))
    # Widen numeric mixtures instead of degrading to UNKNOWN.
    if seen <= {FieldType.INTEGER, FieldType.FLOAT, FieldType.BOOLEAN}:
        return FieldType.FLOAT
    return FieldType.STRING


def infer_schema(records: Sequence[Mapping[str, Any]]) -> DatasetSchema:
    """Infer a dataset schema from a sample of records.

    Columns keep first-seen order so that generated CSV headers are stable
    across runs, which matters for downstream diffing.
    """
    columns: dict[str, list[Any]] = {}
    for record in records:
        for key, value in record.items():
            columns.setdefault(key, []).append(value)

    fields = [
        FieldSchema(
            name=name,
            type=_infer_field_type(values),
            nullable=any(v is None for v in values) or len(values) < len(records),
        )
        for name, values in columns.items()
    ]
    return DatasetSchema(tuple(fields))


def iter_records(stream: RecordStream) -> Iterator[Record]:
    """Flatten a batch stream into a record stream (test/reporting helper)."""
    for batch in stream:
        yield from batch.records


def batched(records: Iterable[Record], size: int, *, source: str = "memory") -> RecordStream:
    """Chunk an arbitrary record iterable into :class:`RecordBatch` objects."""
    if size <= 0:
        raise ValueError("batch size must be positive")
    buffer: list[Record] = []
    sequence = 0
    for record in records:
        buffer.append(record)
        if len(buffer) >= size:
            yield RecordBatch(records=buffer, sequence=sequence, source=source)
            sequence += 1
            buffer = []
    if buffer:
        yield RecordBatch(records=buffer, sequence=sequence, source=source)


__all__ = [
    "DatasetSchema",
    "FieldSchema",
    "FieldType",
    "LoadMode",
    "LoadStrategy",
    "OnViolation",
    "Record",
    "RecordBatch",
    "RecordStream",
    "RunStatus",
    "SchemaDiff",
    "Severity",
    "StageMetrics",
    "Violation",
    "batched",
    "infer_schema",
    "iter_records",
]
