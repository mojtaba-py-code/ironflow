"""Blocking transformations - operations that need the whole stream.

Sorting, joining, aggregating and global deduplication cannot be expressed on a
single batch.  These transformations therefore materialise data, and each one
states its memory profile explicitly in its docstring and enforces a row cap.

The cap is not a nuisance - it is the difference between a job that fails at
03:10 with a clear message naming the transformation and a container that is
OOM-killed with no diagnostics at all.  ``max_rows`` is configurable per step.

For datasets that genuinely exceed memory the correct answer is not a bigger
cap: it is to push the operation into the source system (``ORDER BY``/``GROUP
BY`` in the SQL connector's ``query``), where an index and spill-to-disk already
exist.  Every docstring below says so.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from typing import Any

from ironflow.config.models import TransformSpec
from ironflow.core.context import ExecutionContext
from ironflow.core.errors import ConfigurationError, TransformationError
from ironflow.core.types import Record, RecordBatch, RecordStream
from ironflow.transformation.base import StreamTransformation, transformation

logger = logging.getLogger(__name__)

#: Default cap on materialised rows for a blocking transformation.
DEFAULT_MAX_ROWS = 2_000_000


class _MaterialisingTransformation(StreamTransformation):
    """Shared row-cap enforcement and re-batching."""

    def _max_rows(self) -> int:
        return self.int_option("max_rows", DEFAULT_MAX_ROWS)

    def _collect(
        self, stream: RecordStream, context: ExecutionContext
    ) -> tuple[list[Record], int, str]:
        """Drain the stream into a list, enforcing the row cap."""
        records: list[Record] = []
        limit = self._max_rows()
        batch_size = 0
        source = "stream"
        for batch in stream:
            context.cancellation.raise_if_cancelled()
            batch_size = max(batch_size, len(batch))
            source = batch.source
            records.extend(batch.records)
            if len(records) > limit:
                raise TransformationError(
                    f"blocking transformation {self.name!r} exceeded max_rows; "
                    "push this operation into the source query or raise 'max_rows'",
                    context={"transformation": self.name, "rows": len(records), "max_rows": limit},
                )
        logger.info("materialised %d rows for blocking transformation %r", len(records), self.name)
        return records, batch_size or 10_000, source


# --------------------------------------------------------------------------- #
@transformation("sort", "order_by")
class Sort(_MaterialisingTransformation):
    """Sort the whole dataset.

    Options: ``columns`` (required; ``"name desc"`` for descending),
    ``nulls_last`` (default true), ``max_rows``.

    Memory: the entire dataset.  Prefer ``ORDER BY`` in the source query - the
    database can use an index and spill to disk.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._keys: list[tuple[str, bool]] = []
        for entry in self.list_option("columns", required=True):
            name, _, direction = str(entry).partition(" ")
            self._keys.append((name.strip(), direction.strip().lower() == "desc"))
        self._nulls_last = self.bool_option("nulls_last", True)

    def apply_stream(self, stream: RecordStream, context: ExecutionContext) -> RecordStream:
        records, batch_size, source = self._collect(stream, context)

        # Stable sorts applied from the least significant key upwards give
        # correct multi-key ordering with mixed directions, which a single
        # composite key cannot do without a comparator.
        for column, descending in reversed(self._keys):

            def key_for(record: Record, c: str = column) -> tuple[int, int, float, str]:
                return _sort_key(record.get(c), self._nulls_last)

            records.sort(key=key_for, reverse=descending)
        return self._rebatch(records, batch_size, source)


def _sort_key(value: Any, nulls_last: bool) -> tuple[int, int, float, str]:
    """Total ordering across mixed types.

    Python 3 refuses both ``None < 1`` and ``"a" < 1``, and a real dataset with
    an uncast column contains both.  The key is widened to
    ``(null_rank, type_rank, number, text)`` so comparison never reaches two
    values of different types: nulls sort to one end, numbers before text.
    """
    if value is None:
        return (1 if nulls_last else -1, 0, 0.0, "")
    if isinstance(value, bool):
        return (0, 0, float(value), "")
    if isinstance(value, (int, float)):
        return (0, 0, float(value), "")
    return (0, 1, 0.0, str(value))


@transformation("deduplicate", "distinct", "dedupe")
class Deduplicate(_MaterialisingTransformation):
    """Remove duplicates across the whole dataset.

    Options: ``columns`` (business key; defaults to the whole record),
    ``keep`` (``first``|``last``), ``order_by`` (decides which row wins),
    ``max_rows``.

    Memory: one hash per distinct key plus the retained rows.  When only the key
    matters, ``keep: first`` streams in constant memory relative to duplicates.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._columns = self.list_option("columns")
        self._keep = self.str_option("keep", "first").lower()
        self._order_by = self.str_option("order_by", "")
        if self._keep not in {"first", "last"}:
            raise ConfigurationError(
                "'keep' must be 'first' or 'last'", context={"transformation": self.name}
            )
        self.dropped = 0

    def apply_stream(self, stream: RecordStream, context: ExecutionContext) -> RecordStream:
        if self._keep == "first" and not self._order_by:
            return self._stream_first(stream, context)

        records, batch_size, source = self._collect(stream, context)
        if self._order_by:
            column, _, direction = self._order_by.partition(" ")
            records.sort(
                key=lambda r: _sort_key(r.get(column.strip()), True),
                reverse=direction.strip().lower() == "desc",
            )
        chosen: dict[int, Record] = {}
        for record in records:
            key = self._key(record)
            if self._keep == "first" and key in chosen:
                self.dropped += 1
                continue
            if key in chosen:
                self.dropped += 1
            chosen[key] = record
        return self._rebatch(list(chosen.values()), batch_size, source)

    def _stream_first(self, stream: RecordStream, context: ExecutionContext) -> RecordStream:
        """``keep: first`` needs no materialisation - only the key set."""
        seen: set[int] = set()
        limit = self._max_rows()

        def generate() -> Iterator[RecordBatch]:
            for batch in stream:
                context.cancellation.raise_if_cancelled()
                kept: list[Record] = []
                for record in batch.records:
                    key = self._key(record)
                    if key in seen:
                        self.dropped += 1
                        continue
                    if len(seen) >= limit:
                        raise TransformationError(
                            "deduplicate exceeded max_rows distinct keys",
                            context={"transformation": self.name, "max_rows": limit},
                        )
                    seen.add(key)
                    kept.append(record)
                if kept:
                    yield batch.replace(kept)

        return generate()

    def _key(self, record: Record) -> int:
        import json

        payload = {c: record.get(c) for c in self._columns} if self._columns else record
        return hash(json.dumps(payload, sort_keys=True, default=str))


@transformation("aggregate", "group_by")
class Aggregate(_MaterialisingTransformation):
    """Group and aggregate.

    Options: ``group_by`` (list; empty means one global group),
    ``aggregations`` (``{output: {column, function}}``, required),
    ``max_groups``.

    Functions: ``sum``, ``avg``/``mean``, ``min``, ``max``, ``count``,
    ``count_distinct``, ``first``, ``last``, ``list``, ``concat``.

    Memory: one accumulator per group, *not* one row per input row - so a
    100-million-row table grouped into 500 keys is cheap.  Only
    ``count_distinct``, ``list`` and ``concat`` retain per-row data, and each
    caps what it keeps.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._group_by = self.list_option("group_by")
        raw = self.dict_option("aggregations", required=True)
        self._aggregations: dict[str, tuple[str, str]] = {}
        for output, definition in raw.items():
            if isinstance(definition, str):
                function, column = definition, output
            else:
                function = str(definition.get("function", "sum"))
                column = str(definition.get("column", output))
            if function not in _AGGREGATORS:
                raise ConfigurationError(
                    "unknown aggregate function",
                    context={"function": function, "supported": sorted(_AGGREGATORS)},
                )
            self._aggregations[str(output)] = (column, function)
        self._max_groups = self.int_option("max_groups", 1_000_000)

    def apply_stream(self, stream: RecordStream, context: ExecutionContext) -> RecordStream:
        # Single pass, accumulator per group: never materialises the input.
        groups: dict[tuple[Any, ...], dict[str, Any]] = {}
        batch_size = 10_000
        source = "aggregate"

        for batch in stream:
            context.cancellation.raise_if_cancelled()
            batch_size = max(batch_size, len(batch))
            source = batch.source
            for record in batch.records:
                key = tuple(record.get(column) for column in self._group_by)
                accumulators = groups.get(key)
                if accumulators is None:
                    if len(groups) >= self._max_groups:
                        raise TransformationError(
                            "aggregate exceeded max_groups; the group_by column is "
                            "probably higher-cardinality than expected",
                            context={"transformation": self.name, "max_groups": self._max_groups},
                        )
                    accumulators = {
                        output: _AGGREGATORS[function]()
                        for output, (_, function) in self._aggregations.items()
                    }
                    groups[key] = accumulators
                for output, (column, _) in self._aggregations.items():
                    accumulators[output].add(record.get(column))

        results: list[Record] = []
        for key, accumulators in groups.items():
            row: Record = dict(zip(self._group_by, key, strict=True))
            for output, accumulator in accumulators.items():
                row[output] = accumulator.value()
            results.append(row)

        logger.info("aggregated into %d group(s)", len(results))
        return self._rebatch(results, batch_size, source)


class _Accumulator:
    """Incremental aggregate state."""

    __slots__ = ()

    def add(self, value: Any) -> None: ...

    def value(self) -> Any: ...


class _Sum(_Accumulator):
    __slots__ = ("_total",)

    def __init__(self) -> None:
        self._total = 0.0

    def add(self, value: Any) -> None:
        number = _to_number(value)
        if number is not None:
            self._total += number

    def value(self) -> float:
        return round(self._total, 10)


class _Count(_Accumulator):
    __slots__ = ("_count",)

    def __init__(self) -> None:
        self._count = 0

    def add(self, value: Any) -> None:
        if value is not None:
            self._count += 1

    def value(self) -> int:
        return self._count


class _Mean(_Accumulator):
    __slots__ = ("_count", "_total")

    def __init__(self) -> None:
        self._total = 0.0
        self._count = 0

    def add(self, value: Any) -> None:
        number = _to_number(value)
        if number is not None:
            self._total += number
            self._count += 1

    def value(self) -> float | None:
        return round(self._total / self._count, 10) if self._count else None


class _Extreme(_Accumulator):
    __slots__ = ("_best", "_is_max")

    def __init__(self, is_max: bool) -> None:
        self._best: Any = None
        self._is_max = is_max

    def add(self, value: Any) -> None:
        if value is None:
            return
        if self._best is None:
            self._best = value
            return
        try:
            better = value > self._best if self._is_max else value < self._best
        except TypeError:
            better = (
                (str(value) > str(self._best)) if self._is_max else (str(value) < str(self._best))
            )
        if better:
            self._best = value

    def value(self) -> Any:
        return self._best


class _Edge(_Accumulator):
    __slots__ = ("_seen", "_take_first", "_value")

    def __init__(self, take_first: bool) -> None:
        self._value: Any = None
        self._seen = False
        self._take_first = take_first

    def add(self, value: Any) -> None:
        if self._take_first and self._seen:
            return
        self._value = value
        self._seen = True

    def value(self) -> Any:
        return self._value


class _CountDistinct(_Accumulator):
    __slots__ = ("_seen",)
    LIMIT = 1_000_000

    def __init__(self) -> None:
        self._seen: set[Any] = set()

    def add(self, value: Any) -> None:
        if value is not None and len(self._seen) < self.LIMIT:
            self._seen.add(str(value))

    def value(self) -> int:
        return len(self._seen)


class _Collect(_Accumulator):
    __slots__ = ("_items", "_join")
    LIMIT = 10_000

    def __init__(self, join: str | None = None) -> None:
        self._items: list[Any] = []
        self._join = join

    def add(self, value: Any) -> None:
        if value is not None and len(self._items) < self.LIMIT:
            self._items.append(value)

    def value(self) -> Any:
        if self._join is not None:
            return self._join.join(str(item) for item in self._items)
        return self._items


def _to_number(value: Any) -> float | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


_AGGREGATORS: dict[str, Callable[[], _Accumulator]] = {
    "sum": _Sum,
    "count": _Count,
    "avg": _Mean,
    "mean": _Mean,
    "min": lambda: _Extreme(is_max=False),
    "max": lambda: _Extreme(is_max=True),
    "first": lambda: _Edge(take_first=True),
    "last": lambda: _Edge(take_first=False),
    "count_distinct": _CountDistinct,
    "list": _Collect,
    "concat": lambda: _Collect(join=","),
}


@transformation("join", "lookup_join", "enrich")
class Join(_MaterialisingTransformation):
    """Enrich the stream from a lookup source.

    Options: ``source`` (a connector spec, required), ``left_on`` (required),
    ``right_on`` (defaults to ``left_on``), ``how`` (``inner``|``left``),
    ``columns`` (subset to bring across), ``prefix``, ``max_rows``.

    Memory: only the *lookup* side is materialised, into a hash index; the main
    stream still flows batch by batch.  That is the right shape for the common
    case - a large fact stream enriched from a small dimension.  If the lookup
    itself is large, do the join in the database.
    """

    def __init__(self, spec: TransformSpec) -> None:
        super().__init__(spec)
        self._left_on = self.list_option("left_on", required=True)
        self._right_on = self.list_option("right_on") or self._left_on
        if len(self._left_on) != len(self._right_on):
            raise ConfigurationError(
                "left_on and right_on must have the same number of columns",
                context={"transformation": self.name},
            )
        self._how = self.str_option("how", "left").lower()
        if self._how not in {"left", "inner"}:
            raise ConfigurationError(
                "'how' must be 'left' or 'inner'", context={"transformation": self.name}
            )
        self._columns = self.list_option("columns")
        self._prefix = self.str_option("prefix", "")
        self._source_spec = self.dict_option("source", required=True)
        self.matched = 0
        self.unmatched = 0

    def apply_stream(self, stream: RecordStream, context: ExecutionContext) -> RecordStream:
        index = self._build_index(context)

        def generate() -> Iterator[RecordBatch]:
            for batch in stream:
                context.cancellation.raise_if_cancelled()
                out: list[Record] = []
                for record in batch.records:
                    key = tuple(record.get(c) for c in self._left_on)
                    match = index.get(key)
                    if match is None:
                        self.unmatched += 1
                        if self._how == "inner":
                            continue
                        out.append(record)
                        continue
                    self.matched += 1
                    out.append({**record, **match})
                if out or self._how == "left":
                    yield batch.replace(out)

        return generate()

    def _build_index(self, context: ExecutionContext) -> dict[tuple[Any, ...], Record]:
        from ironflow.config.models import ConnectorSpec
        from ironflow.connectors import ConnectorFactory

        spec = ConnectorSpec.model_validate(self._source_spec)
        connector = ConnectorFactory().create_source(spec, context=f"join:{self.name}")
        limit = self._max_rows()
        index: dict[tuple[Any, ...], Record] = {}

        connector.open(context)
        try:
            for batch in connector.read(context):
                for record in batch.records:
                    if len(index) >= limit:
                        raise TransformationError(
                            "join lookup exceeded max_rows; perform this join in the "
                            "source database instead",
                            context={"transformation": self.name, "max_rows": limit},
                        )
                    key = tuple(record.get(c) for c in self._right_on)
                    payload = (
                        {c: record.get(c) for c in self._columns} if self._columns else dict(record)
                    )
                    for column in self._right_on:
                        payload.pop(column, None)
                    if self._prefix:
                        payload = {f"{self._prefix}{k}": v for k, v in payload.items()}
                    # First row wins: a duplicated dimension key is a data
                    # problem, and silently fanning out the fact table hides it.
                    index.setdefault(key, payload)
        finally:
            connector.close()

        logger.info("built join index with %d key(s) for %r", len(index), self.name)
        return index


@transformation("limit", "head", "sample")
class Limit(StreamTransformation):
    """Emit at most N records.

    Options: ``count`` (default 100).

    Non-blocking despite living here: it short-circuits the stream, which makes
    it the right tool for ``--dry-run`` previews and smoke tests.
    """

    blocking = False

    def apply_stream(self, stream: RecordStream, context: ExecutionContext) -> RecordStream:
        limit = self.int_option("count", 100)

        def generate() -> Iterator[RecordBatch]:
            emitted = 0
            for batch in stream:
                if emitted >= limit:
                    return
                remaining = limit - emitted
                records = batch.records[:remaining]
                emitted += len(records)
                yield batch.replace(records)

        return generate()


__all__ = ["Aggregate", "Deduplicate", "Join", "Limit", "Sort"]
