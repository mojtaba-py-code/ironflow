"""Extraction engine: load strategies, watermarks and schema-drift detection.

Load strategies
---------------
``full``
    Read everything.  Simple, always correct, and the right default below a few
    million rows.
``incremental``
    Read only rows whose watermark column exceeds the previous run's high-water
    mark.  The mark is advanced *only after the destination commits* - advancing
    it optimistically is how rows get silently skipped forever when a load
    fails after extraction.
``cdc``
    Incremental plus business-key deduplication over the re-read overlap window,
    so a row updated twice inside the overlap arrives once.

The overlap window deserves explanation.  A row inserted in a transaction that
commits at 10:00:05 may carry ``updated_at = 10:00:00``.  If the previous run's
mark was 10:00:02, that row is invisible forever.  Re-reading a configurable
overlap (typically a few seconds) closes the gap, and the ``key_columns``
deduplication removes the rows the overlap re-delivers.

Schema drift
------------
The first batch's inferred schema is compared with the previous run's snapshot.
``strict`` fails on any change, ``additive`` (default) allows new columns but
fails on removed ones or type changes, ``permissive`` only logs.  Detecting a
removed column *before* the load is what prevents a table quietly filling with
NULLs.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from ironflow.config.models import TaskSpec
from ironflow.connectors.base import BaseSource
from ironflow.core.context import ExecutionContext
from ironflow.core.errors import ConfigurationError, ExtractionError, SchemaError
from ironflow.core.events import EventType
from ironflow.core.types import (
    DatasetSchema,
    LoadStrategy,
    Record,
    RecordBatch,
    RecordStream,
    SchemaDiff,
)
from ironflow.observability.metrics import Metric
from ironflow.repositories.repositories import SchemaRepository, WatermarkRepository

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class ExtractionState:
    """Mutable state accumulated while a stream is consumed."""

    rows_read: int = 0
    batches: int = 0
    previous_watermark: Any = None
    max_watermark: Any = None
    schema: DatasetSchema = field(default_factory=DatasetSchema)
    schema_diff: SchemaDiff = field(default_factory=SchemaDiff)
    duplicates_dropped: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rows_read": self.rows_read,
            "batches": self.batches,
            "previous_watermark": self.previous_watermark,
            "new_watermark": self.max_watermark,
            "duplicates_dropped": self.duplicates_dropped,
            "schema_drift": self.schema_diff.to_dict() if not self.schema_diff.is_empty else None,
        }


class ExtractionEngine:
    """Wraps a source with strategy, watermark and drift handling."""

    def __init__(
        self,
        task: TaskSpec,
        pipeline_name: str,
        *,
        watermarks: WatermarkRepository | None = None,
        schemas: SchemaRepository | None = None,
    ) -> None:
        self.task = task
        self.pipeline_name = pipeline_name
        self.watermarks = watermarks
        self.schemas = schemas
        self.state = ExtractionState()

    @property
    def strategy(self) -> LoadStrategy:
        return self.task.strategy

    @property
    def is_incremental(self) -> bool:
        return self.strategy in (LoadStrategy.INCREMENTAL, LoadStrategy.CDC)

    # -- watermark --------------------------------------------------------- #
    def prepare(self, source: BaseSource, context: ExecutionContext) -> None:
        """Resolve the starting watermark and push it into the source spec."""
        if not self.is_incremental or self.task.incremental is None:
            return
        if not source.supports_incremental:
            # Before anything is read: the source would ignore the watermark, and
            # every "incremental" run would silently be a full load.
            raise ConfigurationError(
                f"strategy {self.strategy.value!r} needs a source that can filter on "
                f"the watermark; a {source.spec.type!r} source re-reads its whole input "
                "on every run. Use 'strategy: full' with an overwrite or upsert destination",
                context={"task": self.task.name, "source": source.name},
            )

        incremental = self.task.incremental
        previous = None
        if self.watermarks is not None:
            previous = self.watermarks.get(self.pipeline_name, self.task.name)
        if previous is None:
            previous = incremental.initial_value

        effective = _apply_overlap(previous, incremental.overlap)
        self.state.previous_watermark = previous
        self.state.max_watermark = previous

        if effective is not None:
            # Passed as a *bound parameter*, never interpolated into SQL.
            source.spec.__pydantic_extra__["__watermark_column__"] = incremental.column  # type: ignore[index]
            params = dict(source.spec.options.get("params") or {})
            params["__watermark__"] = effective
            source.spec.__pydantic_extra__["params"] = params  # type: ignore[index]
            logger.info(
                "incremental extraction from %s > %r (overlap %.1fs)",
                incremental.column,
                effective,
                incremental.overlap,
            )
        else:
            logger.info(
                "no previous watermark for task %r; performing an initial full read",
                self.task.name,
            )

    def commit_watermark(self, context: ExecutionContext) -> None:
        """Persist the new high-water mark.  Called only after a successful load."""
        if not self.is_incremental or self.task.incremental is None:
            return
        if self.watermarks is None or self.state.max_watermark is None:
            return
        if context.dry_run:
            logger.info("dry run: not advancing the watermark")
            return
        self.watermarks.set(
            self.pipeline_name,
            self.task.name,
            column=self.task.incremental.column,
            value=self.state.max_watermark,
            rows=self.state.rows_read,
            execution_id=context.execution_id,
        )
        logger.info(
            "watermark for %s/%s advanced to %r",
            self.pipeline_name,
            self.task.name,
            self.state.max_watermark,
        )

    # -- reading ----------------------------------------------------------- #
    def read(self, source: BaseSource, context: ExecutionContext) -> RecordStream:
        """Return the instrumented, deduplicated batch stream."""
        column = self.task.incremental.column if self.task.incremental else None
        key_columns = list(self.task.incremental.key_columns) if self.task.incremental else []
        deduplicate = self.strategy is LoadStrategy.CDC and bool(key_columns)
        seen_keys: set[int] = set()

        def generate() -> Iterator[RecordBatch]:
            try:
                stream = source.read(context)
            except ExtractionError:
                raise
            except Exception as exc:
                raise ExtractionError(
                    f"source {source.name!r} failed to start reading",
                    context={"task": self.task.name},
                    cause=exc,
                ) from exc

            first = True
            for batch in stream:
                context.cancellation.raise_if_cancelled()

                if first:
                    first = False
                    self._check_schema(batch, source, context)

                records = batch.records
                if deduplicate:
                    records = self._deduplicate(records, key_columns, seen_keys)

                if column:
                    self._advance_watermark(records, column)

                self.state.rows_read += len(records)
                self.state.batches += 1
                self._emit_metrics(context, len(records))

                yield batch.replace(records)

        return generate()

    def _deduplicate(
        self, records: list[Record], key_columns: list[str], seen: set[int]
    ) -> list[Record]:
        """Drop rows already delivered within this run (CDC overlap)."""
        kept: list[Record] = []
        for record in records:
            key = hash(tuple(str(record.get(c)) for c in key_columns))
            if key in seen:
                self.state.duplicates_dropped += 1
                continue
            seen.add(key)
            kept.append(record)
        return kept

    def _advance_watermark(self, records: list[Record], column: str) -> None:
        for record in records:
            value = record.get(column)
            if value is None:
                continue
            if self.state.max_watermark is None or _greater(value, self.state.max_watermark):
                self.state.max_watermark = value

    def _check_schema(
        self, batch: RecordBatch, source: BaseSource, context: ExecutionContext
    ) -> None:
        """Detect and act on schema drift using the first batch."""
        policy = self.task.schema_evolution
        if not policy.enabled:
            return

        declared = source.describe()
        observed = declared if declared.fields else batch.infer_schema()
        self.state.schema = observed

        if self.schemas is None:
            return

        diff = self.schemas.compare_and_store(
            pipeline=self.pipeline_name,
            task=self.task.name,
            schema=observed,
            source_key=source.name,
            store=not context.dry_run,
        )
        self.state.schema_diff = diff
        if diff.is_empty:
            return

        logger.warning("schema drift detected for task %r: %s", self.task.name, diff.to_dict())
        if context.events is not None:
            context.events.emit(
                EventType.SCHEMA_DRIFT_DETECTED,
                pipeline_id=context.pipeline_id,
                execution_id=context.execution_id,
                task_id=self.task.name,
                **diff.to_dict(),
            )

        if policy.mode == "permissive":
            return
        if policy.mode == "strict":
            raise SchemaError(
                "schema drift detected and the evolution policy is 'strict'",
                context={"task": self.task.name, **diff.to_dict()},
            )
        # additive
        if diff.removed and policy.fail_on_removed_columns:
            raise SchemaError(
                "columns disappeared from the source; refusing to load NULLs over existing data",
                context={"task": self.task.name, "removed": list(diff.removed)},
            )
        if diff.type_changed and policy.fail_on_type_change:
            raise SchemaError(
                "column types changed in the source",
                context={"task": self.task.name, "changed": list(diff.type_changed)},
            )
        if diff.added:
            logger.info(
                "task %r: new column(s) %s accepted under the additive policy",
                self.task.name,
                list(diff.added),
            )

    def _emit_metrics(self, context: ExecutionContext, rows: int) -> None:
        if context.metrics is None:
            return
        labels = {"pipeline": context.pipeline_id, "task": context.task_id}
        context.metrics.counter(
            Metric.ROWS_EXTRACTED, rows, labels=labels, help="Rows read from sources."
        )
        context.metrics.counter(Metric.BATCHES, 1, labels=labels)

    def report(self) -> dict[str, Any]:
        return {"strategy": self.strategy.value, **self.state.to_dict()}


def _greater(a: Any, b: Any) -> bool:
    try:
        return bool(a > b)
    except TypeError:
        return str(a) > str(b)


def _apply_overlap(watermark: Any, overlap_seconds: float) -> Any:
    """Rewind a timestamp watermark by the overlap window.

    Non-temporal watermarks (an auto-increment id) are returned unchanged - you
    cannot subtract seconds from a sequence number, and doing so numerically
    would re-read an arbitrary number of rows.
    """
    if watermark is None or overlap_seconds <= 0:
        return watermark

    from datetime import datetime, timedelta

    if isinstance(watermark, datetime):
        return watermark - timedelta(seconds=overlap_seconds)
    if isinstance(watermark, str):
        try:
            parsed = datetime.fromisoformat(watermark.replace("Z", "+00:00"))
        except ValueError:
            return watermark
        return (parsed - timedelta(seconds=overlap_seconds)).isoformat()
    return watermark


__all__ = ["ExtractionEngine", "ExtractionState"]
