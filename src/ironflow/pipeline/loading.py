"""Loading engine: transactional writes, quarantine routing and rollback.

Contract
--------
The engine owns the sink's transaction boundary.  Nothing is committed until the
entire stream has been consumed without error; any exception triggers
``rollback`` on both the main and the reject sink.  For a transactional
destination (SQL, staged files, Parquet) that means a failed run leaves the
destination byte-identical to how it started.

That guarantee is what makes ``on_violation: fail`` meaningful and what lets an
operator re-run a failed job without first working out how much of it landed.

Non-transactional sinks (REST) cannot offer it.  They say so through
``transactional = False``, the engine logs a warning naming the sink at open
time, and ``ironflow pipeline validate`` reports it - so the limitation is known
before the incident, not during it.

Dry runs read, transform and validate everything but never open the destination,
which makes ``--dry-run`` a genuine rehearsal rather than a syntax check.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any

from ironflow.connectors.base import BaseSink
from ironflow.core.context import ExecutionContext
from ironflow.core.errors import LoadingError
from ironflow.core.types import Record, RecordBatch, RecordStream
from ironflow.observability.metrics import Metric

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class LoadResult:
    """Counters produced by one load."""

    rows_written: int = 0
    rows_rejected: int = 0
    batches: int = 0
    seconds: float = 0.0
    committed: bool = False
    rolled_back: bool = False

    @property
    def throughput(self) -> float:
        return round(self.rows_written / self.seconds, 2) if self.seconds > 0 else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "rows_written": self.rows_written,
            "rows_rejected": self.rows_rejected,
            "batches": self.batches,
            "seconds": round(self.seconds, 4),
            "throughput_rows_per_second": self.throughput,
            "committed": self.committed,
            "rolled_back": self.rolled_back,
        }


class LoadEngine:
    """Drives a sink through open -> write* -> commit / rollback -> close."""

    def __init__(
        self,
        sink: BaseSink | None,
        *,
        reject_sink: BaseSink | None = None,
        task_name: str = "",
    ) -> None:
        self.sink = sink
        self.reject_sink = reject_sink
        self.task_name = task_name
        self.result = LoadResult()
        self._reject_opened = False

    def load(
        self,
        stream: RecordStream,
        context: ExecutionContext,
        *,
        rejects_for: dict[int, list[Record]] | None = None,
    ) -> LoadResult:
        """Consume ``stream`` into the sink inside one transaction."""
        if self.sink is None or context.dry_run:
            return self._consume_without_writing(stream, context)

        started = time.perf_counter()
        self.sink.open(context)
        if not self.sink.transactional:
            logger.warning(
                "destination %r is not transactional: a failure part-way through will "
                "leave partial data at the destination",
                self.sink.name,
            )

        try:
            for batch in stream:
                context.cancellation.raise_if_cancelled()
                self._write_batch(batch, context)
            self._commit()
        except Exception as exc:
            self._rollback(exc)
            raise
        finally:
            self.result.seconds = time.perf_counter() - started
            self._close()

        logger.info(
            "loaded %d row(s) into %s in %.2fs (%.0f rows/s)",
            self.result.rows_written,
            self.sink.name,
            self.result.seconds,
            self.result.throughput,
        )
        return self.result

    def write_rejects(self, records: list[Record], context: ExecutionContext) -> int:
        """Route quarantined records to the reject destination.

        A failure here is logged, not raised: losing the quarantine copy is bad,
        but failing an otherwise healthy load because the quarantine table is
        full is worse.  The count is still recorded, so the discrepancy is
        visible in the run report.
        """
        if not records:
            return 0
        self.result.rows_rejected += len(records)

        if self.reject_sink is None or context.dry_run:
            return len(records)

        try:
            if not self._reject_opened:
                self.reject_sink.open(context)
                self._reject_opened = True
            self.reject_sink.write(RecordBatch(records, source="quarantine"), context)
        except Exception:
            logger.error(
                "unable to write %d quarantined record(s) to %s",
                len(records),
                self.reject_sink.name,
                exc_info=True,
            )
        return len(records)

    # -- internals --------------------------------------------------------- #
    def _write_batch(self, batch: RecordBatch, context: ExecutionContext) -> None:
        if batch.is_empty:
            return
        assert self.sink is not None
        try:
            written = self.sink.write(batch, context)
        except LoadingError:
            raise
        except Exception as exc:
            raise LoadingError(
                f"destination {self.sink.name!r} failed while writing a batch",
                context={"task": self.task_name, "batch": batch.sequence, "rows": len(batch)},
                cause=exc,
            ) from exc

        self.result.rows_written += written
        self.result.batches += 1
        if context.metrics is not None:
            context.metrics.counter(
                Metric.ROWS_LOADED,
                written,
                labels={"pipeline": context.pipeline_id, "task": context.task_id},
                help="Rows written to destinations.",
            )

    def _commit(self) -> None:
        if self.sink is not None:
            self.sink.commit()
        if self.reject_sink is not None and self._reject_opened:
            self.reject_sink.commit()
        self.result.committed = True

    def _rollback(self, exc: BaseException) -> None:
        logger.error(
            "load failed for task %r; rolling back %d written row(s): %s",
            self.task_name,
            self.result.rows_written,
            exc,
        )
        for sink, opened in ((self.sink, True), (self.reject_sink, self._reject_opened)):
            if sink is None or not opened:
                continue
            try:
                sink.rollback()
            except Exception:
                logger.error("rollback of %s failed", sink.name, exc_info=True)
        self.result.rolled_back = True

    def _close(self) -> None:
        for sink in (self.sink, self.reject_sink):
            if sink is None:
                continue
            try:
                sink.close()
            except Exception:
                logger.warning("closing %s failed", sink.name, exc_info=True)

    def _consume_without_writing(
        self, stream: RecordStream, context: ExecutionContext
    ) -> LoadResult:
        """Dry run: exercise the full read/transform/validate path, write nothing."""
        started = time.perf_counter()
        for batch in stream:
            context.cancellation.raise_if_cancelled()
            self.result.rows_written += len(batch)
            self.result.batches += 1
        self.result.seconds = time.perf_counter() - started
        self.result.committed = False
        logger.info(
            "dry run: %d row(s) would have been written by task %r",
            self.result.rows_written,
            self.task_name,
        )
        return self.result


__all__ = ["LoadEngine", "LoadResult"]
