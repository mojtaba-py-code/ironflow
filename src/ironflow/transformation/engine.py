"""Transformation pipeline - composes steps into a single lazy stream.

The engine builds a chain of generators rather than a list of intermediate
results, so a 50-step transformation over a 40 GB source still holds only one
batch per step in memory.  Batch-level steps are fused into one pass over each
batch (one loop, not N), and blocking steps are inserted as stream operators.

Per-step timings and row deltas are collected because "the job got slower" is
otherwise unanswerable: with them, ``ironflow pipeline logs`` shows exactly
which step went from 2 s to 40 s.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field
from typing import Any

from ironflow.config.models import TransformSpec
from ironflow.core.context import ExecutionContext
from ironflow.core.errors import TransformationError
from ironflow.core.types import RecordBatch, RecordStream
from ironflow.transformation.base import (
    BaseTransformation,
    StreamTransformation,
    Transformation,
    build_transformation,
)

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class StepStats:
    """Per-step counters, surfaced in the run report."""

    name: str
    type: str
    blocking: bool
    rows_in: int = 0
    rows_out: int = 0
    batches: int = 0
    seconds: float = 0.0
    errors: int = 0

    @property
    def rows_dropped(self) -> int:
        return max(0, self.rows_in - self.rows_out)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "blocking": self.blocking,
            "rows_in": self.rows_in,
            "rows_out": self.rows_out,
            "rows_dropped": self.rows_dropped,
            "batches": self.batches,
            "seconds": round(self.seconds, 4),
            "errors": self.errors,
        }


@dataclass(slots=True)
class TransformationPipeline:
    """An ordered chain of transformations."""

    steps: list[BaseTransformation] = field(default_factory=list)
    stats: list[StepStats] = field(default_factory=list)
    task_name: str = ""

    @classmethod
    def from_specs(
        cls, specs: Sequence[TransformSpec], *, task_name: str = ""
    ) -> TransformationPipeline:
        """Build a pipeline, skipping disabled steps."""
        steps = [build_transformation(spec) for spec in specs if spec.enabled]
        stats = [
            StepStats(name=step.name, type=step.spec.type, blocking=step.blocking) for step in steps
        ]
        pipeline = cls(steps=steps, stats=stats, task_name=task_name)
        blocking = [s.name for s in steps if s.blocking]
        if blocking:
            logger.info(
                "task %r has blocking transformation(s) %s: the stream is materialised there",
                task_name,
                blocking,
            )
        return pipeline

    @property
    def is_empty(self) -> bool:
        return not self.steps

    @property
    def has_blocking_steps(self) -> bool:
        return any(step.blocking for step in self.steps)

    def apply(self, stream: RecordStream, context: ExecutionContext) -> RecordStream:
        """Wrap ``stream`` in the transformation chain (lazily)."""
        if not self.steps:
            return stream

        current = stream
        # Consecutive batch-level steps are fused into a single pass so a chain
        # of 10 renames costs one loop over each batch, not ten.
        buffer: list[tuple[Transformation, StepStats]] = []

        for step, stats in zip(self.steps, self.stats, strict=True):
            if isinstance(step, StreamTransformation):
                if buffer:
                    current = self._apply_batch_steps(current, buffer, context)
                    buffer = []
                current = self._apply_stream_step(current, step, stats, context)
            else:
                buffer.append((step, stats))  # type: ignore[arg-type]

        if buffer:
            current = self._apply_batch_steps(current, buffer, context)
        return current

    def _apply_batch_steps(
        self,
        stream: RecordStream,
        steps: list[tuple[Transformation, StepStats]],
        context: ExecutionContext,
    ) -> RecordStream:
        def generate() -> Iterator[RecordBatch]:
            for batch in stream:
                context.cancellation.raise_if_cancelled()
                current = batch
                for step, stats in steps:
                    stats.rows_in += len(current)
                    stats.batches += 1
                    started = time.perf_counter()
                    try:
                        current = step.apply(current, context)
                    except TransformationError as exc:
                        stats.errors += 1
                        exc.with_context(step=step.name, task=self.task_name)
                        raise
                    except Exception as exc:
                        stats.errors += 1
                        raise TransformationError(
                            f"transformation {step.name!r} failed",
                            context={"step": step.name, "task": self.task_name},
                            cause=exc,
                        ) from exc
                    finally:
                        stats.seconds += time.perf_counter() - started
                    stats.rows_out += len(current)
                    if current.is_empty:
                        break  # nothing left for later steps in this batch
                if not current.is_empty:
                    yield current

        return generate()

    def _apply_stream_step(
        self,
        stream: RecordStream,
        step: StreamTransformation,
        stats: StepStats,
        context: ExecutionContext,
    ) -> RecordStream:
        def counted_input() -> Iterator[RecordBatch]:
            for batch in stream:
                stats.rows_in += len(batch)
                stats.batches += 1
                yield batch

        started = time.perf_counter()
        try:
            transformed = step.apply_stream(counted_input(), context)
        except TransformationError as exc:
            stats.errors += 1
            exc.with_context(step=step.name, task=self.task_name)
            raise

        def counted_output() -> Iterator[RecordBatch]:
            try:
                for batch in transformed:
                    stats.rows_out += len(batch)
                    yield batch
            except TransformationError as exc:
                stats.errors += 1
                exc.with_context(step=step.name, task=self.task_name)
                raise
            finally:
                stats.seconds += time.perf_counter() - started

        return counted_output()

    def report(self) -> list[dict[str, Any]]:
        """Per-step summary for the run history and the CLI."""
        return [stats.to_dict() for stats in self.stats]

    def total_seconds(self) -> float:
        return sum(stats.seconds for stats in self.stats)

    def slowest_step(self) -> StepStats | None:
        return max(self.stats, key=lambda s: s.seconds, default=None)


__all__ = ["StepStats", "TransformationPipeline"]
