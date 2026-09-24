"""Task executor - runs one task end to end.

Pipeline shape
--------------
``source -> extraction -> [validate] -> transform -> [validate] -> load``

The whole chain is a single lazy generator: no stage materialises its output for
the next one, so memory is bounded by ``batch_size`` even for a source larger
than RAM (except where an explicitly blocking transformation says otherwise).

Ordering of validation is configurable and defaults to *after* transformation,
because that is where the data has the types the destination expects.  Validating
the raw CSV strings would reject every integer column.

Retries wrap the whole task, not individual batches.  A partially loaded
transactional destination is rolled back first, so attempt 2 starts from a clean
state - retrying at batch granularity against a non-idempotent destination is
how duplicates get created.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterator
from typing import Any

from ironflow.config.models import TaskSpec
from ironflow.connectors.base import BaseSink, BaseSource
from ironflow.connectors.factory import ConnectorFactory
from ironflow.core.context import ExecutionContext
from ironflow.core.errors import IronFlowError, PipelineError, TaskError
from ironflow.core.events import EventType
from ironflow.core.retry import RetryPolicy, call_with_retry
from ironflow.core.types import RecordBatch, RecordStream, RunStatus
from ironflow.expressions import compile_expression
from ironflow.observability.metrics import Metric
from ironflow.pipeline.extraction import ExtractionEngine
from ironflow.pipeline.loading import LoadEngine
from ironflow.pipeline.results import TaskResult
from ironflow.repositories.repositories import SchemaRepository, WatermarkRepository
from ironflow.transformation.engine import TransformationPipeline
from ironflow.validation.engine import ValidationEngine

logger = logging.getLogger(__name__)


class TaskExecutor:
    """Executes a single :class:`TaskSpec`."""

    def __init__(
        self,
        task: TaskSpec,
        pipeline_name: str,
        *,
        factory: ConnectorFactory,
        watermarks: WatermarkRepository | None = None,
        schemas: SchemaRepository | None = None,
    ) -> None:
        self.task = task
        self.pipeline_name = pipeline_name
        self.factory = factory
        self.extraction = ExtractionEngine(
            task, pipeline_name, watermarks=watermarks, schemas=schemas
        )
        self.validation = ValidationEngine(task.validation, task_name=task.name)
        self.transformations = TransformationPipeline.from_specs(
            task.transformations, task_name=task.name
        )
        self._load_engine: LoadEngine | None = None

    # -- public API -------------------------------------------------------- #
    def should_run(self, context: ExecutionContext) -> tuple[bool, str]:
        """Evaluate the task's ``condition``; returns ``(run, reason)``."""
        if not self.task.enabled:
            return False, "task is disabled in the pipeline definition"
        if not self.task.condition:
            return True, ""
        expression = compile_expression(self.task.condition)
        scope = {
            "params": dict(context.parameters),
            "state": dict(context.state),
            "pipeline": self.pipeline_name,
            "task": self.task.name,
            "dry_run": context.dry_run,
        }
        if expression.evaluate_bool(scope):
            return True, ""
        return False, f"condition evaluated false: {self.task.condition}"

    def execute(self, context: ExecutionContext) -> TaskResult:
        """Run the task, applying its retry policy."""
        # The runner normally hands us a task-scoped context. When the executor
        # is driven directly (tests, embedding), scope it here so metric labels
        # and log records carry the task name instead of "-".
        if context.task_id in ("-", ""):
            context = context.for_task(self.task.name)

        result = TaskResult(task_name=self.task.name)
        should_run, reason = self.should_run(context)
        if not should_run:
            result.skipped_reason = reason
            logger.info("skipping task %r: %s", self.task.name, reason)
            self._emit(context, EventType.TASK_SKIPPED, reason=reason)
            return result.finish(RunStatus.SKIPPED)

        self._emit(context, EventType.TASK_STARTED)
        policy = self._retry_policy()
        attempt_counter = {"n": 0}

        def attempt() -> TaskResult:
            attempt_counter["n"] += 1
            result.attempt = attempt_counter["n"]
            if attempt_counter["n"] > 1:
                self._reset_for_retry()
            return self._run_once(context, result)

        try:
            call_with_retry(
                attempt,
                policy,
                description=f"task {self.task.name!r}",
                on_retry=lambda n, exc, delay: self._on_retry(context, n, exc, delay),
            )
        except PipelineError as exc:
            if context.cancellation.is_cancelled:
                return result.finish(RunStatus.CANCELLED, exc)
            return self._fail(context, result, exc)
        except IronFlowError as exc:
            return self._fail(context, result, exc)
        except Exception as exc:
            return self._fail(
                context,
                result,
                TaskError(
                    f"task {self.task.name!r} failed unexpectedly",
                    context={"task": self.task.name},
                    cause=exc,
                ),
            )

        result.finish(RunStatus.SUCCESS)
        self._record_metrics(context, result)
        self._emit(
            context,
            EventType.TASK_SUCCEEDED,
            rows_written=result.metrics.rows_out,
            duration=round(result.duration_seconds, 3),
        )
        logger.info(
            "task %r succeeded: %d row(s) written in %.2fs",
            self.task.name,
            result.metrics.rows_out,
            result.duration_seconds,
        )
        return result

    # -- execution --------------------------------------------------------- #
    def _run_once(self, context: ExecutionContext, result: TaskResult) -> TaskResult:
        if self.task.type == "noop":
            logger.info("task %r is a no-op", self.task.name)
            return result

        if self.task.type == "sql":
            return self._run_sql(context, result)

        source = self._build_source()
        sink = self._build_sink(context)
        reject_sink = self._build_reject_sink()
        self._load_engine = LoadEngine(sink, reject_sink=reject_sink, task_name=self.task.name)

        deadline = time.monotonic() + self.task.timeout if self.task.timeout else None

        source.open(context)
        try:
            self.extraction.prepare(source, context)
            stream = self._build_stream(source, context, deadline)
            load_result = self._load_engine.load(stream, context)
        finally:
            self._close_source(source)

        # The watermark advances only after the destination has committed.
        if load_result.committed or context.dry_run:
            self._commit_watermark(context, committed=load_result.committed)

        result.metrics.rows_in = self.extraction.state.rows_read
        result.metrics.rows_out = load_result.rows_written
        result.metrics.rows_failed = load_result.rows_rejected
        result.metrics.rows_skipped = self.extraction.state.duplicates_dropped
        result.metrics.batches = load_result.batches
        result.validation = self.validation.report()
        result.transformations = self.transformations.report()
        result.watermark = self.extraction.state.max_watermark
        if not self.extraction.state.schema_diff.is_empty:
            result.schema_drift = self.extraction.state.schema_diff.to_dict()
        return result

    @staticmethod
    def _close_source(source: BaseSource) -> None:
        """Close the source without letting a close error decide the outcome.

        After a committed load, raising here would report a failed run whose
        rows are published - and a retry would load them again.  After a failed
        load it would replace the error that explains the failure.
        """
        try:
            source.close()
        except Exception:
            logger.warning("closing source %s failed", source.name, exc_info=True)

    def _commit_watermark(self, context: ExecutionContext, *, committed: bool) -> None:
        """Advance the watermark; after a commit, a failure here is only logged.

        The destination's commit is the point of no return.  Failing the task
        now would report a failed run that changed the destination and invite a
        retry that loads the same rows again; instead the next run re-reads from
        the previous mark, which an upsert or overwrite destination absorbs and
        an append destination does not - hence the error.
        """
        try:
            self.extraction.commit_watermark(context)
        except Exception:
            if not committed:
                raise
            logger.error(
                "task %r committed its rows but the watermark could not be saved; the "
                "next run will re-read from the previous watermark %r",
                self.task.name,
                self.extraction.state.previous_watermark,
                exc_info=True,
            )

    def _build_stream(
        self, source: BaseSource, context: ExecutionContext, deadline: float | None
    ) -> RecordStream:
        """Compose extraction, validation and transformation into one stream."""
        stream = self.extraction.read(source, context)
        stage = self.task.validation.stage if self.task.validation else "post_transform"

        if self.validation.enabled and stage == "pre_transform":
            stream = self._validate_stream(stream, context)
        stream = self.transformations.apply(stream, context)
        if self.validation.enabled and stage == "post_transform":
            stream = self._validate_stream(stream, context)
        if deadline is not None:
            stream = self._enforce_timeout(stream, deadline)
        return stream

    def _validate_stream(self, stream: RecordStream, context: ExecutionContext) -> RecordStream:
        """Validate each batch and route rejects to the quarantine sink."""

        def generate() -> Iterator[RecordBatch]:
            for batch in stream:
                outcome = self.validation.validate_batch(batch, context)
                if outcome.rejected and self._load_engine is not None:
                    self._load_engine.write_rejects(outcome.rejected, context)
                if outcome.accepted:
                    yield outcome.accepted

        return generate()

    def _enforce_timeout(self, stream: RecordStream, deadline: float) -> RecordStream:
        """Abort between batches once the task's time budget is spent.

        Checking between batches (rather than interrupting a thread) keeps the
        in-flight write intact, so the rollback that follows is clean.
        """

        def generate() -> Iterator[RecordBatch]:
            for batch in stream:
                if time.monotonic() > deadline:
                    raise TaskError(
                        f"task {self.task.name!r} exceeded its timeout",
                        context={"task": self.task.name, "timeout": self.task.timeout},
                    )
                yield batch

        return generate()

    def _run_sql(self, context: ExecutionContext, result: TaskResult) -> TaskResult:
        """Execute a standalone statement (post-load maintenance, marker rows)."""
        from ironflow.connectors.sql import SqlSink, execute_statement

        if self.task.destination is None or not self.task.sql:
            raise TaskError(
                "sql tasks require both 'destination' and 'sql'",
                context={"task": self.task.name},
            )
        if context.dry_run:
            logger.info("dry run: not executing SQL for task %r", self.task.name)
            return result

        sink = self.factory.create_sink(self.task.destination, context=self.task.name)
        if not isinstance(sink, SqlSink):
            raise TaskError("sql tasks require a SQL destination", context={"task": self.task.name})
        engine = sink._create_engine()
        try:
            affected = execute_statement(engine, self.task.sql)
        finally:
            engine.dispose()
        result.metrics.rows_out = affected
        logger.info("task %r executed SQL, %d row(s) affected", self.task.name, affected)
        return result

    # -- construction ------------------------------------------------------ #
    def _build_source(self) -> BaseSource:
        assert self.task.source is not None
        spec = self.task.source
        if spec.batch_size is None and self.task.batch_size:
            spec.batch_size = self.task.batch_size
        return self.factory.create_source(spec, context=self.task.name)

    def _build_sink(self, context: ExecutionContext) -> BaseSink | None:
        if self.task.destination is None or context.dry_run:
            return None
        return self.factory.create_sink(self.task.destination, context=self.task.name)

    def _build_reject_sink(self) -> BaseSink | None:
        if self.task.reject_destination is None:
            return None
        return self.factory.create_sink(
            self.task.reject_destination, context=f"{self.task.name}:rejects"
        )

    def _retry_policy(self) -> RetryPolicy:
        spec = self.task.retry
        if spec is None:
            return RetryPolicy.disabled()
        return RetryPolicy(
            max_attempts=spec.max_attempts,
            initial_delay=spec.initial_delay,
            max_delay=spec.max_delay,
            multiplier=spec.multiplier,
            jitter=spec.jitter,
        )

    def _reset_for_retry(self) -> None:
        """Rebuild per-attempt state so a retry is not polluted by the last one."""
        self.validation.reset()
        self.extraction = ExtractionEngine(
            self.task,
            self.pipeline_name,
            watermarks=self.extraction.watermarks,
            schemas=self.extraction.schemas,
        )
        self.transformations = TransformationPipeline.from_specs(
            self.task.transformations, task_name=self.task.name
        )

    # -- bookkeeping ------------------------------------------------------- #
    def _fail(self, context: ExecutionContext, result: TaskResult, exc: Exception) -> TaskResult:
        result.validation = self.validation.report()
        result.transformations = self.transformations.report()
        result.metrics.rows_in = self.extraction.state.rows_read
        logger.error("task %r failed: %s", self.task.name, exc, exc_info=True)
        self._emit(context, EventType.TASK_FAILED, error=str(exc)[:500])
        if context.metrics is not None:
            context.metrics.counter(
                Metric.TASK_RUNS,
                labels={
                    "pipeline": context.pipeline_id,
                    "task": context.task_id,
                    "status": "failed",
                },
            )
        return result.finish(RunStatus.FAILED, exc)

    def _on_retry(
        self, context: ExecutionContext, attempt: int, exc: BaseException, delay: float
    ) -> None:
        logger.warning(
            "task %r attempt %d failed (%s); retrying in %.1fs",
            self.task.name,
            attempt,
            exc,
            delay,
        )
        if context.metrics is not None:
            context.metrics.counter(
                Metric.RETRY_ATTEMPTS,
                labels={"pipeline": context.pipeline_id, "task": context.task_id},
            )
        self._emit(context, EventType.TASK_RETRYING, attempt=attempt, error=str(exc)[:300])

    def _record_metrics(self, context: ExecutionContext, result: TaskResult) -> None:
        if context.metrics is None:
            return
        # ``context.task_id`` (not ``self.task.name``) so every emitter in the
        # task - extraction, loading, validation - uses identical labels and the
        # series line up in Prometheus.
        labels = {"pipeline": context.pipeline_id, "task": context.task_id}
        context.metrics.counter(Metric.TASK_RUNS, labels={**labels, "status": "success"})
        context.metrics.observe(Metric.TASK_DURATION, result.duration_seconds, labels=labels)
        context.metrics.gauge(
            Metric.THROUGHPUT, result.metrics.throughput_rows_per_second, labels=labels
        )

    def _emit(self, context: ExecutionContext, event: EventType, **payload: Any) -> None:
        if context.events is None:
            return
        context.events.emit(
            event,
            pipeline_id=context.pipeline_id,
            execution_id=context.execution_id,
            task_id=self.task.name,
            **payload,
        )


__all__ = ["TaskExecutor"]
