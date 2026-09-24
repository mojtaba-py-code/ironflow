"""Pipeline runner - orchestrates a whole run.

Responsibilities
----------------
* Build the DAG, and execute each level with a bounded thread pool.
* Enforce ``on_failure``: ``fail`` aborts the run and marks every downstream
  task ``SKIPPED``; ``continue`` proceeds and the run ends ``PARTIAL``.
* Checkpoint each successful task so ``pipeline resume`` restarts from the
  failure instead of the beginning.
* Record history, metrics, resource usage and audit entries.
* Publish events, which is how notifications are delivered without the runner
  knowing that Slack exists.

Why threads and not processes
-----------------------------
ETL tasks are I/O bound - a socket to a database, a socket to an API, a file
handle.  The GIL is released for all of them, so threads give real concurrency
with shared connection pools and no pickling of batches.  CPU-bound
transformation is the exception, and the honest answer there is to push the work
into the database or use a columnar engine, not to fan out processes.

Cancellation is cooperative: SIGINT sets the token, tasks notice it between
batches, in-flight transactions roll back cleanly.  Killing threads mid-write is
how a half-committed load happens.
"""

from __future__ import annotations

import logging
import signal
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from types import FrameType
from typing import Any

from ironflow.config.models import PipelineSpec
from ironflow.config.settings import Settings, get_settings
from ironflow.connectors.factory import ConnectorFactory
from ironflow.core.context import ExecutionContext, new_id
from ironflow.core.errors import ConfigurationError, IronFlowError, PipelineError
from ironflow.core.events import EventBus, EventType
from ironflow.core.types import RunStatus
from ironflow.observability.audit import AuditLog, NullAuditLog
from ironflow.observability.metrics import METRICS, Metric, MetricsRegistry
from ironflow.observability.resources import ResourceMonitor
from ironflow.orchestration.dag import TaskGraph
from ironflow.pipeline.results import PipelineResult, TaskResult
from ironflow.pipeline.task import TaskExecutor
from ironflow.repositories.repositories import (
    CheckpointRepository,
    RunRepository,
    SchemaRepository,
    WatermarkRepository,
)
from ironflow.security.rbac import Principal

logger = logging.getLogger(__name__)


class PipelineRunner:
    """Executes a :class:`PipelineSpec`."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        factory: ConnectorFactory | None = None,
        runs: RunRepository | None = None,
        watermarks: WatermarkRepository | None = None,
        checkpoints: CheckpointRepository | None = None,
        schemas: SchemaRepository | None = None,
        events: EventBus | None = None,
        metrics: MetricsRegistry | None = None,
        audit: AuditLog | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.factory = factory or ConnectorFactory(self.settings)
        self.runs = runs
        self.watermarks = watermarks
        self.checkpoints = checkpoints
        self.schemas = schemas
        self.events = events or EventBus()
        self.metrics = metrics or METRICS
        self.audit = audit or NullAuditLog()

    # ------------------------------------------------------------------ #
    def run(
        self,
        pipeline: PipelineSpec,
        *,
        parameters: dict[str, Any] | None = None,
        dry_run: bool = False,
        only: list[str] | None = None,
        resume_execution_id: str | None = None,
        principal: Principal | None = None,
        trigger: str = "manual",
        execution_id: str | None = None,
        install_signal_handlers: bool = False,
    ) -> PipelineResult:
        """Execute ``pipeline`` and return its :class:`PipelineResult`."""
        if not pipeline.enabled:
            raise ConfigurationError("pipeline is disabled", context={"pipeline": pipeline.name})

        context = ExecutionContext(
            pipeline_id=pipeline.name,
            execution_id=resume_execution_id or execution_id or new_id("exec_"),
            dry_run=dry_run,
            parameters={**pipeline.parameters, **(parameters or {})},
            principal=principal,
            metrics=self.metrics,
            events=self.events,
        )
        result = PipelineResult(
            pipeline_name=pipeline.name,
            execution_id=context.execution_id,
            correlation_id=context.correlation_id,
            dry_run=dry_run,
            parameters=context.parameters,
        )

        graph = TaskGraph.from_spec(pipeline)
        if only:
            graph = graph.subgraph(only)

        completed: set[str] = set()
        if resume_execution_id and self.checkpoints is not None:
            completed = self.checkpoints.completed_tasks(
                resume_execution_id, pipeline=pipeline.name
            )
            if completed:
                logger.info(
                    "resuming %s: %d task(s) already complete (%s)",
                    resume_execution_id,
                    len(completed),
                    ", ".join(sorted(completed)),
                )

        with context.bind(), ResourceMonitor() as resources:
            run_id = self._start_history(pipeline, context, graph, trigger, principal)
            # Installed once the start is accepted, so a refused start cannot
            # leave SIGINT pointing at a run that never began.
            restore = self._install_signal_handlers(context) if install_signal_handlers else None
            self.events.emit(
                EventType.PIPELINE_STARTED,
                pipeline_id=pipeline.name,
                execution_id=context.execution_id,
                tasks=graph.size,
                dry_run=dry_run,
            )
            self.audit.record(
                "pipeline.run",
                actor=(principal.subject if principal else "system"),
                resource=pipeline.name,
                correlation_id=context.correlation_id,
                execution_id=context.execution_id,
                trigger=trigger,
                dry_run=dry_run,
            )

            try:
                self._execute_levels(pipeline, graph, context, result, completed)
                result.finish(result.derive_status())
            except PipelineError as exc:
                result.finish(
                    RunStatus.CANCELLED if context.cancellation.is_cancelled else RunStatus.FAILED,
                    exc,
                )
            except IronFlowError as exc:
                result.finish(RunStatus.FAILED, exc)
            finally:
                if restore is not None:
                    restore()

        result.resources = resources.to_dict()
        result.metrics_snapshot = self.metrics.snapshot()
        self._finish_history(result)
        self._record_tasks(result, run_id, carried_over=completed)
        self._emit_completion(result)
        self._log_summary(result)
        return result

    # ------------------------------------------------------------------ #
    def _execute_levels(
        self,
        pipeline: PipelineSpec,
        graph: TaskGraph,
        context: ExecutionContext,
        result: PipelineResult,
        completed: set[str],
    ) -> None:
        """Run each level, honouring dependencies and failure policy."""
        skipped: set[str] = set()
        failed: set[str] = set()
        max_workers = max(1, min(pipeline.max_parallel_tasks, self.settings.max_parallel_tasks))

        for level in graph.levels:
            runnable = [name for name in level if name not in completed and name not in skipped]

            for name in level:
                if name in completed:
                    result.tasks.append(
                        TaskResult(
                            task_name=name, skipped_reason="completed in a previous attempt"
                        ).finish(RunStatus.SKIPPED)
                    )
                elif name in skipped:
                    result.tasks.append(
                        TaskResult(
                            task_name=name,
                            skipped_reason="an upstream task failed",
                        ).finish(RunStatus.SKIPPED)
                    )

            if not runnable:
                continue
            if context.cancellation.is_cancelled:
                raise PipelineError("run cancelled", context={"pipeline": pipeline.name})

            level_results = self._run_level(runnable, graph, context, max_workers)
            result.tasks.extend(level_results)

            for task_result in level_results:
                if task_result.status is RunStatus.SUCCESS:
                    self._checkpoint(context, task_result)
                    continue
                if task_result.status in (RunStatus.SKIPPED, RunStatus.CANCELLED):
                    continue

                failed.add(task_result.task_name)
                spec = graph.spec(task_result.task_name)
                downstream = graph.descendants(task_result.task_name)
                skipped |= downstream

                if spec.on_failure == "fail":
                    logger.error(
                        "task %r failed and on_failure=fail; abandoning %d downstream task(s)",
                        task_result.task_name,
                        len(downstream),
                    )
                    for name in sorted(downstream):
                        result.tasks.append(
                            TaskResult(
                                task_name=name, skipped_reason="an upstream task failed"
                            ).finish(RunStatus.SKIPPED)
                        )
                    raise PipelineError(
                        f"task {task_result.task_name!r} failed",
                        context={
                            "pipeline": pipeline.name,
                            "task": task_result.task_name,
                            "skipped": sorted(downstream),
                        },
                        cause=task_result.error,
                    )
                logger.warning(
                    "task %r failed but on_failure=continue; the run will be PARTIAL",
                    task_result.task_name,
                )

    def _run_level(
        self,
        names: list[str],
        graph: TaskGraph,
        context: ExecutionContext,
        max_workers: int,
    ) -> list[TaskResult]:
        """Execute one level, in parallel when it has more than one task."""
        if len(names) == 1:
            return [self._run_task(names[0], graph, context)]

        workers = min(len(names), max_workers)
        logger.info("running %d task(s) in parallel with %d worker(s)", len(names), workers)
        results: list[TaskResult] = []

        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ironflow-task") as pool:
            futures: dict[Future[TaskResult], str] = {
                pool.submit(self._run_task, name, graph, context): name for name in names
            }
            for future in futures:
                name = futures[future]
                try:
                    results.append(future.result())
                except Exception as exc:
                    logger.error("task %r raised out of its executor", name, exc_info=True)
                    results.append(TaskResult(task_name=name).finish(RunStatus.FAILED, exc))
        # Level order is not guaranteed by completion order; sort for stable output.
        results.sort(key=lambda r: names.index(r.task_name))
        return results

    def _run_task(self, name: str, graph: TaskGraph, context: ExecutionContext) -> TaskResult:
        spec = graph.spec(name)
        task_context = context.for_task(name)
        executor = TaskExecutor(
            spec,
            context.pipeline_id,
            factory=self.factory,
            watermarks=self.watermarks,
            schemas=self.schemas,
        )
        with task_context.bind():
            result = executor.execute(task_context)
        # Publish row counts for downstream conditions (``state.orders.rows_out``).
        context.state[name] = {
            "status": result.status.value,
            "rows_out": result.metrics.rows_out,
            "rows_in": result.metrics.rows_in,
        }
        return result

    # ------------------------------------------------------------------ #
    def _checkpoint(self, context: ExecutionContext, result: TaskResult) -> None:
        if self.checkpoints is None or context.dry_run:
            return
        if not self.settings.checkpoint_enabled:
            return
        try:
            self.checkpoints.save(
                execution_id=context.execution_id,
                pipeline=context.pipeline_id,
                task=result.task_name,
                status=RunStatus.SUCCESS,
                rows_processed=result.metrics.rows_out,
                last_batch=result.metrics.batches,
                payload={"watermark": result.watermark},
            )
            self.events.emit(
                EventType.CHECKPOINT_SAVED,
                pipeline_id=context.pipeline_id,
                execution_id=context.execution_id,
                task_id=result.task_name,
            )
        except IronFlowError:
            # A missing checkpoint costs a re-run, not correctness.
            logger.warning("unable to checkpoint task %r", result.task_name, exc_info=True)

    def _start_history(
        self,
        pipeline: PipelineSpec,
        context: ExecutionContext,
        graph: TaskGraph,
        trigger: str,
        principal: Principal | None,
    ) -> int | None:
        """Record the start of the run; returns the row id task rows attach to."""
        if self.runs is None:
            return None
        try:
            return self.runs.start_run(
                execution_id=context.execution_id,
                pipeline_name=pipeline.name,
                pipeline_version=pipeline.version,
                correlation_id=context.correlation_id,
                trigger=trigger,
                actor=principal.subject if principal else "system",
                parameters=context.parameters,
                tasks_total=graph.size,
                dry_run=context.dry_run,
            )
        except ConfigurationError:
            # The execution id is another pipeline's run. Unlike a history
            # outage this must stop the run: history is keyed by execution id,
            # so carrying on would write this run's outcome over that record.
            raise
        except IronFlowError:
            logger.warning("unable to record the start of this run", exc_info=True)
            return None

    def _finish_history(self, result: PipelineResult) -> None:
        if self.runs is None:
            return
        try:
            self.runs.finish_run(
                result.execution_id,
                status=result.status,
                duration_seconds=result.duration_seconds,
                rows_read=result.rows_read,
                rows_written=result.rows_written,
                rows_rejected=result.rows_rejected,
                tasks_succeeded=result.tasks_succeeded,
                tasks_failed=result.tasks_failed,
                error=result.error,
                metrics={"resources": result.resources},
            )
        except IronFlowError:
            logger.warning("unable to record the end of this run", exc_info=True)

    def _record_tasks(
        self, result: PipelineResult, run_id: int | None, *, carried_over: set[str]
    ) -> None:
        """Write the per-task rows that ``pipeline logs`` shows.

        Written after the run row is finished, so a failure here cannot leave
        the run marked RUNNING - the scheduler counts those against
        ``max_concurrent_runs``.  Rows take the run's attempt number, so after a
        resume each row says which attempt produced it; the task's own retries
        go into ``details``.  Tasks ``carried_over`` from an earlier attempt are
        not written again: the row from the attempt that ran them stands.
        """
        if self.runs is None or run_id is None:
            return
        for task in result.tasks:
            if task.task_name in carried_over:
                continue
            details: dict[str, Any] = {}
            if task.skipped_reason:
                details["skipped_reason"] = task.skipped_reason
            if task.attempt > 1:
                details["retries"] = task.attempt - 1
            try:
                self.runs.record_task(
                    run_id=run_id,
                    execution_id=result.execution_id,
                    task_name=task.task_name,
                    status=task.status,
                    started_at=task.started_at,
                    finished_at=task.finished_at,
                    duration_seconds=task.duration_seconds,
                    rows_read=task.metrics.rows_in,
                    rows_written=task.metrics.rows_out,
                    rows_rejected=task.metrics.rows_failed,
                    rows_skipped=task.metrics.rows_skipped,
                    batches=task.metrics.batches,
                    error=task.error,
                    details=details,
                )
            except IronFlowError:
                logger.warning(
                    "unable to record task %r in the run history", task.task_name, exc_info=True
                )

    def _emit_completion(self, result: PipelineResult) -> None:
        event = {
            RunStatus.SUCCESS: EventType.PIPELINE_SUCCEEDED,
            RunStatus.PARTIAL: EventType.PIPELINE_SUCCEEDED,
            RunStatus.CANCELLED: EventType.PIPELINE_CANCELLED,
        }.get(result.status, EventType.PIPELINE_FAILED)

        self.events.emit(
            event,
            pipeline_id=result.pipeline_name,
            execution_id=result.execution_id,
            status=result.status.value,
            duration=round(result.duration_seconds, 3),
            rows_written=result.rows_written,
            rows_rejected=result.rows_rejected,
            error=str(result.error)[:500] if result.error else None,
            summary=result.to_dict(include_tasks=False),
        )
        self.metrics.counter(
            Metric.PIPELINE_RUNS,
            labels={"pipeline": result.pipeline_name, "status": result.status.value},
            help="Pipeline runs by terminal status.",
        )
        self.metrics.observe(
            Metric.PIPELINE_DURATION,
            result.duration_seconds,
            labels={"pipeline": result.pipeline_name},
        )
        self.audit.record(
            "pipeline.finished",
            actor="system",
            outcome=result.status.value,
            resource=result.pipeline_name,
            correlation_id=result.correlation_id,
            execution_id=result.execution_id,
            rows_written=result.rows_written,
            duration_seconds=round(result.duration_seconds, 3),
        )

    def _log_summary(self, result: PipelineResult) -> None:
        level = logging.INFO if result.status is RunStatus.SUCCESS else logging.ERROR
        logger.log(
            level,
            "pipeline %r finished with status %s in %.2fs "
            "(%d read, %d written, %d rejected, %d/%d tasks succeeded)",
            result.pipeline_name,
            result.status.value,
            result.duration_seconds,
            result.rows_read,
            result.rows_written,
            result.rows_rejected,
            result.tasks_succeeded,
            len(result.tasks),
        )

    def _install_signal_handlers(self, context: ExecutionContext) -> Any:
        """Turn SIGINT/SIGTERM into cooperative cancellation.

        Only installable from the main thread; a scheduler thread simply skips
        this and relies on its own shutdown path.
        """
        if threading.current_thread() is not threading.main_thread():
            return None

        previous: dict[int, Any] = {}

        def handler(signum: int, _frame: FrameType | None) -> None:
            logger.warning("received signal %s; cancelling after the current batch", signum)
            context.cancellation.cancel(f"signal {signum}")

        for signum in (signal.SIGINT, getattr(signal, "SIGTERM", signal.SIGINT)):
            try:
                previous[signum] = signal.signal(signum, handler)
            except (ValueError, OSError):  # pragma: no cover - platform dependent
                continue

        def restore() -> None:
            for signum, original in previous.items():
                try:
                    signal.signal(signum, original)
                except (ValueError, OSError):  # pragma: no cover
                    continue

        return restore


__all__ = ["PipelineRunner"]
