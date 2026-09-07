"""Result objects returned by the task executor and the pipeline runner.

They are plain dataclasses rather than ORM rows so that a run can be executed,
inspected and asserted on without a database - which is what makes the
end-to-end tests fast and the library usable as an embedded component.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ironflow.core.context import utcnow
from ironflow.core.types import RunStatus, StageMetrics


@dataclass(slots=True)
class TaskResult:
    """Outcome of a single task."""

    task_name: str
    status: RunStatus = RunStatus.PENDING
    attempt: int = 1
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None
    metrics: StageMetrics = field(default_factory=StageMetrics)
    error: Exception | None = None
    skipped_reason: str | None = None
    validation: dict[str, Any] = field(default_factory=dict)
    transformations: list[dict[str, Any]] = field(default_factory=list)
    schema_drift: dict[str, Any] | None = None
    watermark: Any = None

    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or utcnow()
        return (end - self.started_at).total_seconds()

    @property
    def succeeded(self) -> bool:
        return self.status is RunStatus.SUCCESS

    def finish(self, status: RunStatus, error: Exception | None = None) -> TaskResult:
        self.status = status
        self.error = error
        self.finished_at = utcnow()
        self.metrics.duration_seconds = self.duration_seconds
        return self

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "task": self.task_name,
            "status": self.status.value,
            "attempt": self.attempt,
            "duration_seconds": round(self.duration_seconds, 3),
            "metrics": self.metrics.to_dict(),
        }
        if self.skipped_reason:
            payload["skipped_reason"] = self.skipped_reason
        if self.validation:
            payload["validation"] = self.validation
        if self.transformations:
            payload["transformations"] = self.transformations
        if self.schema_drift:
            payload["schema_drift"] = self.schema_drift
        if self.watermark is not None:
            payload["watermark"] = self.watermark
        if self.error is not None:
            payload["error"] = _error_payload(self.error)
        return payload


@dataclass(slots=True)
class PipelineResult:
    """Outcome of a whole pipeline run."""

    pipeline_name: str
    execution_id: str
    correlation_id: str = ""
    status: RunStatus = RunStatus.PENDING
    started_at: datetime = field(default_factory=utcnow)
    finished_at: datetime | None = None
    tasks: list[TaskResult] = field(default_factory=list)
    error: Exception | None = None
    dry_run: bool = False
    parameters: dict[str, Any] = field(default_factory=dict)
    resources: dict[str, Any] = field(default_factory=dict)
    metrics_snapshot: dict[str, Any] = field(default_factory=dict)

    # -- aggregates -------------------------------------------------------- #
    @property
    def duration_seconds(self) -> float:
        end = self.finished_at or utcnow()
        return (end - self.started_at).total_seconds()

    @property
    def rows_read(self) -> int:
        return sum(t.metrics.rows_in for t in self.tasks)

    @property
    def rows_written(self) -> int:
        return sum(t.metrics.rows_out for t in self.tasks)

    @property
    def rows_rejected(self) -> int:
        return sum(t.metrics.rows_failed for t in self.tasks)

    @property
    def rows_skipped(self) -> int:
        return sum(t.metrics.rows_skipped for t in self.tasks)

    @property
    def tasks_succeeded(self) -> int:
        return sum(1 for t in self.tasks if t.status is RunStatus.SUCCESS)

    @property
    def tasks_failed(self) -> int:
        return sum(1 for t in self.tasks if t.status is RunStatus.FAILED)

    @property
    def tasks_skipped(self) -> int:
        return sum(1 for t in self.tasks if t.status is RunStatus.SKIPPED)

    @property
    def succeeded(self) -> bool:
        return self.status is RunStatus.SUCCESS

    @property
    def throughput_rows_per_second(self) -> float:
        duration = self.duration_seconds
        return round(self.rows_written / duration, 2) if duration > 0 else 0.0

    def task(self, name: str) -> TaskResult | None:
        return next((t for t in self.tasks if t.task_name == name), None)

    def finish(self, status: RunStatus, error: Exception | None = None) -> PipelineResult:
        self.status = status
        self.error = error
        self.finished_at = utcnow()
        return self

    def derive_status(self) -> RunStatus:
        """Compute the overall status from the task outcomes.

        ``PARTIAL`` exists for the ``on_failure: continue`` case: some tasks
        failed but the run still produced output.  Collapsing that into SUCCESS
        would hide a real problem; collapsing it into FAILED would trigger a
        pointless full re-run.
        """
        if not self.tasks:
            return RunStatus.SUCCESS
        if self.tasks_failed == 0:
            return RunStatus.SUCCESS
        if self.tasks_succeeded > 0:
            return RunStatus.PARTIAL
        return RunStatus.FAILED

    def to_dict(self, *, include_tasks: bool = True) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "pipeline": self.pipeline_name,
            "execution_id": self.execution_id,
            "correlation_id": self.correlation_id,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": round(self.duration_seconds, 3),
            "dry_run": self.dry_run,
            "rows": {
                "read": self.rows_read,
                "written": self.rows_written,
                "rejected": self.rows_rejected,
                "skipped": self.rows_skipped,
            },
            "tasks_summary": {
                "total": len(self.tasks),
                "succeeded": self.tasks_succeeded,
                "failed": self.tasks_failed,
                "skipped": self.tasks_skipped,
            },
            "throughput_rows_per_second": self.throughput_rows_per_second,
        }
        if self.resources:
            payload["resources"] = self.resources
        if include_tasks:
            payload["tasks"] = [task.to_dict() for task in self.tasks]
        if self.error is not None:
            payload["error"] = _error_payload(self.error)
        return payload


def _error_payload(error: Exception) -> dict[str, Any]:
    from ironflow.core.errors import IronFlowError

    if isinstance(error, IronFlowError):
        return error.to_dict()
    return {"error": type(error).__name__, "code": "UNEXPECTED", "message": str(error)[:1000]}


__all__ = ["PipelineResult", "TaskResult"]
