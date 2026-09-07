"""Execution context propagated through every stage of a run.

The context is the single object that carries identity, correlation ids,
cancellation state and shared services (metrics, event bus, secret resolver)
down the call chain.  Passing it explicitly rather than reaching for globals
keeps the stages unit-testable and makes concurrent pipeline runs safe.

Correlation ids are also mirrored into :mod:`contextvars` so that the logging
layer can stamp them onto records emitted by code that does not receive the
context object (third-party libraries, for instance).
"""

from __future__ import annotations

import contextvars
import threading
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - import cycle avoidance
    from ironflow.core.events import EventBus
    from ironflow.observability.metrics import MetricsRegistry
    from ironflow.security.rbac import Principal

# Mirrored into log records by ``ContextFilter``.
correlation_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "ironflow_correlation_id", default="-"
)
execution_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "ironflow_execution_id", default="-"
)
pipeline_id_var: contextvars.ContextVar[str] = contextvars.ContextVar(
    "ironflow_pipeline_id", default="-"
)
task_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("ironflow_task_id", default="-")


def new_id(prefix: str = "") -> str:
    """Return a short, collision-resistant identifier."""
    token = uuid.uuid4().hex[:16]
    return f"{prefix}{token}" if prefix else token


def utcnow() -> datetime:
    """Timezone-aware UTC timestamp.

    Every timestamp in the system is tz-aware UTC; naive datetimes are treated
    as a bug because they silently break duration maths across DST boundaries.
    """
    return datetime.now(UTC)


class CancellationToken:
    """Cooperative cancellation shared between the runner and its workers.

    Threads check :meth:`raise_if_cancelled` between batches.  This keeps
    shutdown deterministic - a batch in flight always finishes, so partially
    written transactional loads are never left half-committed.
    """

    __slots__ = ("_event", "_reason")

    def __init__(self) -> None:
        self._event = threading.Event()
        self._reason: str | None = None

    @property
    def is_cancelled(self) -> bool:
        return self._event.is_set()

    @property
    def reason(self) -> str | None:
        return self._reason

    def cancel(self, reason: str = "cancelled by operator") -> None:
        self._reason = reason
        self._event.set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)

    def raise_if_cancelled(self) -> None:
        if self._event.is_set():
            from ironflow.core.errors import PipelineError

            raise PipelineError(
                self._reason or "execution cancelled",
                context={"cancelled": True},
            )


@dataclass(slots=True)
class ExecutionContext:
    """Immutable-ish carrier of run identity and shared services."""

    pipeline_id: str
    execution_id: str = field(default_factory=lambda: new_id("exec_"))
    correlation_id: str = field(default_factory=lambda: new_id("corr_"))
    task_id: str = "-"
    started_at: datetime = field(default_factory=utcnow)
    dry_run: bool = False
    parameters: dict[str, Any] = field(default_factory=dict)
    principal: Principal | None = None
    metrics: MetricsRegistry | None = None
    events: EventBus | None = None
    cancellation: CancellationToken = field(default_factory=CancellationToken)
    state: dict[str, Any] = field(default_factory=dict)
    """Free-form scratch space shared between tasks of one run (XCom-like)."""

    def for_task(self, task_id: str) -> ExecutionContext:
        """Derive a child context scoped to a task.

        ``state`` and the cancellation token are shared by reference so a task
        can publish values for its downstream dependents and so cancelling the
        run cancels every task.
        """
        return ExecutionContext(
            pipeline_id=self.pipeline_id,
            execution_id=self.execution_id,
            correlation_id=self.correlation_id,
            task_id=task_id,
            started_at=utcnow(),
            dry_run=self.dry_run,
            parameters=self.parameters,
            principal=self.principal,
            metrics=self.metrics,
            events=self.events,
            cancellation=self.cancellation,
            state=self.state,
        )

    @property
    def elapsed_seconds(self) -> float:
        return (utcnow() - self.started_at).total_seconds()

    def log_fields(self) -> dict[str, str]:
        """Identity fields injected into every structured log record."""
        return {
            "pipeline_id": self.pipeline_id,
            "execution_id": self.execution_id,
            "correlation_id": self.correlation_id,
            "task_id": self.task_id,
        }

    @contextmanager
    def bind(self) -> Iterator[ExecutionContext]:
        """Bind the identity fields to context vars for the enclosed block."""
        tokens = (
            correlation_id_var.set(self.correlation_id),
            execution_id_var.set(self.execution_id),
            pipeline_id_var.set(self.pipeline_id),
            task_id_var.set(self.task_id),
        )
        try:
            yield self
        finally:
            correlation_id_var.reset(tokens[0])
            execution_id_var.reset(tokens[1])
            pipeline_id_var.reset(tokens[2])
            task_id_var.reset(tokens[3])


def current_log_context() -> dict[str, str]:
    """Read the currently bound identity fields (used by the log filter)."""
    return {
        "correlation_id": correlation_id_var.get(),
        "execution_id": execution_id_var.get(),
        "pipeline_id": pipeline_id_var.get(),
        "task_id": task_id_var.get(),
    }


__all__ = [
    "CancellationToken",
    "ExecutionContext",
    "current_log_context",
    "new_id",
    "utcnow",
]
