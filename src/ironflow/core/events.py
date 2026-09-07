"""In-process event bus (Observer pattern).

Notifications, metrics scraping and the audit trail all want to react to
"pipeline started", "task failed", "rows quarantined" - but the runner must not
know about any of them.  The bus inverts that dependency: the runner publishes
facts, subscribers decide what to do with them.

Reliability rule: a subscriber that raises never breaks the run.  A failing
Slack webhook must not fail an otherwise healthy ETL job, so exceptions from
handlers are logged and swallowed.  The bus is thread-safe because parallel task
execution publishes from worker threads.
"""

from __future__ import annotations

import enum
import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from ironflow.core.context import utcnow

logger = logging.getLogger(__name__)


class EventType(str, enum.Enum):
    """Every fact the platform publishes."""

    PIPELINE_STARTED = "pipeline.started"
    PIPELINE_SUCCEEDED = "pipeline.succeeded"
    PIPELINE_FAILED = "pipeline.failed"
    PIPELINE_CANCELLED = "pipeline.cancelled"
    TASK_STARTED = "task.started"
    TASK_SUCCEEDED = "task.succeeded"
    TASK_FAILED = "task.failed"
    TASK_SKIPPED = "task.skipped"
    TASK_RETRYING = "task.retrying"
    BATCH_PROCESSED = "batch.processed"
    RECORDS_QUARANTINED = "records.quarantined"
    SCHEMA_DRIFT_DETECTED = "schema.drift"
    CHECKPOINT_SAVED = "checkpoint.saved"
    SECURITY_VIOLATION = "security.violation"


@dataclass(frozen=True, slots=True)
class Event:
    """An immutable fact emitted during a run."""

    type: EventType
    pipeline_id: str
    execution_id: str
    task_id: str = "-"
    timestamp: datetime = field(default_factory=utcnow)
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "pipeline_id": self.pipeline_id,
            "execution_id": self.execution_id,
            "task_id": self.task_id,
            "timestamp": self.timestamp.isoformat(),
            "payload": self.payload,
        }


Handler = Callable[[Event], None]


class EventBus:
    """Thread-safe synchronous publish/subscribe hub."""

    __slots__ = ("_global", "_history", "_history_limit", "_lock", "_subscribers")

    def __init__(self, history_limit: int = 500) -> None:
        self._subscribers: dict[EventType, list[Handler]] = {}
        self._global: list[Handler] = []
        self._lock = threading.RLock()
        self._history: list[Event] = []
        self._history_limit = max(0, history_limit)

    def subscribe(self, event_type: EventType | None, handler: Handler) -> Callable[[], None]:
        """Register ``handler``; ``event_type=None`` subscribes to everything.

        Returns an unsubscribe callable so tests and short-lived services can
        detach cleanly instead of leaking handlers.
        """
        with self._lock:
            bucket = (
                self._global if event_type is None else self._subscribers.setdefault(event_type, [])
            )
            bucket.append(handler)

        def unsubscribe() -> None:
            with self._lock:
                target = (
                    self._global if event_type is None else self._subscribers.get(event_type, [])
                )
                if handler in target:
                    target.remove(handler)

        return unsubscribe

    def publish(self, event: Event) -> None:
        """Deliver ``event`` to every matching subscriber."""
        with self._lock:
            handlers = [*self._subscribers.get(event.type, []), *self._global]
            if self._history_limit:
                self._history.append(event)
                if len(self._history) > self._history_limit:
                    del self._history[: len(self._history) - self._history_limit]

        for handler in handlers:
            try:
                handler(event)
            except Exception:
                logger.exception("event subscriber failed", extra={"event_type": event.type.value})

    def emit(
        self,
        event_type: EventType,
        *,
        pipeline_id: str,
        execution_id: str,
        task_id: str = "-",
        **payload: Any,
    ) -> Event:
        """Convenience constructor + publish."""
        event = Event(
            type=event_type,
            pipeline_id=pipeline_id,
            execution_id=execution_id,
            task_id=task_id,
            payload=payload,
        )
        self.publish(event)
        return event

    def history(self, event_type: EventType | None = None, limit: int = 100) -> list[Event]:
        """Recent events - powers the dashboard's activity feed."""
        with self._lock:
            events = [e for e in self._history if event_type is None or e.type is event_type]
        return events[-limit:]

    def clear(self) -> None:
        with self._lock:
            self._history.clear()


__all__ = ["Event", "EventBus", "EventType", "Handler"]
