"""ORM models for the platform's own state.

These tables are IronFlow's control plane, not the data it moves:

``pipeline_runs`` / ``task_runs``
    Execution history.  Answers "did last night's load run, how long did it
    take, and how many rows?" without grepping logs.
``watermarks``
    High-water marks for incremental extraction, keyed by pipeline+task+source.
``checkpoints``
    Progress within a run, so a failed pipeline resumes at the failed task
    instead of re-running the six that succeeded.
``schema_snapshots``
    The last observed schema per source, which is what schema-drift detection
    compares against.
``kv_state``
    Generic key/value scratch space (CDC cursors, scheduler bookkeeping).

Indexes are declared explicitly: the two hot queries are "latest runs for
pipeline X" and "runs in status Y", and both would otherwise become a full scan
once the table has a year of history in it.

JSON payloads are stored as ``Text`` with explicit serialisation rather than a
native JSON column, because the platform must run on SQLite (local/CI) and
PostgreSQL (production) from the same schema.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from ironflow.core.context import utcnow
from ironflow.core.types import RunStatus


class Base(DeclarativeBase):
    """Declarative base for every control-plane table."""


def _dumps(value: Any) -> str:
    return json.dumps(value, default=str, ensure_ascii=False)


def _loads(value: str | None) -> Any:
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:  # pragma: no cover - defensive
        return None


class PipelineRun(Base):
    """One execution of a pipeline."""

    __tablename__ = "pipeline_runs"
    __table_args__ = (
        Index("ix_pipeline_runs_pipeline_started", "pipeline_name", "started_at"),
        Index("ix_pipeline_runs_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    execution_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    pipeline_name: Mapped[str] = mapped_column(String(128), index=True)
    pipeline_version: Mapped[str] = mapped_column(String(32), default="1")
    correlation_id: Mapped[str] = mapped_column(String(64), default="")
    status: Mapped[str] = mapped_column(String(16), default=RunStatus.PENDING.value)
    trigger: Mapped[str] = mapped_column(String(32), default="manual")
    actor: Mapped[str] = mapped_column(String(128), default="system")
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    """Incremented by ``pipeline resume``, which re-enters the same execution."""

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)

    rows_read: Mapped[int] = mapped_column(Integer, default=0)
    rows_written: Mapped[int] = mapped_column(Integer, default=0)
    rows_rejected: Mapped[int] = mapped_column(Integer, default=0)
    tasks_total: Mapped[int] = mapped_column(Integer, default=0)
    tasks_succeeded: Mapped[int] = mapped_column(Integer, default=0)
    tasks_failed: Mapped[int] = mapped_column(Integer, default=0)

    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    parameters_json: Mapped[str] = mapped_column(Text, default="{}")
    metrics_json: Mapped[str] = mapped_column(Text, default="{}")
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)

    tasks: Mapped[list[TaskRun]] = relationship(
        back_populates="run", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def parameters(self) -> dict[str, Any]:
        return _loads(self.parameters_json) or {}

    @parameters.setter
    def parameters(self, value: dict[str, Any]) -> None:
        self.parameters_json = _dumps(value)

    @property
    def metrics(self) -> dict[str, Any]:
        return _loads(self.metrics_json) or {}

    @metrics.setter
    def metrics(self, value: dict[str, Any]) -> None:
        self.metrics_json = _dumps(value)

    @property
    def success_rate(self) -> float:
        return self.tasks_succeeded / self.tasks_total if self.tasks_total else 0.0

    def to_dict(self, *, include_tasks: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "execution_id": self.execution_id,
            "pipeline": self.pipeline_name,
            "version": self.pipeline_version,
            "status": self.status,
            "trigger": self.trigger,
            "actor": self.actor,
            "attempt": self.attempt,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": round(self.duration_seconds, 3),
            "rows_read": self.rows_read,
            "rows_written": self.rows_written,
            "rows_rejected": self.rows_rejected,
            "tasks": {
                "total": self.tasks_total,
                "succeeded": self.tasks_succeeded,
                "failed": self.tasks_failed,
            },
            "error": (
                {"code": self.error_code, "message": self.error_message}
                if self.error_message
                else None
            ),
            "dry_run": self.dry_run,
        }
        if include_tasks:
            payload["task_runs"] = [task.to_dict() for task in self.tasks]
        return payload


class TaskRun(Base):
    """One execution of a task inside a pipeline run."""

    __tablename__ = "task_runs"
    __table_args__ = (
        Index("ix_task_runs_execution_task", "execution_id", "task_name"),
        Index("ix_task_runs_status", "status"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("pipeline_runs.id", ondelete="CASCADE"))
    execution_id: Mapped[str] = mapped_column(String(64), index=True)
    task_name: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default=RunStatus.PENDING.value)
    attempt: Mapped[int] = mapped_column(Integer, default=1)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[float] = mapped_column(Float, default=0.0)

    rows_read: Mapped[int] = mapped_column(Integer, default=0)
    rows_written: Mapped[int] = mapped_column(Integer, default=0)
    rows_rejected: Mapped[int] = mapped_column(Integer, default=0)
    rows_skipped: Mapped[int] = mapped_column(Integer, default=0)
    batches: Mapped[int] = mapped_column(Integer, default=0)

    error_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    details_json: Mapped[str] = mapped_column(Text, default="{}")

    run: Mapped[PipelineRun] = relationship(back_populates="tasks")

    @property
    def details(self) -> dict[str, Any]:
        return _loads(self.details_json) or {}

    @details.setter
    def details(self, value: dict[str, Any]) -> None:
        self.details_json = _dumps(value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "task": self.task_name,
            "status": self.status,
            "attempt": self.attempt,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "duration_seconds": round(self.duration_seconds, 3),
            "rows_read": self.rows_read,
            "rows_written": self.rows_written,
            "rows_rejected": self.rows_rejected,
            "rows_skipped": self.rows_skipped,
            "batches": self.batches,
            "error": (
                {"code": self.error_code, "message": self.error_message}
                if self.error_message
                else None
            ),
            "details": self.details,
        }


class Watermark(Base):
    """High-water mark for an incremental extraction."""

    __tablename__ = "watermarks"
    __table_args__ = (
        UniqueConstraint("pipeline_name", "task_name", "source_key", name="uq_watermark_scope"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    pipeline_name: Mapped[str] = mapped_column(String(128), index=True)
    task_name: Mapped[str] = mapped_column(String(128))
    source_key: Mapped[str] = mapped_column(String(256), default="default")
    column_name: Mapped[str] = mapped_column(String(128))
    value_json: Mapped[str] = mapped_column(Text, default="null")
    rows_last_run: Mapped[int] = mapped_column(Integer, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )
    execution_id: Mapped[str] = mapped_column(String(64), default="")

    @property
    def value(self) -> Any:
        return _loads(self.value_json)

    @value.setter
    def value(self, new_value: Any) -> None:
        self.value_json = _dumps(new_value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "pipeline": self.pipeline_name,
            "task": self.task_name,
            "source_key": self.source_key,
            "column": self.column_name,
            "value": self.value,
            "rows_last_run": self.rows_last_run,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Checkpoint(Base):
    """Progress marker within a run, used by ``pipeline resume``."""

    __tablename__ = "checkpoints"
    __table_args__ = (
        UniqueConstraint("execution_id", "task_name", name="uq_checkpoint_scope"),
        Index("ix_checkpoints_pipeline", "pipeline_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    execution_id: Mapped[str] = mapped_column(String(64), index=True)
    pipeline_name: Mapped[str] = mapped_column(String(128))
    task_name: Mapped[str] = mapped_column(String(128))
    status: Mapped[str] = mapped_column(String(16), default=RunStatus.SUCCESS.value)
    rows_processed: Mapped[int] = mapped_column(Integer, default=0)
    last_batch: Mapped[int] = mapped_column(Integer, default=0)
    payload_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    @property
    def payload(self) -> dict[str, Any]:
        return _loads(self.payload_json) or {}

    @payload.setter
    def payload(self, value: dict[str, Any]) -> None:
        self.payload_json = _dumps(value)

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "pipeline": self.pipeline_name,
            "task": self.task_name,
            "status": self.status,
            "rows_processed": self.rows_processed,
            "last_batch": self.last_batch,
            "payload": self.payload,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class SchemaSnapshot(Base):
    """Last observed schema for a source, for drift detection."""

    __tablename__ = "schema_snapshots"
    __table_args__ = (
        UniqueConstraint("pipeline_name", "task_name", "source_key", name="uq_schema_scope"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    pipeline_name: Mapped[str] = mapped_column(String(128), index=True)
    task_name: Mapped[str] = mapped_column(String(128))
    source_key: Mapped[str] = mapped_column(String(256), default="default")
    fingerprint: Mapped[str] = mapped_column(String(64), default="")
    schema_json: Mapped[str] = mapped_column(Text, default="{}")
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    @property
    def schema(self) -> dict[str, Any]:
        return _loads(self.schema_json) or {}

    @schema.setter
    def schema(self, value: dict[str, Any]) -> None:
        self.schema_json = _dumps(value)


class KeyValue(Base):
    """Generic namespaced key/value state."""

    __tablename__ = "kv_state"
    __table_args__ = (UniqueConstraint("namespace", "key", name="uq_kv_scope"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    namespace: Mapped[str] = mapped_column(String(128), index=True)
    key: Mapped[str] = mapped_column(String(256))
    value_json: Mapped[str] = mapped_column(Text, default="null")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )

    @property
    def value(self) -> Any:
        return _loads(self.value_json)

    @value.setter
    def value(self, new_value: Any) -> None:
        self.value_json = _dumps(new_value)


__all__ = [
    "Base",
    "Checkpoint",
    "KeyValue",
    "PipelineRun",
    "SchemaSnapshot",
    "TaskRun",
    "Watermark",
]
