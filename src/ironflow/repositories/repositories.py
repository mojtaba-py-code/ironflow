"""Repository layer - all state-database access lives behind these classes.

The rest of the platform never issues a query.  It asks a repository, which
means SQLAlchemy is confined to one package and can be swapped, and it means a
unit test can substitute an in-memory fake without a database at all.

Every method opens its own short transaction rather than holding one across a
pipeline run: a run can last hours, and an open transaction that long pins the
database's oldest snapshot and blocks vacuum on PostgreSQL.
"""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Sequence
from datetime import timedelta
from typing import Any, cast

from sqlalchemy import delete, func, select
from sqlalchemy.engine import CursorResult, Result
from sqlalchemy.exc import SQLAlchemyError

from ironflow.core.context import utcnow
from ironflow.core.errors import CheckpointError, IronFlowError
from ironflow.core.types import DatasetSchema, RunStatus, SchemaDiff
from ironflow.repositories.database import Database, get_database
from ironflow.repositories.models import (
    Checkpoint,
    KeyValue,
    PipelineRun,
    SchemaSnapshot,
    TaskRun,
    Watermark,
)

logger = logging.getLogger(__name__)


def _rowcount(result: Result[Any]) -> int:
    """Number of rows a DML statement touched.

    ``rowcount`` lives on ``CursorResult``, but ``Session.execute`` is typed as
    returning the ``Result`` base class, so the attribute is invisible to the
    type checker.  A DELETE always yields a ``CursorResult`` at run time; the
    cast records that fact in one place instead of at every call site.
    """
    return int(cast("CursorResult[Any]", result).rowcount or 0)


class BaseRepository:
    """Holds the database handle."""

    def __init__(self, database: Database | None = None) -> None:
        self.db = database or get_database()


class RunRepository(BaseRepository):
    """Execution history for pipelines and tasks."""

    # -- writes ------------------------------------------------------------ #
    def start_run(
        self,
        *,
        execution_id: str,
        pipeline_name: str,
        pipeline_version: str = "1",
        correlation_id: str = "",
        trigger: str = "manual",
        actor: str = "system",
        parameters: dict[str, Any] | None = None,
        tasks_total: int = 0,
        dry_run: bool = False,
    ) -> int:
        """Upsert a RUNNING row and return its primary key.

        Upsert rather than insert because ``pipeline resume`` re-enters an
        existing ``execution_id``; a plain insert violated the unique constraint
        and made resume impossible.  The existing row is reused and ``attempt``
        incremented, so history keeps one row per logical execution and still
        records that it was retried.
        """
        with self.db.session() as session:
            run = session.scalar(
                select(PipelineRun).where(PipelineRun.execution_id == execution_id)
            )
            if run is None:
                run = PipelineRun(
                    execution_id=execution_id,
                    pipeline_name=pipeline_name,
                    started_at=utcnow(),
                )
                session.add(run)
            else:
                run.attempt += 1
                # Clear the previous attempt's outcome so a resumed run that
                # succeeds does not keep showing the old failure.
                run.error_code = None
                run.error_message = None
                run.finished_at = None

            run.pipeline_version = pipeline_version
            run.correlation_id = correlation_id
            run.status = RunStatus.RUNNING.value
            run.trigger = trigger
            run.actor = actor
            run.tasks_total = tasks_total
            run.dry_run = dry_run
            run.parameters = parameters or {}
            session.flush()
            return int(run.id)

    def finish_run(
        self,
        execution_id: str,
        *,
        status: RunStatus,
        duration_seconds: float,
        rows_read: int = 0,
        rows_written: int = 0,
        rows_rejected: int = 0,
        tasks_succeeded: int = 0,
        tasks_failed: int = 0,
        error: IronFlowError | Exception | None = None,
        metrics: dict[str, Any] | None = None,
    ) -> None:
        with self.db.session() as session:
            run = session.scalar(
                select(PipelineRun).where(PipelineRun.execution_id == execution_id)
            )
            if run is None:
                logger.warning("finish_run called for unknown execution %s", execution_id)
                return
            run.status = status.value
            run.finished_at = utcnow()
            run.duration_seconds = duration_seconds
            run.rows_read = rows_read
            run.rows_written = rows_written
            run.rows_rejected = rows_rejected
            run.tasks_succeeded = tasks_succeeded
            run.tasks_failed = tasks_failed
            run.metrics = metrics or {}
            if error is not None:
                run.error_code = getattr(error, "code", type(error).__name__)
                # Bounded: a stack-trace-laden message must not bloat the row.
                run.error_message = str(error)[:4000]

    def record_task(
        self,
        *,
        run_id: int,
        execution_id: str,
        task_name: str,
        status: RunStatus,
        attempt: int = 1,
        duration_seconds: float = 0.0,
        rows_read: int = 0,
        rows_written: int = 0,
        rows_rejected: int = 0,
        rows_skipped: int = 0,
        batches: int = 0,
        error: Exception | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        with self.db.session() as session:
            task = TaskRun(
                run_id=run_id,
                execution_id=execution_id,
                task_name=task_name,
                status=status.value,
                attempt=attempt,
                started_at=utcnow() - timedelta(seconds=duration_seconds),
                finished_at=utcnow(),
                duration_seconds=duration_seconds,
                rows_read=rows_read,
                rows_written=rows_written,
                rows_rejected=rows_rejected,
                rows_skipped=rows_skipped,
                batches=batches,
            )
            if error is not None:
                task.error_code = getattr(error, "code", type(error).__name__)
                task.error_message = str(error)[:4000]
            task.details = details or {}
            session.add(task)

    # -- reads ------------------------------------------------------------- #
    def get_run(self, execution_id: str) -> dict[str, Any] | None:
        with self.db.session() as session:
            run = session.scalar(
                select(PipelineRun).where(PipelineRun.execution_id == execution_id)
            )
            return run.to_dict(include_tasks=True) if run else None

    def list_runs(
        self,
        *,
        pipeline_name: str | None = None,
        status: RunStatus | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        with self.db.session() as session:
            statement = select(PipelineRun).order_by(PipelineRun.started_at.desc())
            if pipeline_name:
                statement = statement.where(PipelineRun.pipeline_name == pipeline_name)
            if status:
                statement = statement.where(PipelineRun.status == status.value)
            statement = statement.limit(min(limit, 500)).offset(max(0, offset))
            return [run.to_dict() for run in session.scalars(statement)]

    def latest_run(self, pipeline_name: str) -> dict[str, Any] | None:
        runs = self.list_runs(pipeline_name=pipeline_name, limit=1)
        return runs[0] if runs else None

    def last_failed_run(self, pipeline_name: str) -> dict[str, Any] | None:
        with self.db.session() as session:
            run = session.scalar(
                select(PipelineRun)
                .where(
                    PipelineRun.pipeline_name == pipeline_name,
                    PipelineRun.status.in_([RunStatus.FAILED.value, RunStatus.PARTIAL.value]),
                )
                .order_by(PipelineRun.started_at.desc())
                .limit(1)
            )
            return run.to_dict(include_tasks=True) if run else None

    def running_count(self, pipeline_name: str) -> int:
        """Used by the scheduler to enforce ``max_concurrent_runs``."""
        with self.db.session() as session:
            return int(
                session.scalar(
                    select(func.count())
                    .select_from(PipelineRun)
                    .where(
                        PipelineRun.pipeline_name == pipeline_name,
                        PipelineRun.status == RunStatus.RUNNING.value,
                    )
                )
                or 0
            )

    def statistics(self, pipeline_name: str | None = None, *, days: int = 30) -> dict[str, Any]:
        """Aggregate KPIs for the dashboard and ``ironflow report``."""
        since = utcnow() - timedelta(days=max(1, days))
        with self.db.session() as session:
            base = select(PipelineRun).where(PipelineRun.started_at >= since)
            if pipeline_name:
                base = base.where(PipelineRun.pipeline_name == pipeline_name)
            runs = list(session.scalars(base))

        total = len(runs)
        succeeded = sum(1 for r in runs if r.status == RunStatus.SUCCESS.value)
        failed = sum(1 for r in runs if r.status == RunStatus.FAILED.value)
        durations = sorted(r.duration_seconds for r in runs if r.duration_seconds)
        rows_written = sum(r.rows_written for r in runs)

        return {
            "window_days": days,
            "pipeline": pipeline_name,
            "runs_total": total,
            "runs_succeeded": succeeded,
            "runs_failed": failed,
            "success_rate": round(succeeded / total, 4) if total else 0.0,
            "failure_rate": round(failed / total, 4) if total else 0.0,
            "rows_written": rows_written,
            "rows_read": sum(r.rows_read for r in runs),
            "rows_rejected": sum(r.rows_rejected for r in runs),
            "avg_duration_seconds": (
                round(sum(durations) / len(durations), 3) if durations else 0.0
            ),
            "p95_duration_seconds": (
                round(durations[min(len(durations) - 1, int(len(durations) * 0.95))], 3)
                if durations
                else 0.0
            ),
            "max_duration_seconds": round(durations[-1], 3) if durations else 0.0,
        }

    def timeline(self, *, limit: int = 100) -> list[dict[str, Any]]:
        """Recent runs across all pipelines, for the execution-timeline chart."""
        with self.db.session() as session:
            statement = (
                select(PipelineRun).order_by(PipelineRun.started_at.desc()).limit(min(limit, 500))
            )
            return [
                {
                    "pipeline": run.pipeline_name,
                    "execution_id": run.execution_id,
                    "status": run.status,
                    "started_at": run.started_at.isoformat() if run.started_at else None,
                    "duration_seconds": round(run.duration_seconds, 3),
                    "rows_written": run.rows_written,
                }
                for run in session.scalars(statement)
            ]

    def purge(self, *, older_than_days: int = 90) -> int:
        """Delete history older than the retention window; returns rows removed."""
        cutoff = utcnow() - timedelta(days=max(1, older_than_days))
        with self.db.session() as session:
            ids = list(
                session.scalars(select(PipelineRun.id).where(PipelineRun.started_at < cutoff))
            )
            if not ids:
                return 0
            session.execute(delete(TaskRun).where(TaskRun.run_id.in_(ids)))
            session.execute(delete(PipelineRun).where(PipelineRun.id.in_(ids)))
            logger.info("purged %d pipeline run(s) older than %d days", len(ids), older_than_days)
            return len(ids)


class WatermarkRepository(BaseRepository):
    """High-water marks for incremental extraction."""

    def get(self, pipeline: str, task: str, source_key: str = "default") -> Any:
        with self.db.session() as session:
            row = session.scalar(
                select(Watermark).where(
                    Watermark.pipeline_name == pipeline,
                    Watermark.task_name == task,
                    Watermark.source_key == source_key,
                )
            )
            return row.value if row else None

    def set(
        self,
        pipeline: str,
        task: str,
        *,
        column: str,
        value: Any,
        source_key: str = "default",
        rows: int = 0,
        execution_id: str = "",
    ) -> None:
        """Upsert the watermark.

        Only ever moves forward: a run that read fewer rows than the previous
        one must not rewind the mark and cause a re-load.
        """
        with self.db.session() as session:
            row = session.scalar(
                select(Watermark).where(
                    Watermark.pipeline_name == pipeline,
                    Watermark.task_name == task,
                    Watermark.source_key == source_key,
                )
            )
            if row is None:
                row = Watermark(
                    pipeline_name=pipeline,
                    task_name=task,
                    source_key=source_key,
                    column_name=column,
                )
                session.add(row)
            elif not _is_greater(value, row.value):
                logger.debug(
                    "watermark for %s/%s not advanced (new=%r, current=%r)",
                    pipeline,
                    task,
                    value,
                    row.value,
                )
                row.rows_last_run = rows
                row.execution_id = execution_id
                return
            row.column_name = column
            row.value = value
            row.rows_last_run = rows
            row.execution_id = execution_id
            row.updated_at = utcnow()

    def reset(self, pipeline: str, task: str | None = None) -> int:
        """Clear watermarks so the next run performs a full load."""
        with self.db.session() as session:
            statement = delete(Watermark).where(Watermark.pipeline_name == pipeline)
            if task:
                statement = statement.where(Watermark.task_name == task)
            result = session.execute(statement)
            return _rowcount(result)

    def list(self, pipeline: str | None = None) -> list[dict[str, Any]]:
        with self.db.session() as session:
            statement = select(Watermark).order_by(Watermark.pipeline_name, Watermark.task_name)
            if pipeline:
                statement = statement.where(Watermark.pipeline_name == pipeline)
            return [row.to_dict() for row in session.scalars(statement)]


def _is_greater(new_value: Any, current: Any) -> bool:
    """Compare watermark values across the types they actually take."""
    if current is None:
        return True
    if new_value is None:
        return False
    try:
        return bool(new_value > current)
    except TypeError:
        return str(new_value) > str(current)


class CheckpointRepository(BaseRepository):
    """Per-task progress markers powering ``pipeline resume``."""

    def save(
        self,
        *,
        execution_id: str,
        pipeline: str,
        task: str,
        status: RunStatus = RunStatus.SUCCESS,
        rows_processed: int = 0,
        last_batch: int = 0,
        payload: dict[str, Any] | None = None,
    ) -> None:
        try:
            with self.db.session() as session:
                row = session.scalar(
                    select(Checkpoint).where(
                        Checkpoint.execution_id == execution_id,
                        Checkpoint.task_name == task,
                    )
                )
                if row is None:
                    row = Checkpoint(
                        execution_id=execution_id, pipeline_name=pipeline, task_name=task
                    )
                    session.add(row)
                row.status = status.value
                row.rows_processed = rows_processed
                row.last_batch = last_batch
                row.payload = payload or {}
                row.created_at = utcnow()
        except SQLAlchemyError as exc:
            raise CheckpointError(
                "unable to save checkpoint",
                context={"execution_id": execution_id, "task": task},
                cause=exc,
            ) from exc

    def completed_tasks(self, execution_id: str) -> set[str]:
        """Tasks already finished successfully in a previous attempt."""
        with self.db.session() as session:
            rows = session.scalars(
                select(Checkpoint).where(
                    Checkpoint.execution_id == execution_id,
                    Checkpoint.status == RunStatus.SUCCESS.value,
                )
            )
            return {row.task_name for row in rows}

    def get(self, execution_id: str, task: str) -> dict[str, Any] | None:
        with self.db.session() as session:
            row = session.scalar(
                select(Checkpoint).where(
                    Checkpoint.execution_id == execution_id, Checkpoint.task_name == task
                )
            )
            return row.to_dict() if row else None

    def clear(self, execution_id: str) -> int:
        with self.db.session() as session:
            result = session.execute(
                delete(Checkpoint).where(Checkpoint.execution_id == execution_id)
            )
            return _rowcount(result)

    def purge(self, *, older_than_days: int = 30) -> int:
        cutoff = utcnow() - timedelta(days=max(1, older_than_days))
        with self.db.session() as session:
            result = session.execute(delete(Checkpoint).where(Checkpoint.created_at < cutoff))
            return _rowcount(result)


class SchemaRepository(BaseRepository):
    """Stores and compares observed source schemas (drift detection)."""

    def compare_and_store(
        self,
        *,
        pipeline: str,
        task: str,
        schema: DatasetSchema,
        source_key: str = "default",
        store: bool = True,
    ) -> SchemaDiff:
        """Diff ``schema`` against the last snapshot and optionally replace it."""
        payload = schema.to_dict()
        fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()

        with self.db.session() as session:
            row = session.scalar(
                select(SchemaSnapshot).where(
                    SchemaSnapshot.pipeline_name == pipeline,
                    SchemaSnapshot.task_name == task,
                    SchemaSnapshot.source_key == source_key,
                )
            )
            if row is None:
                if store:
                    row = SchemaSnapshot(
                        pipeline_name=pipeline,
                        task_name=task,
                        source_key=source_key,
                        fingerprint=fingerprint,
                    )
                    row.schema = payload
                    session.add(row)
                return SchemaDiff()  # first observation is never drift

            if row.fingerprint == fingerprint:
                return SchemaDiff()

            previous = _schema_from_dict(row.schema)
            diff = previous.diff(schema)
            if store:
                row.fingerprint = fingerprint
                row.schema = payload
                row.observed_at = utcnow()
            return diff

    def get(self, pipeline: str, task: str, source_key: str = "default") -> dict[str, Any] | None:
        with self.db.session() as session:
            row = session.scalar(
                select(SchemaSnapshot).where(
                    SchemaSnapshot.pipeline_name == pipeline,
                    SchemaSnapshot.task_name == task,
                    SchemaSnapshot.source_key == source_key,
                )
            )
            return row.schema if row else None

    def reset(self, pipeline: str, task: str | None = None) -> int:
        """Forget the stored snapshot so the next run re-baselines.

        Needed after a *deliberate* schema change: editing a task's
        transformations changes the shape of its output, and the drift check
        would otherwise keep failing against a snapshot the operator already
        knows is stale.
        """
        with self.db.session() as session:
            statement = delete(SchemaSnapshot).where(SchemaSnapshot.pipeline_name == pipeline)
            if task:
                statement = statement.where(SchemaSnapshot.task_name == task)
            result = session.execute(statement)
            return _rowcount(result)

    def list(self, pipeline: str | None = None) -> list[dict[str, Any]]:
        with self.db.session() as session:
            statement = select(SchemaSnapshot).order_by(
                SchemaSnapshot.pipeline_name, SchemaSnapshot.task_name
            )
            if pipeline:
                statement = statement.where(SchemaSnapshot.pipeline_name == pipeline)
            return [
                {
                    "pipeline": row.pipeline_name,
                    "task": row.task_name,
                    "source_key": row.source_key,
                    "columns": [f["name"] for f in row.schema.get("fields", [])],
                    "observed_at": row.observed_at.isoformat() if row.observed_at else None,
                }
                for row in session.scalars(statement)
            ]


def _schema_from_dict(payload: dict[str, Any]) -> DatasetSchema:
    from ironflow.core.types import FieldSchema, FieldType

    fields = []
    for entry in payload.get("fields", []):
        try:
            field_type = FieldType(entry.get("type", "unknown"))
        except ValueError:  # pragma: no cover - forward compatibility
            field_type = FieldType.UNKNOWN
        fields.append(
            FieldSchema(
                name=entry["name"],
                type=field_type,
                nullable=bool(entry.get("nullable", True)),
                sensitive=bool(entry.get("sensitive", False)),
            )
        )
    return DatasetSchema(tuple(fields))


class StateRepository(BaseRepository):
    """Generic namespaced key/value store (implements ``StateStore``)."""

    def get(self, namespace: str, key: str) -> Any:
        with self.db.session() as session:
            row = session.scalar(
                select(KeyValue).where(KeyValue.namespace == namespace, KeyValue.key == key)
            )
            return row.value if row else None

    def set(self, namespace: str, key: str, value: Any) -> None:
        with self.db.session() as session:
            row = session.scalar(
                select(KeyValue).where(KeyValue.namespace == namespace, KeyValue.key == key)
            )
            if row is None:
                row = KeyValue(namespace=namespace, key=key)
                session.add(row)
            row.value = value
            row.updated_at = utcnow()

    def delete(self, namespace: str, key: str) -> None:
        with self.db.session() as session:
            session.execute(
                delete(KeyValue).where(KeyValue.namespace == namespace, KeyValue.key == key)
            )

    def keys(self, namespace: str) -> Sequence[str]:
        with self.db.session() as session:
            return list(
                session.scalars(select(KeyValue.key).where(KeyValue.namespace == namespace))
            )


__all__ = [
    "CheckpointRepository",
    "RunRepository",
    "SchemaRepository",
    "StateRepository",
    "WatermarkRepository",
]
