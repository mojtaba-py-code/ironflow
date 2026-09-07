"""Tests for the state database and the repository layer."""

from __future__ import annotations

from datetime import timedelta

import pytest

from ironflow.core.context import utcnow
from ironflow.core.errors import ConnectionError as IFConnectionError
from ironflow.core.types import DatasetSchema, FieldSchema, FieldType, RunStatus
from ironflow.repositories.database import Database
from ironflow.repositories.models import PipelineRun
from ironflow.repositories.repositories import (
    CheckpointRepository,
    RunRepository,
    SchemaRepository,
    StateRepository,
    WatermarkRepository,
)


class TestDatabase:
    def test_schema_is_created(self, database):
        assert database.healthcheck()

    def test_create_schema_is_idempotent(self, database):
        database.create_schema()
        database.create_schema()
        assert database.healthcheck()

    def test_session_rolls_back_on_error(self, database):
        with pytest.raises(RuntimeError), database.session() as session:
            session.add(PipelineRun(execution_id="e1", pipeline_name="p"))
            raise RuntimeError("boom")
        with database.session() as session:
            assert session.query(PipelineRun).count() == 0

    def test_session_commits_on_success(self, database):
        with database.session() as session:
            session.add(PipelineRun(execution_id="e1", pipeline_name="p"))
        with database.session() as session:
            assert session.query(PipelineRun).count() == 1

    def test_in_memory_database(self, settings):
        db = Database("sqlite:///:memory:", settings=settings)
        assert db.healthcheck()
        db.dispose()

    def test_invalid_url_is_reported(self, settings):
        with pytest.raises(IFConnectionError):
            Database("not-a-database-url", settings=settings)

    def test_sqlite_foreign_keys_are_enabled(self, database):
        from sqlalchemy import text

        with database.engine.connect() as connection:
            assert connection.execute(text("PRAGMA foreign_keys")).scalar() == 1


class TestRunRepository:
    def test_start_and_finish(self, database):
        repository = RunRepository(database)
        repository.start_run(execution_id="e1", pipeline_name="p", tasks_total=3)
        repository.finish_run(
            "e1",
            status=RunStatus.SUCCESS,
            duration_seconds=1.5,
            rows_read=100,
            rows_written=95,
            tasks_succeeded=3,
        )
        run = repository.get_run("e1")
        assert run["status"] == "success"
        assert run["rows_written"] == 95
        assert run["duration_seconds"] == 1.5

    def test_start_is_idempotent_for_resume(self, database):
        """A resume re-enters the same execution id; it must not violate the key."""
        repository = RunRepository(database)
        first = repository.start_run(execution_id="e1", pipeline_name="p")
        second = repository.start_run(execution_id="e1", pipeline_name="p", trigger="resume")
        assert first == second
        assert repository.get_run("e1")["attempt"] == 2

    def test_resume_clears_the_previous_error(self, database):
        repository = RunRepository(database)
        repository.start_run(execution_id="e1", pipeline_name="p")
        repository.finish_run(
            "e1", status=RunStatus.FAILED, duration_seconds=1, error=RuntimeError("boom")
        )
        repository.start_run(execution_id="e1", pipeline_name="p", trigger="resume")
        assert repository.get_run("e1")["error"] is None

    def test_finish_of_an_unknown_run_is_ignored(self, database, caplog):
        with caplog.at_level("WARNING"):
            RunRepository(database).finish_run(
                "ghost", status=RunStatus.SUCCESS, duration_seconds=0
            )
        assert "unknown execution" in caplog.text

    def test_error_is_stored_with_its_code(self, database):
        from ironflow.core.errors import ValidationError

        repository = RunRepository(database)
        repository.start_run(execution_id="e1", pipeline_name="p")
        repository.finish_run(
            "e1", status=RunStatus.FAILED, duration_seconds=1, error=ValidationError("bad data")
        )
        run = repository.get_run("e1")
        assert run["error"]["code"] == "VALIDATION_FAILED"

    def test_long_error_messages_are_truncated(self, database):
        repository = RunRepository(database)
        repository.start_run(execution_id="e1", pipeline_name="p")
        repository.finish_run(
            "e1", status=RunStatus.FAILED, duration_seconds=1, error=RuntimeError("x" * 10_000)
        )
        assert len(repository.get_run("e1")["error"]["message"]) <= 4000

    def test_task_runs_are_recorded(self, database):
        repository = RunRepository(database)
        run_id = repository.start_run(execution_id="e1", pipeline_name="p")
        repository.record_task(
            run_id=run_id,
            execution_id="e1",
            task_name="t1",
            status=RunStatus.SUCCESS,
            rows_written=10,
        )
        run = repository.get_run("e1")
        assert run["task_runs"][0]["task"] == "t1"

    def test_list_filters_and_orders(self, database):
        repository = RunRepository(database)
        for index in range(5):
            repository.start_run(execution_id=f"e{index}", pipeline_name="a" if index < 3 else "b")
            repository.finish_run(
                f"e{index}",
                status=RunStatus.SUCCESS if index % 2 == 0 else RunStatus.FAILED,
                duration_seconds=index,
            )
        assert len(repository.list_runs(pipeline_name="a")) == 3
        assert len(repository.list_runs(status=RunStatus.FAILED)) == 2
        assert len(repository.list_runs(limit=2)) == 2

    def test_latest_and_last_failed(self, database):
        repository = RunRepository(database)
        repository.start_run(execution_id="e1", pipeline_name="p")
        repository.finish_run("e1", status=RunStatus.SUCCESS, duration_seconds=1)
        repository.start_run(execution_id="e2", pipeline_name="p")
        repository.finish_run("e2", status=RunStatus.FAILED, duration_seconds=1)
        assert repository.latest_run("p")["execution_id"] == "e2"
        assert repository.last_failed_run("p")["execution_id"] == "e2"

    def test_running_count(self, database):
        repository = RunRepository(database)
        repository.start_run(execution_id="e1", pipeline_name="p")
        assert repository.running_count("p") == 1
        repository.finish_run("e1", status=RunStatus.SUCCESS, duration_seconds=1)
        assert repository.running_count("p") == 0

    def test_statistics(self, database):
        repository = RunRepository(database)
        for index in range(4):
            repository.start_run(execution_id=f"e{index}", pipeline_name="p")
            repository.finish_run(
                f"e{index}",
                status=RunStatus.SUCCESS if index < 3 else RunStatus.FAILED,
                duration_seconds=float(index + 1),
                rows_written=10,
            )
        stats = repository.statistics("p")
        assert stats["runs_total"] == 4
        assert stats["success_rate"] == 0.75
        assert stats["rows_written"] == 40
        assert stats["avg_duration_seconds"] == 2.5
        assert stats["max_duration_seconds"] == 4.0

    def test_statistics_of_an_empty_window(self, database):
        stats = RunRepository(database).statistics("nothing")
        assert stats["runs_total"] == 0
        assert stats["success_rate"] == 0.0

    def test_purge_removes_old_runs_and_their_tasks(self, database):
        repository = RunRepository(database)
        run_id = repository.start_run(execution_id="old", pipeline_name="p")
        repository.record_task(
            run_id=run_id, execution_id="old", task_name="t", status=RunStatus.SUCCESS
        )
        with database.session() as session:
            run = session.query(PipelineRun).filter_by(execution_id="old").one()
            run.started_at = utcnow() - timedelta(days=200)

        repository.start_run(execution_id="new", pipeline_name="p")
        assert repository.purge(older_than_days=90) == 1
        assert repository.get_run("old") is None
        assert repository.get_run("new") is not None

    def test_timeline(self, database):
        repository = RunRepository(database)
        repository.start_run(execution_id="e1", pipeline_name="p")
        repository.finish_run("e1", status=RunStatus.SUCCESS, duration_seconds=2, rows_written=7)
        entry = repository.timeline()[0]
        assert entry["pipeline"] == "p"
        assert entry["rows_written"] == 7


class TestWatermarkRepository:
    def test_set_and_get(self, database):
        repository = WatermarkRepository(database)
        assert repository.get("p", "t") is None
        repository.set("p", "t", column="ts", value="2026-01-01")
        assert repository.get("p", "t") == "2026-01-01"

    def test_only_moves_forward(self, database):
        repository = WatermarkRepository(database)
        repository.set("p", "t", column="ts", value=100)
        repository.set("p", "t", column="ts", value=50)
        assert repository.get("p", "t") == 100

    def test_mixed_type_comparison_does_not_crash(self, database):
        repository = WatermarkRepository(database)
        repository.set("p", "t", column="ts", value="2026-01-01")
        repository.set("p", "t", column="ts", value=5)
        assert repository.get("p", "t") is not None

    def test_scoped_by_source_key(self, database):
        repository = WatermarkRepository(database)
        repository.set("p", "t", column="ts", value=1, source_key="a")
        repository.set("p", "t", column="ts", value=2, source_key="b")
        assert repository.get("p", "t", "a") == 1
        assert repository.get("p", "t", "b") == 2

    def test_reset(self, database):
        repository = WatermarkRepository(database)
        repository.set("p", "t1", column="ts", value=1)
        repository.set("p", "t2", column="ts", value=1)
        assert repository.reset("p", "t1") == 1
        assert repository.get("p", "t1") is None
        assert repository.get("p", "t2") == 1
        assert repository.reset("p") == 1

    def test_list(self, database):
        repository = WatermarkRepository(database)
        repository.set("p", "t", column="ts", value=1, rows=99)
        rows = repository.list("p")
        assert rows[0]["column"] == "ts"
        assert rows[0]["rows_last_run"] == 99


class TestCheckpointRepository:
    def test_save_and_read(self, database):
        repository = CheckpointRepository(database)
        repository.save(execution_id="e1", pipeline="p", task="t1", rows_processed=10)
        assert repository.completed_tasks("e1") == {"t1"}
        assert repository.get("e1", "t1")["rows_processed"] == 10

    def test_save_is_idempotent(self, database):
        repository = CheckpointRepository(database)
        repository.save(execution_id="e1", pipeline="p", task="t1", rows_processed=10)
        repository.save(execution_id="e1", pipeline="p", task="t1", rows_processed=20)
        assert repository.get("e1", "t1")["rows_processed"] == 20

    def test_failed_checkpoints_are_not_reported_as_complete(self, database):
        repository = CheckpointRepository(database)
        repository.save(execution_id="e1", pipeline="p", task="t1", status=RunStatus.FAILED)
        assert repository.completed_tasks("e1") == set()

    def test_clear_and_purge(self, database):
        repository = CheckpointRepository(database)
        repository.save(execution_id="e1", pipeline="p", task="t1")
        assert repository.clear("e1") == 1
        assert repository.completed_tasks("e1") == set()


class TestSchemaRepository:
    def _schema(self, *names: str) -> DatasetSchema:
        return DatasetSchema(tuple(FieldSchema(n, FieldType.STRING) for n in names))

    def test_first_observation_is_not_drift(self, database):
        repository = SchemaRepository(database)
        diff = repository.compare_and_store(pipeline="p", task="t", schema=self._schema("a", "b"))
        assert diff.is_empty

    def test_identical_schema_is_not_drift(self, database):
        repository = SchemaRepository(database)
        repository.compare_and_store(pipeline="p", task="t", schema=self._schema("a"))
        assert repository.compare_and_store(
            pipeline="p", task="t", schema=self._schema("a")
        ).is_empty

    def test_added_and_removed_columns_are_detected(self, database):
        repository = SchemaRepository(database)
        repository.compare_and_store(pipeline="p", task="t", schema=self._schema("a", "b"))
        diff = repository.compare_and_store(pipeline="p", task="t", schema=self._schema("a", "c"))
        assert diff.added == ("c",)
        assert diff.removed == ("b",)

    def test_reset_rebaselines_after_a_deliberate_change(self, database):
        """Editing a task changes its output shape; the snapshot must be clearable."""
        repository = SchemaRepository(database)
        repository.compare_and_store(pipeline="p", task="t", schema=self._schema("a", "b"))
        assert repository.reset("p", "t") == 1
        # Next observation is a first observation again, so no drift is reported.
        assert repository.compare_and_store(
            pipeline="p", task="t", schema=self._schema("a")
        ).is_empty

    def test_reset_is_scoped_to_the_pipeline(self, database):
        repository = SchemaRepository(database)
        repository.compare_and_store(pipeline="p1", task="t", schema=self._schema("a"))
        repository.compare_and_store(pipeline="p2", task="t", schema=self._schema("a"))
        assert repository.reset("p1") == 1
        assert repository.get("p2", "t") is not None

    def test_list(self, database):
        repository = SchemaRepository(database)
        repository.compare_and_store(pipeline="p", task="t", schema=self._schema("a", "b"))
        rows = repository.list("p")
        assert rows[0]["columns"] == ["a", "b"]

    def test_store_false_leaves_the_snapshot_untouched(self, database):
        repository = SchemaRepository(database)
        repository.compare_and_store(pipeline="p", task="t", schema=self._schema("a"))
        repository.compare_and_store(
            pipeline="p", task="t", schema=self._schema("a", "b"), store=False
        )
        diff = repository.compare_and_store(pipeline="p", task="t", schema=self._schema("a", "b"))
        assert diff.added == ("b",), "a dry run must not consume the drift"


class TestStateRepository:
    def test_set_get_delete(self, database):
        repository = StateRepository(database)
        assert repository.get("ns", "k") is None
        repository.set("ns", "k", {"a": 1})
        assert repository.get("ns", "k") == {"a": 1}
        repository.set("ns", "k", "replaced")
        assert repository.get("ns", "k") == "replaced"
        repository.delete("ns", "k")
        assert repository.get("ns", "k") is None

    def test_namespaces_are_isolated(self, database):
        repository = StateRepository(database)
        repository.set("a", "k", 1)
        repository.set("b", "k", 2)
        assert repository.get("a", "k") == 1
        assert list(repository.keys("a")) == ["k"]
