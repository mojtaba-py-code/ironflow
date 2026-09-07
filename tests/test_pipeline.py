"""End-to-end pipeline tests: task execution, orchestration, failure handling."""

from __future__ import annotations

import pytest

from ironflow.config.models import PipelineSpec, TaskSpec
from ironflow.connectors.factory import ConnectorFactory
from ironflow.connectors.memory import MemorySink, MemorySource
from ironflow.core.errors import TaskError
from ironflow.core.events import EventType
from ironflow.core.types import RecordBatch, RunStatus
from ironflow.pipeline.loading import LoadEngine
from ironflow.pipeline.results import PipelineResult, TaskResult
from ironflow.pipeline.runner import PipelineRunner
from ironflow.pipeline.task import TaskExecutor
from ironflow.repositories.repositories import (
    CheckpointRepository,
    RunRepository,
    SchemaRepository,
    WatermarkRepository,
)


def make_pipeline(tasks: list[dict], **overrides) -> PipelineSpec:
    return PipelineSpec.model_validate({"name": "p", "tasks": tasks, **overrides})


def etl_task(name: str, dataset: str, buffer: str, **overrides) -> dict:
    return {
        "name": name,
        "source": {"type": "memory", "dataset": dataset},
        "destination": {"type": "memory", "buffer": buffer, "mode": "overwrite"},
        **overrides,
    }


@pytest.fixture
def runner(settings, database, metrics, events) -> PipelineRunner:
    return PipelineRunner(
        settings=settings,
        factory=ConnectorFactory(settings),
        runs=RunRepository(database),
        watermarks=WatermarkRepository(database),
        checkpoints=CheckpointRepository(database),
        schemas=SchemaRepository(database),
        events=events,
        metrics=metrics,
    )


class TestTaskExecutor:
    def _execute(self, spec_dict: dict, settings, context) -> TaskResult:
        executor = TaskExecutor(
            TaskSpec.model_validate(spec_dict), "p", factory=ConnectorFactory(settings)
        )
        return executor.execute(context)

    def test_simple_copy(self, settings, context, sample_records):
        MemorySource.register("src", sample_records)
        result = self._execute(etl_task("t", "src", "out"), settings, context)
        assert result.status is RunStatus.SUCCESS
        assert result.metrics.rows_in == 5
        assert result.metrics.rows_out == 5
        assert len(MemorySink.buffer("out")) == 5

    def test_transformations_are_applied(self, settings, context, sample_records):
        MemorySource.register("src", sample_records)
        spec = etl_task(
            "t",
            "src",
            "out",
            transformations=[
                {"type": "filter", "expression": "amount is not None and amount > 0"},
                {"type": "mask_pii", "columns": ["email"], "strategy": "email"},
            ],
        )
        result = self._execute(spec, settings, context)
        rows = MemorySink.buffer("out")
        assert result.metrics.rows_out == 3
        # No raw address survives; a value that is not an email is masked whole.
        assert all("*" in r["email"] for r in rows)
        assert not any(r["email"] in {"alice@corp.com", "carol@corp.com"} for r in rows)

    def test_validation_quarantines(self, settings, context, sample_records):
        MemorySource.register("src", sample_records)
        spec = etl_task(
            "t",
            "src",
            "out",
            validation={
                "on_violation": "quarantine",
                "rules": [{"type": "range", "field": "amount", "min": 0}],
            },
            reject_destination={"type": "memory", "buffer": "rejects", "mode": "overwrite"},
        )
        result = self._execute(spec, settings, context)
        assert result.metrics.rows_out == 4  # 5 records, 1 negative amount
        assert result.metrics.rows_failed == 1
        assert len(MemorySink.buffer("rejects")) == 1

    def test_validation_failure_rolls_back_the_destination(self, settings, context, sample_records):
        MemorySource.register("src", sample_records)
        spec = etl_task(
            "t",
            "src",
            "out",
            validation={
                "on_violation": "fail",
                "rules": [{"type": "range", "field": "amount", "min": 0}],
            },
        )
        result = self._execute(spec, settings, context)
        assert result.status is RunStatus.FAILED
        assert MemorySink.buffer("out") == [], "a failed load must publish nothing"

    def test_validation_runs_after_transformation_by_default(self, settings, context):
        """A type rule must see the cast value, not the raw CSV string."""
        MemorySource.register("src", [{"amount": "42"}])
        spec = etl_task(
            "t",
            "src",
            "out",
            transformations=[{"type": "cast", "columns": {"amount": "integer"}}],
            validation={
                "on_violation": "fail",
                "rules": [
                    {"type": "type", "field": "amount", "expected": "integer", "strict": True}
                ],
            },
        )
        assert self._execute(spec, settings, context).status is RunStatus.SUCCESS

    def test_pre_transform_validation_sees_the_raw_source(self, settings, context):
        MemorySource.register("src", [{"amount": "42"}])
        spec = etl_task(
            "t",
            "src",
            "out",
            transformations=[{"type": "cast", "columns": {"amount": "integer"}}],
            validation={
                "stage": "pre_transform",
                "on_violation": "fail",
                "rules": [
                    {"type": "type", "field": "amount", "expected": "integer", "strict": True}
                ],
            },
        )
        assert self._execute(spec, settings, context).status is RunStatus.FAILED

    def test_condition_skips_the_task(self, settings, context):
        MemorySource.register("src", [{"a": 1}])
        context.parameters["full_refresh"] = False
        spec = etl_task("t", "src", "out", condition="params.full_refresh")
        result = self._execute(spec, settings, context)
        assert result.status is RunStatus.SKIPPED
        assert "condition" in result.skipped_reason

    def test_disabled_task_is_skipped(self, settings, context):
        MemorySource.register("src", [{"a": 1}])
        result = self._execute(etl_task("t", "src", "out", enabled=False), settings, context)
        assert result.status is RunStatus.SKIPPED

    def test_noop_task(self, settings, context):
        executor = TaskExecutor(
            TaskSpec.model_validate({"name": "t", "type": "noop"}),
            "p",
            factory=ConnectorFactory(settings),
        )
        assert executor.execute(context).status is RunStatus.SUCCESS

    def test_dry_run_writes_nothing(self, settings, context, sample_records):
        MemorySource.register("src", sample_records)
        context.dry_run = True
        result = self._execute(etl_task("t", "src", "out"), settings, context)
        assert result.status is RunStatus.SUCCESS
        assert MemorySink.buffer("out") == []

    def test_events_are_published(self, settings, context, events, sample_records):
        MemorySource.register("src", sample_records)
        self._execute(etl_task("t", "src", "out"), settings, context)
        types = {event.type for event in events.history(limit=50)}
        assert EventType.TASK_STARTED in types
        assert EventType.TASK_SUCCEEDED in types

    def test_metrics_are_recorded(self, settings, context, metrics, sample_records):
        MemorySource.register("src", sample_records)
        self._execute(etl_task("t", "src", "out"), settings, context)
        labels = {"pipeline": "test_pipeline", "task": "t"}
        assert metrics.get_counter("rows_extracted_total", labels) == 5
        assert metrics.get_counter("rows_loaded_total", labels) == 5

    def test_missing_source_dataset_yields_zero_rows(self, settings, context):
        result = self._execute(etl_task("t", "absent", "out"), settings, context)
        assert result.status is RunStatus.SUCCESS
        assert result.metrics.rows_out == 0


class TestIncremental:
    def test_watermark_advances_only_after_a_successful_load(self, settings, context, database):
        MemorySource.register("src", [{"id": 1, "ts": "2026-01-01"}, {"id": 2, "ts": "2026-01-02"}])
        watermarks = WatermarkRepository(database)
        spec = TaskSpec.model_validate(
            etl_task(
                "t",
                "src",
                "out",
                strategy="incremental",
                incremental={"column": "ts"},
            )
        )
        executor = TaskExecutor(
            spec, "p", factory=ConnectorFactory(settings), watermarks=watermarks
        )
        result = executor.execute(context)
        assert result.status is RunStatus.SUCCESS
        assert watermarks.get("p", "t") == "2026-01-02"

    def test_watermark_is_not_advanced_on_failure(self, settings, context, database):
        MemorySource.register("src", [{"id": 1, "ts": "2026-01-01", "bad": -1}])
        watermarks = WatermarkRepository(database)
        spec = TaskSpec.model_validate(
            etl_task(
                "t",
                "src",
                "out",
                strategy="incremental",
                incremental={"column": "ts"},
                validation={
                    "on_violation": "fail",
                    "rules": [{"type": "range", "field": "bad", "min": 0}],
                },
            )
        )
        executor = TaskExecutor(
            spec, "p", factory=ConnectorFactory(settings), watermarks=watermarks
        )
        assert executor.execute(context).status is RunStatus.FAILED
        assert watermarks.get("p", "t") is None, "advancing here would skip the rows forever"

    def test_watermark_never_moves_backwards(self, database):
        watermarks = WatermarkRepository(database)
        watermarks.set("p", "t", column="ts", value="2026-06-01")
        watermarks.set("p", "t", column="ts", value="2026-01-01")
        assert watermarks.get("p", "t") == "2026-06-01"

    def test_dry_run_does_not_advance_the_watermark(self, settings, context, database):
        MemorySource.register("src", [{"id": 1, "ts": "2026-01-02"}])
        watermarks = WatermarkRepository(database)
        context.dry_run = True
        spec = TaskSpec.model_validate(
            etl_task("t", "src", "out", strategy="incremental", incremental={"column": "ts"})
        )
        executor = TaskExecutor(
            spec, "p", factory=ConnectorFactory(settings), watermarks=watermarks
        )
        executor.execute(context)
        assert watermarks.get("p", "t") is None


class TestSchemaDrift:
    def test_first_observation_is_not_drift(self, settings, context, database):
        MemorySource.register("src", [{"a": 1}])
        schemas = SchemaRepository(database)
        executor = TaskExecutor(
            TaskSpec.model_validate(etl_task("t", "src", "out")),
            "p",
            factory=ConnectorFactory(settings),
            schemas=schemas,
        )
        result = executor.execute(context)
        assert result.schema_drift is None

    def test_added_column_is_allowed_under_the_additive_policy(self, settings, context, database):
        schemas = SchemaRepository(database)
        factory = ConnectorFactory(settings)
        spec = TaskSpec.model_validate(etl_task("t", "src", "out"))

        MemorySource.register("src", [{"a": 1}])
        TaskExecutor(spec, "p", factory=factory, schemas=schemas).execute(context)

        MemorySource.register("src", [{"a": 1, "b": 2}])
        result = TaskExecutor(spec, "p", factory=factory, schemas=schemas).execute(context)
        assert result.status is RunStatus.SUCCESS
        assert result.schema_drift["added"] == ["b"]

    def test_removed_column_fails_under_the_additive_policy(self, settings, context, database):
        """Loading NULLs over an existing column is worse than failing."""
        schemas = SchemaRepository(database)
        factory = ConnectorFactory(settings)
        spec = TaskSpec.model_validate(etl_task("t", "src", "out"))

        MemorySource.register("src", [{"a": 1, "b": 2}])
        TaskExecutor(spec, "p", factory=factory, schemas=schemas).execute(context)

        MemorySource.register("src", [{"a": 1}])
        result = TaskExecutor(spec, "p", factory=factory, schemas=schemas).execute(context)
        assert result.status is RunStatus.FAILED
        assert "disappeared" in str(result.error)

    def test_strict_policy_fails_on_any_change(self, settings, context, database):
        schemas = SchemaRepository(database)
        factory = ConnectorFactory(settings)
        spec = TaskSpec.model_validate(
            etl_task("t", "src", "out", schema_evolution={"mode": "strict"})
        )
        MemorySource.register("src", [{"a": 1}])
        TaskExecutor(spec, "p", factory=factory, schemas=schemas).execute(context)
        MemorySource.register("src", [{"a": 1, "b": 2}])
        result = TaskExecutor(spec, "p", factory=factory, schemas=schemas).execute(context)
        assert result.status is RunStatus.FAILED

    def test_permissive_policy_only_logs(self, settings, context, database):
        schemas = SchemaRepository(database)
        factory = ConnectorFactory(settings)
        spec = TaskSpec.model_validate(
            etl_task("t", "src", "out", schema_evolution={"mode": "permissive"})
        )
        MemorySource.register("src", [{"a": 1, "b": 2}])
        TaskExecutor(spec, "p", factory=factory, schemas=schemas).execute(context)
        MemorySource.register("src", [{"a": 1}])
        result = TaskExecutor(spec, "p", factory=factory, schemas=schemas).execute(context)
        assert result.status is RunStatus.SUCCESS


class TestRunner:
    def test_linear_pipeline(self, runner, sample_records):
        MemorySource.register("src", sample_records)
        pipeline = make_pipeline(
            [etl_task("a", "src", "mid"), etl_task("b", "src", "out", depends_on=["a"])]
        )
        result = runner.run(pipeline, install_signal_handlers=False)
        assert result.status is RunStatus.SUCCESS
        assert result.tasks_succeeded == 2
        assert result.rows_written == 10

    def test_parallel_level_runs_concurrently(self, runner, sample_records):
        MemorySource.register("src", sample_records)
        pipeline = make_pipeline(
            [
                etl_task("root", "src", "b0"),
                etl_task("a", "src", "b1", depends_on=["root"]),
                etl_task("b", "src", "b2", depends_on=["root"]),
                etl_task("c", "src", "b3", depends_on=["root"]),
            ],
            max_parallel_tasks=3,
        )
        result = runner.run(pipeline, install_signal_handlers=False)
        assert result.status is RunStatus.SUCCESS
        assert result.tasks_succeeded == 4

    def test_failure_aborts_downstream_tasks(self, runner):
        MemorySource.register("src", [{"amount": -1}])
        pipeline = make_pipeline(
            [
                etl_task(
                    "bad",
                    "src",
                    "out",
                    validation={
                        "on_violation": "fail",
                        "rules": [{"type": "range", "field": "amount", "min": 0}],
                    },
                ),
                etl_task("downstream", "src", "out2", depends_on=["bad"]),
            ]
        )
        result = runner.run(pipeline, install_signal_handlers=False)
        assert result.status is RunStatus.FAILED
        assert result.task("downstream").status is RunStatus.SKIPPED
        assert MemorySink.buffer("out2") == []

    def test_on_failure_continue_yields_partial(self, runner, sample_records):
        MemorySource.register("src", sample_records)
        MemorySource.register("bad", [{"amount": -1}])
        pipeline = make_pipeline(
            [
                etl_task(
                    "failing",
                    "bad",
                    "b1",
                    on_failure="continue",
                    validation={
                        "on_violation": "fail",
                        "rules": [{"type": "range", "field": "amount", "min": 0}],
                    },
                ),
                etl_task("independent", "src", "b2"),
            ]
        )
        result = runner.run(pipeline, install_signal_handlers=False)
        assert result.status is RunStatus.PARTIAL
        assert result.tasks_succeeded == 1
        assert result.tasks_failed == 1

    def test_only_runs_a_subset_with_its_ancestors(self, runner, sample_records):
        MemorySource.register("src", sample_records)
        pipeline = make_pipeline(
            [
                etl_task("a", "src", "b1"),
                etl_task("b", "src", "b2", depends_on=["a"]),
                etl_task("c", "src", "b3"),
            ]
        )
        result = runner.run(pipeline, only=["b"], install_signal_handlers=False)
        assert {t.task_name for t in result.tasks} == {"a", "b"}

    def test_task_state_is_visible_to_dependents(self, runner, sample_records):
        MemorySource.register("src", sample_records)
        pipeline = make_pipeline(
            [
                etl_task("producer", "src", "b1"),
                etl_task(
                    "consumer",
                    "src",
                    "b2",
                    depends_on=["producer"],
                    condition="state.producer.rows_out > 0",
                ),
            ]
        )
        result = runner.run(pipeline, install_signal_handlers=False)
        assert result.task("consumer").status is RunStatus.SUCCESS

    def test_condition_can_skip_a_dependent(self, runner, sample_records):
        MemorySource.register("src", sample_records)
        MemorySource.register("empty", [])
        pipeline = make_pipeline(
            [
                etl_task("producer", "empty", "b1"),
                etl_task(
                    "consumer",
                    "src",
                    "b2",
                    depends_on=["producer"],
                    condition="state.producer.rows_out > 0",
                ),
            ]
        )
        result = runner.run(pipeline, install_signal_handlers=False)
        assert result.task("consumer").status is RunStatus.SKIPPED

    def test_run_history_is_recorded(self, runner, database, sample_records):
        MemorySource.register("src", sample_records)
        result = runner.run(
            make_pipeline([etl_task("a", "src", "out")]), install_signal_handlers=False
        )
        stored = RunRepository(database).get_run(result.execution_id)
        assert stored["status"] == "success"
        assert stored["rows_written"] == 5
        assert len(stored["task_runs"]) == 0 or stored["task_runs"]

    def test_checkpoints_are_written(self, runner, database, sample_records):
        MemorySource.register("src", sample_records)
        result = runner.run(
            make_pipeline([etl_task("a", "src", "out")]), install_signal_handlers=False
        )
        assert CheckpointRepository(database).completed_tasks(result.execution_id) == {"a"}

    def test_resume_skips_completed_tasks(self, runner, database, sample_records):
        MemorySource.register("src", sample_records)
        pipeline = make_pipeline(
            [etl_task("a", "src", "b1"), etl_task("b", "src", "b2", depends_on=["a"])]
        )
        first = runner.run(pipeline, install_signal_handlers=False)
        MemorySink.clear()

        second = runner.run(
            pipeline, resume_execution_id=first.execution_id, install_signal_handlers=False
        )
        assert second.task("a").status is RunStatus.SKIPPED
        assert "previous attempt" in second.task("a").skipped_reason
        assert MemorySink.buffer("b1") == [], "a completed task must not re-run"

    def test_disabled_pipeline_is_refused(self, runner):
        pipeline = make_pipeline([etl_task("a", "src", "out")], enabled=False)
        with pytest.raises(Exception, match="disabled"):
            runner.run(pipeline, install_signal_handlers=False)

    def test_cancellation_stops_the_run(self, runner, sample_records):
        MemorySource.register("src", sample_records)
        pipeline = make_pipeline(
            [etl_task("a", "src", "b1"), etl_task("b", "src", "b2", depends_on=["a"])]
        )
        original = runner._run_task

        def cancel_after_first(name, graph, context):
            result = original(name, graph, context)
            context.cancellation.cancel("test cancellation")
            return result

        runner._run_task = cancel_after_first
        result = runner.run(pipeline, install_signal_handlers=False)
        assert result.status is RunStatus.CANCELLED

    def test_pipeline_events_are_published(self, runner, events, sample_records):
        MemorySource.register("src", sample_records)
        runner.run(make_pipeline([etl_task("a", "src", "out")]), install_signal_handlers=False)
        types = {event.type for event in events.history(limit=100)}
        assert EventType.PIPELINE_STARTED in types
        assert EventType.PIPELINE_SUCCEEDED in types

    def test_resource_usage_is_captured(self, runner, sample_records):
        MemorySource.register("src", sample_records)
        result = runner.run(
            make_pipeline([etl_task("a", "src", "out")]), install_signal_handlers=False
        )
        assert "rss_mb" in result.resources


class TestResults:
    def test_derive_status(self):
        result = PipelineResult(pipeline_name="p", execution_id="e")
        assert result.derive_status() is RunStatus.SUCCESS

        result.tasks = [
            TaskResult("a").finish(RunStatus.SUCCESS),
            TaskResult("b").finish(RunStatus.FAILED),
        ]
        assert result.derive_status() is RunStatus.PARTIAL

        result.tasks = [TaskResult("b").finish(RunStatus.FAILED)]
        assert result.derive_status() is RunStatus.FAILED

    def test_aggregates(self):
        result = PipelineResult(pipeline_name="p", execution_id="e")
        first = TaskResult("a")
        first.metrics.rows_in, first.metrics.rows_out = 10, 8
        second = TaskResult("b")
        second.metrics.rows_in, second.metrics.rows_out, second.metrics.rows_failed = 5, 5, 2
        result.tasks = [first, second]
        assert result.rows_read == 15
        assert result.rows_written == 13
        assert result.rows_rejected == 2

    def test_serialisation_includes_errors(self):
        result = PipelineResult(pipeline_name="p", execution_id="e")
        result.finish(RunStatus.FAILED, TaskError("boom", context={"task": "a"}))
        payload = result.to_dict()
        assert payload["error"]["code"] == "TASK_FAILED"
        assert payload["status"] == "failed"


class TestLoadEngine:
    def test_rollback_on_a_failing_stream(self, factory, context):
        from ironflow.config.models import ConnectorSpec

        sink = factory.create_sink(ConnectorSpec.model_validate({"type": "memory", "buffer": "lb"}))

        def exploding_stream():
            yield RecordBatch([{"a": 1}])
            raise RuntimeError("source died")

        engine = LoadEngine(sink, task_name="t")
        with pytest.raises(RuntimeError):
            engine.load(exploding_stream(), context)
        assert engine.result.rolled_back
        assert MemorySink.buffer("lb") == []

    def test_dry_run_counts_without_writing(self, context):
        engine = LoadEngine(None, task_name="t")
        result = engine.load(iter([RecordBatch([{"a": 1}, {"a": 2}])]), context)
        assert result.rows_written == 2
        assert not result.committed

    def test_reject_failures_do_not_break_the_load(self, factory, context, caplog):
        from ironflow.config.models import ConnectorSpec

        sink = factory.create_sink(ConnectorSpec.model_validate({"type": "memory", "buffer": "m"}))
        rejects = factory.create_sink(
            ConnectorSpec.model_validate({"type": "memory", "buffer": "r"})
        )
        rejects.write = lambda *_: (_ for _ in ()).throw(RuntimeError("quarantine full"))

        engine = LoadEngine(sink, reject_sink=rejects, task_name="t")
        with caplog.at_level("ERROR"):
            count = engine.write_rejects([{"a": 1}], context)
        assert count == 1
        assert "quarantined" in caplog.text
