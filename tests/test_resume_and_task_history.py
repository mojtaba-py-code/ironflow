"""A resume stays inside its own pipeline, and every task leaves a record.

``pipeline resume`` accepted any execution id. Authorisation checked only the
pipeline named on the command line, ``completed_tasks`` did not filter by
pipeline, and ``start_run`` took over the other pipeline's history row. An
operator scoped to ``sales_*`` resumed ``sales_daily`` with an ``hr_payroll``
execution id: the hr run record was rewritten (actor, attempt 2, rows 0) and
sales_daily reported success having skipped the tasks hr had finished.

``pipeline logs`` - documented as the per-task breakdown - always printed an
empty table, because nothing ever called ``RunRepository.record_task``.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from ironflow.cli.context import EXIT_FAILED
from ironflow.cli.main import app
from ironflow.config.models import PipelineSpec
from ironflow.config.settings import reset_settings
from ironflow.connectors.factory import ConnectorFactory
from ironflow.connectors.memory import MemorySink, MemorySource
from ironflow.core.errors import CheckpointError, ConfigurationError
from ironflow.core.errors import ConnectionError as IFConnectionError
from ironflow.core.types import RunStatus
from ironflow.pipeline.runner import PipelineRunner
from ironflow.pipeline.task import TaskExecutor
from ironflow.repositories.repositories import CheckpointRepository, RunRepository
from ironflow.security.rbac import OPERATOR, Principal

#: Both pipelines have an ``extract`` and a ``load``: shared task names are what
#: let one pipeline's checkpoints stand in for the other's work.
HR_PAYROLL: dict[str, Any] = {
    "name": "hr_payroll",
    "tasks": [
        {
            "name": "extract",
            "source": {"type": "memory", "records": [{"id": 1}, {"id": 2}]},
            "destination": {"type": "memory", "buffer": "hr_staging", "mode": "overwrite"},
        },
        {
            "name": "load",
            "depends_on": ["extract"],
            "source": {"type": "memory", "dataset": "hr_rows"},
            "validation": {
                "on_violation": "fail",
                "rules": [{"type": "not_null", "field": "id"}],
            },
            "destination": {"type": "memory", "buffer": "hr_out", "mode": "overwrite"},
        },
        {
            "name": "publish",
            "depends_on": ["load"],
            "source": {"type": "memory", "records": [{"id": 1}]},
            "destination": {"type": "memory", "buffer": "hr_published", "mode": "overwrite"},
        },
    ],
}
SALES_DAILY: dict[str, Any] = {
    "name": "sales_daily",
    "tasks": [
        {
            "name": "extract",
            "source": {"type": "memory", "records": [{"sale": 1}, {"sale": 2}, {"sale": 3}]},
            "destination": {"type": "memory", "buffer": "sales_staging", "mode": "overwrite"},
        },
        {
            "name": "load",
            "depends_on": ["extract"],
            "source": {"type": "memory", "records": [{"sale": 1}, {"sale": 2}, {"sale": 3}]},
            "destination": {"type": "memory", "buffer": "sales_out", "mode": "overwrite"},
        },
    ],
}

SALES_OPERATOR = Principal("sales-operator", roles=(OPERATOR,), pipeline_scopes=("sales_*",))


def write_pipelines(directory: Path) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for document in (HR_PAYROLL, SALES_DAILY):
        path = directory / f"{document['name']}.yaml"
        path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


@pytest.fixture
def failed_hr_run(service, tmp_path) -> str:
    """An hr_payroll execution whose ``extract`` finished and ``load`` failed."""
    write_pipelines(tmp_path / "pipelines")
    MemorySource.register("hr_rows", [{"id": None}])
    result = service.run(service.get_pipeline("hr_payroll"), install_signal_handlers=False)
    assert result.status is RunStatus.FAILED
    assert result.task("extract").status is RunStatus.SUCCESS
    MemorySink.clear()
    return result.execution_id


class TestResumeStaysInItsPipeline:
    def test_a_scoped_operator_cannot_resume_another_pipelines_execution(
        self, service, failed_hr_run
    ):
        before = service.runs.get_run(failed_hr_run)
        service.access.enabled = True

        with pytest.raises(ConfigurationError, match="not a run of this pipeline"):
            service.resume("sales_daily", failed_hr_run, principal=SALES_OPERATOR)

        assert service.runs.get_run(failed_hr_run) == before, "the hr record must be untouched"
        assert MemorySink.buffer("sales_staging") == []
        assert MemorySink.buffer("sales_out") == []

    def test_it_is_refused_whoever_asks(self, service, failed_hr_run):
        """Not a permission question: no principal may resume a foreign run."""
        with pytest.raises(ConfigurationError, match="not a run of this pipeline"):
            service.resume("sales_daily", failed_hr_run)

    def test_an_unknown_execution_gets_the_same_answer(self, service, failed_hr_run):
        """Otherwise the error would tell a scoped operator which ids exist elsewhere."""
        with pytest.raises(ConfigurationError, match="not a run of this pipeline") as unknown:
            service.resume("sales_daily", "exec_does_not_exist")
        with pytest.raises(ConfigurationError) as foreign:
            service.resume("sales_daily", failed_hr_run)
        assert unknown.value.message == foreign.value.message
        assert set(unknown.value.context) == set(foreign.value.context)

    def test_a_pipeline_still_resumes_its_own_execution(self, service, failed_hr_run):
        MemorySource.register("hr_rows", [{"id": 3}])
        result = service.resume("hr_payroll", failed_hr_run)

        assert result.status is RunStatus.SUCCESS
        assert result.task("extract").status is RunStatus.SKIPPED
        assert MemorySink.buffer("hr_staging") == [], "a finished task must not re-run"
        assert MemorySink.buffer("hr_out") == [{"id": 3}]
        assert service.runs.get_run(failed_hr_run)["attempt"] == 2


class TestTheLayersBelowRefuseToo:
    """The service check is the front door; these hold for any other caller."""

    def test_start_run_will_not_take_over_another_pipelines_row(self, database):
        runs = RunRepository(database)
        runs.start_run(execution_id="exec_1", pipeline_name="hr_payroll", actor="hr-operator")
        with pytest.raises(ConfigurationError, match="another pipeline"):
            runs.start_run(
                execution_id="exec_1", pipeline_name="sales_daily", actor="sales-operator"
            )
        row = runs.get_run("exec_1")
        assert (row["pipeline"], row["actor"], row["attempt"]) == ("hr_payroll", "hr-operator", 1)

    def test_checkpoints_are_read_per_pipeline(self, database):
        checkpoints = CheckpointRepository(database)
        checkpoints.save(execution_id="exec_1", pipeline="hr_payroll", task="extract")
        assert checkpoints.completed_tasks("exec_1", pipeline="hr_payroll") == {"extract"}
        assert checkpoints.completed_tasks("exec_1", pipeline="sales_daily") == set()
        assert checkpoints.completed_tasks("exec_1") == {"extract"}, "unfiltered call unchanged"

    def test_a_checkpoint_of_another_pipeline_is_not_overwritten(self, database):
        checkpoints = CheckpointRepository(database)
        checkpoints.save(
            execution_id="exec_1", pipeline="hr_payroll", task="extract", rows_processed=2
        )
        with pytest.raises(CheckpointError, match="another pipeline"):
            checkpoints.save(
                execution_id="exec_1", pipeline="sales_daily", task="extract", rows_processed=0
            )
        stored = checkpoints.get("exec_1", "extract")
        assert (stored["pipeline"], stored["rows_processed"]) == ("hr_payroll", 2)

    def test_the_runner_refuses_before_running_anything(self, settings, service, failed_hr_run):
        runner = PipelineRunner(
            settings=settings,
            factory=ConnectorFactory(settings),
            runs=service.runs,
            checkpoints=service.checkpoints,
        )
        before = service.runs.get_run(failed_hr_run)
        with pytest.raises(ConfigurationError, match="another pipeline"):
            runner.run(
                PipelineSpec.model_validate(SALES_DAILY),
                resume_execution_id=failed_hr_run,
                install_signal_handlers=False,
            )
        assert service.runs.get_run(failed_hr_run) == before
        assert MemorySink.buffer("sales_staging") == []

    def test_without_run_history_foreign_checkpoints_skip_nothing(
        self, settings, service, failed_hr_run
    ):
        """A runner with checkpoints but no history has only the checkpoints to go on."""
        runner = PipelineRunner(
            settings=settings, factory=ConnectorFactory(settings), checkpoints=service.checkpoints
        )
        result = runner.run(
            PipelineSpec.model_validate(SALES_DAILY),
            resume_execution_id=failed_hr_run,
            install_signal_handlers=False,
        )
        assert result.task("extract").status is RunStatus.SUCCESS, "hr's extract is not ours"
        assert len(MemorySink.buffer("sales_staging")) == 3
        hr_checkpoint = service.checkpoints.get(failed_hr_run, "extract")
        assert (hr_checkpoint["pipeline"], hr_checkpoint["rows_processed"]) == ("hr_payroll", 2)


def task_rows(service, execution_id: str) -> list[tuple[str, str, int]]:
    """``(task, status, attempt)`` for every task row of a run, in order."""
    return [
        (row["task"], row["status"], row["attempt"])
        for row in service.run_details(execution_id)["task_runs"]
    ]


def as_naive_utc(moment: datetime) -> datetime:
    return moment.astimezone(UTC).replace(tzinfo=None) if moment.tzinfo else moment


class TestTaskHistory:
    def test_every_task_of_a_run_is_recorded(self, service, tmp_path):
        write_pipelines(tmp_path / "pipelines")
        result = service.run(service.get_pipeline("sales_daily"), install_signal_handlers=False)
        assert task_rows(service, result.execution_id) == [
            ("extract", "success", 1),
            ("load", "success", 1),
        ]
        rows = service.run_details(result.execution_id)["task_runs"]
        assert [(row["rows_read"], row["rows_written"]) for row in rows] == [(3, 3), (3, 3)]

    def test_a_row_keeps_the_tasks_own_times(self, service, tmp_path):
        """Written when the run ends, a row must not claim the task ended then."""
        write_pipelines(tmp_path / "pipelines")
        result = service.run(service.get_pipeline("sales_daily"), install_signal_handlers=False)
        rows = service.run_details(result.execution_id)["task_runs"]
        assert len(rows) == 2
        for row in rows:
            task = result.task(row["task"])
            assert task is not None and task.finished_at is not None
            recorded = (
                as_naive_utc(datetime.fromisoformat(row["started_at"])),
                as_naive_utc(datetime.fromisoformat(row["finished_at"])),
            )
            assert recorded == (as_naive_utc(task.started_at), as_naive_utc(task.finished_at))

    def test_a_failed_task_is_recorded_with_its_error_and_what_it_stopped(
        self, service, failed_hr_run
    ):
        rows = {row["task"]: row for row in service.run_details(failed_hr_run)["task_runs"]}
        assert rows["extract"]["status"] == "success"
        assert rows["load"]["status"] == "failed"
        assert rows["load"]["error"]["code"] == "VALIDATION_FAILED"
        assert "failed validation" in rows["load"]["error"]["message"]
        assert rows["publish"]["status"] == "skipped"
        assert rows["publish"]["details"] == {"skipped_reason": "an upstream task failed"}

    def test_a_resume_records_its_own_attempt_and_nothing_twice(self, service, failed_hr_run):
        """``extract`` finished in attempt 1; attempt 2 must not add a row for it."""
        MemorySource.register("hr_rows", [{"id": 3}])
        service.resume("hr_payroll", failed_hr_run)
        assert task_rows(service, failed_hr_run) == [
            ("extract", "success", 1),
            ("load", "failed", 1),
            ("publish", "skipped", 1),
            ("load", "success", 2),
            ("publish", "success", 2),
        ]

    def test_task_retries_are_kept_in_the_details(self, service, monkeypatch):
        """The attempt column is the run's; the task's own retries must not be lost."""
        flaky = PipelineSpec.model_validate(
            {
                "name": "flaky",
                "tasks": [
                    {
                        "name": "load",
                        "source": {"type": "memory", "records": [{"a": 1}]},
                        "destination": {"type": "memory", "buffer": "flaky", "mode": "overwrite"},
                        "retry": {"max_attempts": 3, "initial_delay": 0, "jitter": False},
                    }
                ],
            }
        )
        calls = {"n": 0}
        run_once = TaskExecutor._run_once

        def fails_twice(executor, context, result):
            calls["n"] += 1
            if calls["n"] < 3:
                raise IFConnectionError("source unavailable")
            return run_once(executor, context, result)

        monkeypatch.setattr(TaskExecutor, "_run_once", fails_twice)
        result = service.run(flaky, install_signal_handlers=False)
        (row,) = service.run_details(result.execution_id)["task_runs"]
        assert (row["status"], row["attempt"], row["details"]) == ("success", 1, {"retries": 2})


class TestCli:
    runner = CliRunner()

    @pytest.fixture
    def workspace(self, tmp_path: Path, monkeypatch) -> Path:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("IRONFLOW_HOME", str(tmp_path / ".ironflow"))
        monkeypatch.setenv("IRONFLOW_DATA_ROOTS", str(tmp_path))
        monkeypatch.setenv("IRONFLOW_PIPELINES_DIR", str(tmp_path / "pipelines"))
        monkeypatch.setenv("COLUMNS", "400")
        reset_settings()
        write_pipelines(tmp_path / "pipelines")
        MemorySource.register("hr_rows", [{"id": None}])
        return tmp_path

    def invoke(self, *args: str):
        return self.runner.invoke(app, list(args), catch_exceptions=False)

    def hr_run(self) -> dict[str, Any]:
        history = self.invoke("--json", "pipeline", "history", "hr_payroll")
        (run,) = json.loads(history.stdout)
        return run

    def test_resume_with_another_pipelines_execution_id_is_refused(self, workspace):
        assert self.invoke("pipeline", "run", "hr_payroll").exit_code == EXIT_FAILED
        before = self.hr_run()

        result = self.invoke("pipeline", "resume", "sales_daily", before["execution_id"])
        assert result.exit_code == EXIT_FAILED
        assert "the execution is not a run of this pipeline" in result.stderr
        assert self.hr_run() == before
        assert MemorySink.buffer("sales_out") == []

    def test_logs_shows_the_per_task_breakdown(self, workspace):
        self.invoke("pipeline", "run", "hr_payroll")
        execution_id = self.hr_run()["execution_id"]

        result = self.invoke("pipeline", "logs", execution_id)
        assert result.exit_code == 0
        assert "record failed validation" in result.stdout, "the failing task's error"
        payload = json.loads(self.invoke("--json", "pipeline", "logs", execution_id).stdout)
        assert [(row["task"], row["status"]) for row in payload["task_runs"]] == [
            ("extract", "success"),
            ("load", "failed"),
            ("publish", "skipped"),
        ]
