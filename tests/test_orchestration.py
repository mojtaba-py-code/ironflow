"""Tests for the task graph and the scheduler."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from ironflow.config.models import PipelineSpec, TaskSpec
from ironflow.core.errors import (
    CircularDependencyError,
    ConfigurationError,
    SchedulerError,
)
from ironflow.orchestration.dag import TaskGraph
from ironflow.orchestration.scheduler import CronExpression, Scheduler


def task(name: str, depends_on: list[str] | None = None) -> TaskSpec:
    return TaskSpec.model_validate(
        {
            "name": name,
            "depends_on": depends_on or [],
            "source": {"type": "memory"},
            "destination": {"type": "null"},
        }
    )


class TestTaskGraph:
    def test_linear_chain(self):
        graph = TaskGraph([task("a"), task("b", ["a"]), task("c", ["b"])])
        assert graph.levels == [["a"], ["b"], ["c"]]
        assert graph.depth == 3
        assert graph.max_width == 1

    def test_fan_out_becomes_one_level(self):
        graph = TaskGraph([task("root"), task("a", ["root"]), task("b", ["root"])])
        assert graph.levels == [["root"], ["a", "b"]]
        assert graph.max_width == 2

    def test_diamond(self):
        graph = TaskGraph([task("a"), task("b", ["a"]), task("c", ["a"]), task("d", ["b", "c"])])
        assert graph.levels == [["a"], ["b", "c"], ["d"]]

    def test_independent_tasks_run_together(self):
        graph = TaskGraph([task("a"), task("b"), task("c")])
        assert graph.levels == [["a", "b", "c"]]

    def test_ordering_is_deterministic(self):
        first = TaskGraph([task("z"), task("a"), task("m")]).levels
        second = TaskGraph([task("m"), task("z"), task("a")]).levels
        assert first == second == [["a", "m", "z"]]

    def test_cycle_is_reported_with_participants(self):
        specs = [task("a", ["c"]), task("b", ["a"]), task("c", ["b"])]
        with pytest.raises(CircularDependencyError) as info:
            TaskGraph(specs)
        assert set(info.value.context["tasks_in_cycle"]) == {"a", "b", "c"}

    def test_two_node_cycle(self):
        with pytest.raises(CircularDependencyError):
            TaskGraph([task("a", ["b"]), task("b", ["a"])])

    def test_unknown_dependency(self):
        with pytest.raises(ConfigurationError, match="unknown task"):
            TaskGraph([task("a", ["ghost"])])

    def test_empty_graph_is_rejected(self):
        with pytest.raises(ConfigurationError, match="at least one task"):
            TaskGraph([])

    def test_descendants_and_ancestors(self):
        graph = TaskGraph([task("a"), task("b", ["a"]), task("c", ["b"]), task("d", ["a"])])
        assert graph.descendants("a") == {"b", "c", "d"}
        assert graph.descendants("c") == set()
        assert graph.ancestors("c") == {"a", "b"}

    def test_subgraph_pulls_in_ancestors(self):
        """Running a task without its inputs would use stale data."""
        graph = TaskGraph([task("a"), task("b", ["a"]), task("c", ["b"]), task("d")])
        subgraph = graph.subgraph(["c"])
        assert set(subgraph.names) == {"a", "b", "c"}
        assert subgraph.levels == [["a"], ["b"], ["c"]]

    def test_subgraph_prunes_dangling_edges(self):
        graph = TaskGraph([task("a"), task("b"), task("c", ["a", "b"])])
        subgraph = graph.subgraph(["a"])
        assert set(subgraph.names) == {"a"}

    def test_subgraph_rejects_unknown_tasks(self):
        with pytest.raises(ConfigurationError, match="unknown task"):
            TaskGraph([task("a")]).subgraph(["ghost"])

    def test_iteration_is_topological(self):
        graph = TaskGraph([task("c", ["b"]), task("a"), task("b", ["a"])])
        assert [spec.name for spec in graph] == ["a", "b", "c"]

    def test_describe_and_mermaid(self):
        graph = TaskGraph([task("a"), task("b", ["a"])])
        described = graph.describe()
        assert described["tasks"] == 2
        assert {"from": "a", "to": "b"} in described["edges"]
        mermaid = graph.to_mermaid()
        assert "graph LR" in mermaid
        assert "t_a --> t_b" in mermaid

    def test_from_spec(self):
        spec = PipelineSpec.model_validate(
            {"name": "p", "tasks": [task("a").model_dump(), task("b", ["a"]).model_dump()]}
        )
        assert TaskGraph.from_spec(spec).size == 2

    def test_large_graph_orders_quickly(self):
        specs = [task("t0")] + [task(f"t{i}", [f"t{i - 1}"]) for i in range(1, 500)]
        graph = TaskGraph(specs)
        assert graph.depth == 500


class TestCronExpression:
    @pytest.mark.parametrize(
        ("expression", "moment", "matches"),
        [
            ("0 2 * * *", datetime(2026, 3, 1, 2, 0, tzinfo=UTC), True),
            ("0 2 * * *", datetime(2026, 3, 1, 3, 0, tzinfo=UTC), False),
            ("*/15 * * * *", datetime(2026, 3, 1, 5, 30, tzinfo=UTC), True),
            ("*/15 * * * *", datetime(2026, 3, 1, 5, 31, tzinfo=UTC), False),
            ("0 0 1 * *", datetime(2026, 3, 1, 0, 0, tzinfo=UTC), True),
            ("0 0 1 * *", datetime(2026, 3, 2, 0, 0, tzinfo=UTC), False),
            ("30 8 * * 1-5", datetime(2026, 3, 2, 8, 30, tzinfo=UTC), True),  # Monday
            ("30 8 * * 1-5", datetime(2026, 3, 7, 8, 30, tzinfo=UTC), False),  # Saturday
            ("0 0,12 * * *", datetime(2026, 3, 1, 12, 0, tzinfo=UTC), True),
        ],
    )
    def test_matches(self, expression, moment, matches):
        assert CronExpression(expression).matches(moment) is matches

    def test_day_and_weekday_are_or_ed(self):
        """Historical crontab semantics: either restriction firing is enough."""
        expression = CronExpression("0 0 1 * 0")  # 1st of the month OR Sunday
        assert expression.matches(datetime(2026, 4, 1, 0, 0, tzinfo=UTC))  # a Wednesday 1st
        assert expression.matches(datetime(2026, 4, 5, 0, 0, tzinfo=UTC))  # a Sunday

    def test_next_after(self):
        expression = CronExpression("0 2 * * *")
        nxt = expression.next_after(datetime(2026, 3, 1, 3, 0, tzinfo=UTC))
        assert nxt == datetime(2026, 3, 2, 2, 0, tzinfo=UTC)

    def test_next_after_is_strictly_after(self):
        expression = CronExpression("0 2 * * *")
        moment = datetime(2026, 3, 1, 2, 0, tzinfo=UTC)
        assert expression.next_after(moment) > moment

    def test_rare_schedule_still_resolves(self):
        """A 29 February schedule must not scan minute by minute for four years."""
        expression = CronExpression("0 0 29 2 *")
        nxt = expression.next_after(datetime(2026, 3, 1, 0, 0, tzinfo=UTC))
        assert nxt == datetime(2028, 2, 29, 0, 0, tzinfo=UTC)

    def test_invalid_expressions(self):
        for bad in ("0 2 * *", "99 * * * *", "* * * * 9", "bad"):
            with pytest.raises((ValueError, SchedulerError)):
                CronExpression(bad)


class TestScheduler:
    def _pipeline(self, name: str, **schedule) -> PipelineSpec:
        return PipelineSpec.model_validate(
            {
                "name": name,
                "tasks": [task("t").model_dump()],
                "schedule": schedule or {"interval_seconds": 60},
            }
        )

    def test_register_and_describe(self):
        scheduler = Scheduler(trigger=lambda spec: None)
        scheduler.register(self._pipeline("p", cron="0 2 * * *"))
        jobs = scheduler.describe()
        assert jobs[0]["pipeline"] == "p"
        assert jobs[0]["schedule"] == "0 2 * * *"

    def test_pipelines_without_a_schedule_are_ignored(self):
        scheduler = Scheduler(trigger=lambda spec: None)
        spec = PipelineSpec.model_validate({"name": "p", "tasks": [task("t").model_dump()]})
        assert scheduler.register(spec) is None

    def test_disabled_schedules_are_ignored(self):
        scheduler = Scheduler(trigger=lambda spec: None)
        assert scheduler.register(self._pipeline("p", interval_seconds=60, enabled=False)) is None

    def test_due_job_triggers(self):
        triggered = []
        scheduler = Scheduler(trigger=lambda spec: triggered.append(spec.name))
        job = scheduler.register(self._pipeline("p", interval_seconds=60))
        job.next_run = datetime.now(UTC) - timedelta(seconds=1)
        assert scheduler.tick() == ["p"]
        assert triggered == ["p"]

    def test_future_job_does_not_trigger(self):
        scheduler = Scheduler(trigger=lambda spec: pytest.fail("must not run"))
        job = scheduler.register(self._pipeline("p", interval_seconds=60))
        job.next_run = datetime.now(UTC) + timedelta(hours=1)
        assert scheduler.tick() == []

    def test_missed_runs_are_skipped_without_catchup(self, caplog):
        scheduler = Scheduler(trigger=lambda spec: pytest.fail("must not run"), misfire_grace=60)
        job = scheduler.register(self._pipeline("p", interval_seconds=60))
        job.next_run = datetime.now(UTC) - timedelta(hours=6)
        with caplog.at_level("WARNING"):
            assert scheduler.tick() == []
        assert "missed run" in caplog.text
        assert job.next_run > datetime.now(UTC) - timedelta(seconds=1)

    def test_overlapping_runs_are_skipped(self, caplog):
        triggered = []
        scheduler = Scheduler(
            trigger=lambda spec: triggered.append(spec.name),
            running_count=lambda name: 1,
        )
        job = scheduler.register(self._pipeline("p", interval_seconds=60))
        job.next_run = datetime.now(UTC) - timedelta(seconds=1)
        with caplog.at_level("WARNING"):
            scheduler.tick()
        assert triggered == [], "a second concurrent run would race on the watermark"
        assert "in flight" in caplog.text

    def test_concurrency_limit_above_one(self):
        triggered = []
        scheduler = Scheduler(
            trigger=lambda spec: triggered.append(spec.name), running_count=lambda name: 1
        )
        job = scheduler.register(self._pipeline("p", interval_seconds=60, max_concurrent_runs=2))
        job.next_run = datetime.now(UTC) - timedelta(seconds=1)
        scheduler.tick()
        assert triggered == ["p"]

    def test_a_failing_trigger_does_not_stop_the_scheduler(self, caplog):
        def explode(spec):
            raise RuntimeError("boom")

        scheduler = Scheduler(trigger=explode)
        job = scheduler.register(self._pipeline("p", interval_seconds=60))
        job.next_run = datetime.now(UTC) - timedelta(seconds=1)
        with caplog.at_level("ERROR"):
            assert scheduler.tick() == []
        assert job.failure_count == 1
        assert job.next_run > datetime.now(UTC), "the job must still be rescheduled"

    def test_interval_rolls_forward_past_missed_windows(self):
        scheduler = Scheduler(trigger=lambda spec: None)
        job = scheduler.register(self._pipeline("p", interval_seconds=60))
        now = datetime.now(UTC)
        job.last_run = now - timedelta(hours=5)
        job.advance(now)
        assert job.next_run > now

    def test_unregister(self):
        scheduler = Scheduler(trigger=lambda spec: None)
        scheduler.register(self._pipeline("p", interval_seconds=60))
        assert scheduler.unregister("p")
        assert scheduler.jobs() == []

    def test_start_and_stop(self):
        scheduler = Scheduler(trigger=lambda spec: None, poll_interval=1.0)
        scheduler.register(self._pipeline("p", interval_seconds=60))
        scheduler.start()
        assert scheduler.is_running
        scheduler.stop(timeout=5)
        assert not scheduler.is_running
