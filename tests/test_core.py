"""Tests for the domain core: types, errors, retry, registry, events, context."""

from __future__ import annotations

import threading

import pytest

from ironflow.core.context import CancellationToken, ExecutionContext, current_log_context, new_id
from ironflow.core.errors import (
    ConfigurationError,
    IronFlowError,
    RegistryError,
    RetryExceededError,
    ValidationError,
)
from ironflow.core.errors import ConnectionError as IFConnectionError
from ironflow.core.events import Event, EventBus, EventType
from ironflow.core.registry import ComponentRegistry
from ironflow.core.retry import CircuitBreaker, RetryPolicy, call_with_retry
from ironflow.core.types import (
    DatasetSchema,
    FieldSchema,
    FieldType,
    RecordBatch,
    RunStatus,
    Severity,
    StageMetrics,
    batched,
    infer_schema,
)


class TestErrors:
    def test_error_carries_code_and_context(self):
        error = ConfigurationError("bad", context={"key": "value"})
        payload = error.to_dict()
        assert payload["code"] == "CONFIG_INVALID"
        assert payload["context"] == {"key": "value"}
        assert not payload["retryable"]

    def test_with_context_chains(self):
        error = ConfigurationError("bad").with_context(task="t1")
        assert error.context["task"] == "t1"

    def test_connection_errors_are_retryable_by_default(self):
        assert IFConnectionError("down").retryable is True
        assert ConfigurationError("typo").retryable is False

    def test_validation_error_truncates_violation_list(self):
        error = ValidationError("bad", violations=[{"i": i} for i in range(100)])
        payload = error.to_dict()
        assert payload["violation_count"] == 100
        assert len(payload["violations"]) == 50

    def test_every_error_derives_from_the_base(self):
        for cls in (ConfigurationError, IFConnectionError, ValidationError, RegistryError):
            assert issubclass(cls, IronFlowError)


class TestTypes:
    def test_run_status_terminality(self):
        assert RunStatus.SUCCESS.is_terminal
        assert not RunStatus.RUNNING.is_terminal
        assert RunStatus.FAILED.is_failure
        assert not RunStatus.SUCCESS.is_failure

    def test_severity_blocks_only_on_error(self):
        assert Severity.ERROR.blocks_record
        assert not Severity.WARNING.blocks_record

    def test_batch_columns_preserve_first_seen_order(self):
        batch = RecordBatch([{"b": 1, "a": 2}, {"c": 3, "a": 4}])
        assert batch.columns() == ("b", "a", "c")

    def test_batch_replace_keeps_lineage(self):
        original = RecordBatch([{"a": 1}], sequence=7, source="src", metadata={"k": "v"})
        replaced = original.replace([{"a": 2}])
        assert replaced.sequence == 7
        assert replaced.source == "src"
        assert replaced.metadata == {"k": "v"}
        assert original.records == [{"a": 1}]  # not mutated

    def test_batched_chunks_and_rejects_bad_size(self):
        chunks = list(batched([{"i": i} for i in range(7)], 3))
        assert [len(c) for c in chunks] == [3, 3, 1]
        assert [c.sequence for c in chunks] == [0, 1, 2]
        with pytest.raises(ValueError, match="positive"):
            list(batched([], 0))

    @pytest.mark.parametrize(
        ("values", "expected"),
        [
            ([1, 2, 3], FieldType.INTEGER),
            ([1.5], FieldType.FLOAT),
            ([True, False], FieldType.BOOLEAN),
            (["a"], FieldType.STRING),
            ([{"a": 1}], FieldType.JSON),
            ([1, 2.5], FieldType.FLOAT),
            ([1, "a"], FieldType.STRING),
            ([None], FieldType.UNKNOWN),
        ],
    )
    def test_schema_inference(self, values, expected):
        schema = infer_schema([{"c": v} for v in values])
        assert schema.get("c").type is expected

    def test_bool_is_not_inferred_as_integer(self):
        # bool is a subclass of int; the check order must catch it first.
        assert infer_schema([{"c": True}]).get("c").type is FieldType.BOOLEAN

    def test_schema_diff_classifies_changes(self):
        before = DatasetSchema(
            (FieldSchema("a", FieldType.INTEGER), FieldSchema("b", FieldType.STRING))
        )
        after = DatasetSchema(
            (FieldSchema("a", FieldType.STRING), FieldSchema("c", FieldType.INTEGER))
        )
        diff = before.diff(after)
        assert diff.added == ("c",)
        assert diff.removed == ("b",)
        assert diff.type_changed == ("a",)
        assert not diff.is_backward_compatible

    def test_additive_diff_is_backward_compatible(self):
        before = DatasetSchema((FieldSchema("a", FieldType.INTEGER),))
        after = DatasetSchema(
            (FieldSchema("a", FieldType.INTEGER), FieldSchema("b", FieldType.STRING))
        )
        assert before.diff(after).is_backward_compatible

    def test_unknown_type_never_counts_as_a_type_change(self):
        before = DatasetSchema((FieldSchema("a", FieldType.UNKNOWN),))
        after = DatasetSchema((FieldSchema("a", FieldType.INTEGER),))
        assert before.diff(after).type_changed == ()

    def test_stage_metrics_arithmetic(self):
        metrics = StageMetrics(rows_in=100, rows_out=90, rows_failed=10, duration_seconds=2.0)
        assert metrics.throughput_rows_per_second == 45.0
        assert metrics.success_rate == 0.9
        metrics.merge(StageMetrics(rows_in=50, rows_out=50, duration_seconds=1.0))
        assert metrics.rows_in == 150
        assert metrics.duration_seconds == 3.0

    def test_success_rate_of_empty_stage_is_one(self):
        assert StageMetrics().success_rate == 1.0


class TestRegistry:
    def test_register_and_create(self):
        registry: ComponentRegistry[dict] = ComponentRegistry("thing")
        registry.register("alpha", dict, aliases=("a",))
        assert registry.create("alpha") == {}
        assert registry.create("A") == {}  # normalised
        assert "alpha" in registry

    def test_hyphens_and_case_are_normalised(self):
        registry: ComponentRegistry[dict] = ComponentRegistry("thing")
        registry.register("my_thing", dict)
        assert "MY-THING" in registry

    def test_duplicate_registration_is_rejected(self):
        registry: ComponentRegistry[dict] = ComponentRegistry("thing")
        registry.register("alpha", dict)
        with pytest.raises(RegistryError, match="already registered"):
            registry.register("alpha", dict)
        registry.register("alpha", dict, replace=True)  # explicit replace is fine

    def test_unknown_component_lists_alternatives(self):
        registry: ComponentRegistry[dict] = ComponentRegistry("thing")
        registry.register("alpha", dict)
        with pytest.raises(RegistryError) as info:
            registry.get("beta")
        assert "alpha" in info.value.context["available"]

    def test_freeze_blocks_further_registration(self):
        registry: ComponentRegistry[dict] = ComponentRegistry("thing")
        registry.freeze()
        with pytest.raises(RegistryError, match="frozen"):
            registry.register("alpha", dict)

    def test_decorator_form(self):
        registry: ComponentRegistry[object] = ComponentRegistry("thing")

        @registry.register("noop")
        class Noop:
            pass

        assert isinstance(registry.create("noop"), Noop)


class TestRetry:
    def test_succeeds_without_retrying(self):
        calls = []
        result = call_with_retry(
            lambda: calls.append(1) or "ok", RetryPolicy(max_attempts=3), sleep=lambda _: None
        )
        assert result == "ok"
        assert len(calls) == 1

    def test_retries_transient_errors_then_succeeds(self):
        attempts = {"n": 0}

        def flaky():
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise IFConnectionError("temporary")
            return "recovered"

        result = call_with_retry(
            flaky, RetryPolicy(max_attempts=3, initial_delay=0), sleep=lambda _: None
        )
        assert result == "recovered"
        assert attempts["n"] == 3

    def test_does_not_retry_deterministic_errors(self):
        attempts = {"n": 0}

        def broken():
            attempts["n"] += 1
            raise ConfigurationError("typo in the config")

        with pytest.raises(ConfigurationError):
            call_with_retry(
                broken, RetryPolicy(max_attempts=5, initial_delay=0), sleep=lambda _: None
            )
        assert attempts["n"] == 1, "a non-retryable error must be attempted exactly once"

    def test_exhausting_attempts_raises_retry_exceeded(self):
        with pytest.raises(RetryExceededError) as info:
            call_with_retry(
                lambda: (_ for _ in ()).throw(IFConnectionError("down")),
                RetryPolicy(max_attempts=3, initial_delay=0),
                sleep=lambda _: None,
            )
        assert info.value.attempts == 3
        assert isinstance(info.value.__cause__, IFConnectionError)

    def test_backoff_grows_and_is_capped(self):
        policy = RetryPolicy(initial_delay=1, multiplier=2, max_delay=5, jitter=False)
        assert [policy.delay_for(n) for n in (1, 2, 3, 4)] == [1, 2, 4, 5]

    def test_jitter_stays_within_the_cap(self):
        policy = RetryPolicy(initial_delay=1, multiplier=2, max_delay=8, jitter=True)
        assert all(0 <= policy.delay_for(3) <= 4 for _ in range(50))

    def test_invalid_policies_are_rejected(self):
        with pytest.raises(ValueError, match="max_attempts"):
            RetryPolicy(max_attempts=0)
        with pytest.raises(ValueError, match="multiplier"):
            RetryPolicy(multiplier=0.5)

    def test_circuit_breaker_opens_and_fails_fast(self):
        breaker = CircuitBreaker("db", failure_threshold=2, reset_timeout=60)
        breaker.record_failure()
        assert not breaker.is_open
        breaker.record_failure()
        assert breaker.is_open
        with pytest.raises(IFConnectionError, match="circuit breaker open"):
            breaker.raise_if_open()

    def test_circuit_breaker_closes_on_success(self):
        breaker = CircuitBreaker("db", failure_threshold=1, reset_timeout=60)
        breaker.record_failure()
        assert breaker.is_open
        breaker.record_success()
        assert not breaker.is_open


class TestEvents:
    def test_subscribe_and_publish(self):
        bus = EventBus()
        received = []
        bus.subscribe(EventType.TASK_STARTED, received.append)
        bus.emit(EventType.TASK_STARTED, pipeline_id="p", execution_id="e", task_id="t")
        bus.emit(EventType.TASK_FAILED, pipeline_id="p", execution_id="e")
        assert len(received) == 1
        assert received[0].task_id == "t"

    def test_global_subscriber_receives_everything(self):
        bus = EventBus()
        received = []
        bus.subscribe(None, received.append)
        bus.emit(EventType.TASK_STARTED, pipeline_id="p", execution_id="e")
        bus.emit(EventType.TASK_FAILED, pipeline_id="p", execution_id="e")
        assert len(received) == 2

    def test_a_failing_subscriber_does_not_break_publishing(self):
        bus = EventBus()
        delivered = []

        def broken(_event):
            raise RuntimeError("subscriber exploded")

        bus.subscribe(None, broken)
        bus.subscribe(None, delivered.append)
        bus.emit(EventType.TASK_STARTED, pipeline_id="p", execution_id="e")
        assert len(delivered) == 1, "a broken subscriber must not block the others"

    def test_unsubscribe(self):
        bus = EventBus()
        received = []
        unsubscribe = bus.subscribe(EventType.TASK_STARTED, received.append)
        unsubscribe()
        bus.emit(EventType.TASK_STARTED, pipeline_id="p", execution_id="e")
        assert received == []

    def test_history_is_bounded(self):
        bus = EventBus(history_limit=5)
        for _ in range(20):
            bus.emit(EventType.BATCH_PROCESSED, pipeline_id="p", execution_id="e")
        assert len(bus.history(limit=100)) == 5

    def test_event_serialisation(self):
        event = Event(
            type=EventType.TASK_FAILED, pipeline_id="p", execution_id="e", payload={"a": 1}
        )
        payload = event.to_dict()
        assert payload["type"] == "task.failed"
        assert payload["payload"] == {"a": 1}


class TestContext:
    def test_ids_are_unique(self):
        assert len({new_id() for _ in range(1000)}) == 1000

    def test_for_task_shares_state_and_cancellation(self):
        parent = ExecutionContext(pipeline_id="p")
        child = parent.for_task("t1")
        assert child.execution_id == parent.execution_id
        assert child.task_id == "t1"
        child.state["produced"] = 10
        assert parent.state["produced"] == 10
        parent.cancellation.cancel("stop")
        assert child.cancellation.is_cancelled

    def test_bind_exposes_and_restores_log_context(self):
        context = ExecutionContext(pipeline_id="p", task_id="t")
        assert current_log_context()["pipeline_id"] == "-"
        with context.bind():
            fields = current_log_context()
            assert fields["pipeline_id"] == "p"
            assert fields["task_id"] == "t"
        assert current_log_context()["pipeline_id"] == "-"

    def test_cancellation_raises(self):
        from ironflow.core.errors import PipelineError

        token = CancellationToken()
        token.raise_if_cancelled()  # no-op
        token.cancel("operator stopped it")
        assert token.reason == "operator stopped it"
        with pytest.raises(PipelineError, match="operator stopped it"):
            token.raise_if_cancelled()

    def test_cancellation_is_visible_across_threads(self):
        token = CancellationToken()
        observed = []

        def worker():
            token.wait(timeout=2)
            observed.append(token.is_cancelled)

        thread = threading.Thread(target=worker)
        thread.start()
        token.cancel()
        thread.join(timeout=3)
        assert observed == [True]
