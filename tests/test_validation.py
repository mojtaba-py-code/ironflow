"""Validation tests: individual rules and the enforcement engine."""

from __future__ import annotations

import pytest

from ironflow.config.models import ValidationRuleSpec, ValidationSpec
from ironflow.core.errors import ConfigurationError, ValidationError
from ironflow.core.types import RecordBatch, Severity
from ironflow.security import patterns
from ironflow.validation.engine import (
    REJECT_REASON_KEY,
    ValidationEngine,
)
from ironflow.validation.rules import RULE_REGISTRY, build_rule, rules_from_schema


def rule(rule_type: str, **options):
    return build_rule(ValidationRuleSpec.model_validate({"type": rule_type, **options}))


def check(rule_obj, record: dict) -> list:
    return rule_obj.validate(record, 0)


class TestRuleRegistry:
    def test_expected_rules_are_registered(self):
        for name in (
            "not_null",
            "unique",
            "type",
            "range",
            "length",
            "regex",
            "in_set",
            "expression",
            "comparison",
            "email",
            "date_format",
            "sequence",
        ):
            assert name in RULE_REGISTRY, f"{name} not registered"

    def test_unknown_rule_is_rejected(self):
        with pytest.raises(Exception, match="unknown validation rule type"):
            rule("no_such_rule")


class TestPresenceRules:
    @pytest.mark.parametrize("value", [None, "", "   "])
    def test_not_null_rejects_blank_values(self, value):
        assert check(rule("not_null", field="a"), {"a": value})

    def test_not_null_accepts_zero_and_false(self):
        """0 and False are values, not absences."""
        assert not check(rule("not_null", field="a"), {"a": 0})
        assert not check(rule("not_null", field="a"), {"a": False})

    def test_not_null_can_allow_empty_strings(self):
        assert not check(rule("not_null", field="a", allow_empty_string=True), {"a": ""})

    def test_not_null_requires_a_field(self):
        with pytest.raises(ConfigurationError, match="requires a 'field'"):
            check(rule("not_null"), {})

    def test_required_columns_detects_a_dropped_column(self):
        violations = check(rule("required_columns", columns=["a", "b"]), {"a": 1})
        assert violations and "b" in violations[0].message


class TestTypeAndRangeRules:
    @pytest.mark.parametrize(
        ("value", "expected", "valid"),
        [
            (42, "integer", True),
            ("42", "integer", True),
            ("42.9", "integer", False),
            ("abc", "integer", False),
            (True, "integer", False),
            (3.5, "float", True),
            ("3.5", "float", True),
            (True, "boolean", True),
            ("yes", "boolean", True),
            ("maybe", "boolean", False),
            ("2026-01-01", "date", True),
            ("not-a-date", "date", False),
            ({"a": 1}, "json", True),
        ],
    )
    def test_type_rule(self, value, expected, valid):
        violations = check(rule("type", field="v", expected=expected), {"v": value})
        assert (not violations) is valid

    def test_type_rule_ignores_nulls(self):
        assert not check(rule("type", field="v", expected="integer"), {"v": None})

    def test_strict_mode_rejects_convertible_strings(self):
        assert check(rule("type", field="v", expected="integer", strict=True), {"v": "42"})

    def test_range_bounds(self):
        rule_obj = rule("range", field="v", min=0, max=100)
        assert not check(rule_obj, {"v": 50})
        assert check(rule_obj, {"v": -1})
        assert check(rule_obj, {"v": 101})
        assert not check(rule_obj, {"v": 0}), "inclusive by default"

    def test_range_exclusive(self):
        assert check(rule("range", field="v", min=0, exclusive=True), {"v": 0})

    def test_range_flags_non_numeric_values(self):
        violations = check(rule("range", field="v", min=0), {"v": "abc"})
        assert violations and "not numeric" in violations[0].message

    def test_length(self):
        rule_obj = rule("length", field="v", min=2, max=4)
        assert not check(rule_obj, {"v": "abc"})
        assert check(rule_obj, {"v": "a"})
        assert check(rule_obj, {"v": "abcde"})
        assert check(rule("length", field="v", exact=3), {"v": "ab"})


class TestFormatRules:
    def test_regex(self):
        rule_obj = rule("regex", field="v", pattern=r"[A-Z]{2}\d{4}")
        assert not check(rule_obj, {"v": "AB1234"})
        assert check(rule_obj, {"v": "ab1234"})

    def test_regex_is_full_match_by_default(self):
        assert check(rule("regex", field="v", pattern="abc"), {"v": "xxabcxx"})
        assert not check(
            rule("regex", field="v", pattern="abc", full_match=False), {"v": "xxabcxx"}
        )

    def test_invalid_regex_is_rejected_at_construction(self):
        with pytest.raises(ConfigurationError, match="invalid regular expression"):
            rule("regex", field="v", pattern="[unclosed")

    def test_overlong_regex_is_rejected(self):
        with pytest.raises(ConfigurationError, match="too long"):
            rule("regex", field="v", pattern="a" * 600)

    def test_a_value_the_pattern_cannot_decide_in_time_is_rejected(self, monkeypatch):
        """A backtracking pattern used to pin a core; now the record fails the rule.

        ``(a+)+$`` against 26 characters took 49 seconds under ``re``, and a
        length cap was the only guard on a pattern written in a pipeline file.
        """
        monkeypatch.setattr(patterns, "MATCH_TIMEOUT_SECONDS", 0.02)
        rule_obj = rule("regex", field="v", pattern="(e|ee)+$", full_match=False)
        violations = check(rule_obj, {"v": "e" * 60 + "!"})
        assert len(violations) == 1
        assert "time budget" in violations[0].message
        assert violations[0].severity is Severity.ERROR

    def test_email(self):
        assert not check(rule("email", field="v"), {"v": "a@b.com"})
        assert check(rule("email", field="v"), {"v": "not-an-email"})

    def test_uuid(self):
        assert not check(rule("uuid", field="v"), {"v": "123e4567-e89b-12d3-a456-426614174000"})
        assert check(rule("uuid", field="v"), {"v": "nope"})

    def test_date_format(self):
        assert not check(rule("date_format", field="v"), {"v": "2026-01-15"})
        assert check(rule("date_format", field="v", format="%d/%m/%Y"), {"v": "2026-01-15"})

    def test_date_bounds(self):
        rule_obj = rule("date_format", field="v", min_date="2026-01-01", max_date="2026-12-31")
        assert not check(rule_obj, {"v": "2026-06-01"})
        assert check(rule_obj, {"v": "2025-06-01"})


class TestSetAndCrossFieldRules:
    def test_in_set(self):
        rule_obj = rule("in_set", field="v", values=["EUR", "USD"])
        assert not check(rule_obj, {"v": "EUR"})
        assert check(rule_obj, {"v": "GBP"})

    def test_in_set_case_insensitive(self):
        rule_obj = rule("in_set", field="v", values=["EUR"], case_sensitive=False)
        assert not check(rule_obj, {"v": "eur"})

    def test_in_set_requires_a_list(self):
        with pytest.raises(ConfigurationError, match="must be a list"):
            rule("in_set", field="v", values="EUR")

    def test_unique_detects_duplicates_across_records(self):
        rule_obj = rule("unique", field="id")
        assert not rule_obj.validate({"id": 1}, 0)
        assert not rule_obj.validate({"id": 2}, 1)
        assert rule_obj.validate({"id": 1}, 2)

    def test_unique_over_a_composite_key(self):
        rule_obj = rule("unique", columns=["a", "b"])
        assert not rule_obj.validate({"a": 1, "b": 1}, 0)
        assert not rule_obj.validate({"a": 1, "b": 2}, 1)
        assert rule_obj.validate({"a": 1, "b": 1}, 2)

    def test_unique_resets_between_runs(self):
        rule_obj = rule("unique", field="id")
        rule_obj.validate({"id": 1}, 0)
        rule_obj.reset()
        assert not rule_obj.validate({"id": 1}, 0)

    def test_unique_degrades_gracefully_past_its_cap(self, caplog):
        rule_obj = rule("unique", field="id", max_tracked=2)
        for i in range(5):
            rule_obj.validate({"id": i}, i)
        with caplog.at_level("WARNING"):
            rule_obj.validate({"id": 0}, 6)
        assert "max_tracked" in caplog.text

    def test_expression_rule(self):
        rule_obj = rule("expression", expression="amount > 0", message="amount must be positive")
        assert not check(rule_obj, {"amount": 5})
        violations = check(rule_obj, {"amount": -1})
        assert violations[0].message == "amount must be positive"

    def test_comparison_rule(self):
        rule_obj = rule("comparison", left="start", right="end", operator="<=")
        assert not check(rule_obj, {"start": 1, "end": 2})
        assert check(rule_obj, {"start": 5, "end": 2})

    def test_comparison_rejects_unknown_operators(self):
        with pytest.raises(ConfigurationError, match="unsupported comparison operator"):
            check(rule("comparison", left="a", right="b", operator="~="), {"a": 1, "b": 1})

    def test_sequence_detects_out_of_order_records(self):
        rule_obj = rule("sequence", field="ts")
        assert not rule_obj.validate({"ts": 1}, 0)
        assert not rule_obj.validate({"ts": 2}, 1)
        assert rule_obj.validate({"ts": 1}, 2)


class TestRuleRobustness:
    def test_a_rule_that_raises_downgrades_to_a_warning(self, caplog):
        """A broken rule must not abort a million-row load."""
        rule_obj = rule("range", field="v", min=0)
        rule_obj.check = lambda *_: (_ for _ in ()).throw(RuntimeError("boom"))
        with caplog.at_level("ERROR"):
            violations = rule_obj.validate({"v": 1}, 0)
        assert violations[0].severity is Severity.WARNING


class TestSchemaExpansion:
    def test_schema_expands_into_rules(self):
        specs = rules_from_schema(
            {
                "id": {"type": "integer", "nullable": False, "unique": True},
                "amount": {"type": "float", "min": 0},
                "code": {"values": ["A", "B"], "max_length": 1},
            }
        )
        types = [s.type for s in specs]
        assert "not_null" in types
        assert "unique" in types
        assert "range" in types
        assert "in_set" in types
        assert "length" in types

    def test_shorthand_type_only(self):
        specs = rules_from_schema({"id": "integer"})
        assert specs[0].type == "type"
        assert specs[0].options["expected"] == "integer"


class TestValidationEngine:
    def _engine(self, **overrides) -> ValidationEngine:
        spec = ValidationSpec.model_validate(
            {
                "rules": [
                    {"type": "not_null", "field": "id"},
                    {"type": "range", "field": "amount", "min": 0},
                ],
                **overrides,
            }
        )
        return ValidationEngine(spec, task_name="t1")

    def test_splits_accepted_from_rejected(self, context):
        engine = self._engine()
        outcome = engine.validate_batch(
            RecordBatch(
                [{"id": 1, "amount": 5}, {"id": None, "amount": 5}, {"id": 3, "amount": -1}]
            ),
            context,
        )
        assert len(outcome.accepted) == 1
        assert outcome.rejected_count == 2

    def test_quarantined_records_carry_the_reason(self, context):
        engine = self._engine(on_violation="quarantine")
        outcome = engine.validate_batch(RecordBatch([{"id": None, "amount": 5}]), context)
        assert "not_null" in outcome.rejected[0][REJECT_REASON_KEY]

    def test_fail_policy_aborts_immediately(self, context):
        engine = self._engine(on_violation="fail")
        with pytest.raises(ValidationError, match="policy is 'fail'"):
            engine.validate_batch(RecordBatch([{"id": None, "amount": 5}]), context)

    def test_drop_policy_discards_without_storing(self, context):
        engine = self._engine(on_violation="drop")
        outcome = engine.validate_batch(RecordBatch([{"id": None, "amount": 5}]), context)
        assert len(outcome.accepted) == 0
        assert outcome.rejected == []

    def test_warning_severity_does_not_reject(self, context):
        spec = ValidationSpec.model_validate(
            {"rules": [{"type": "not_null", "field": "id", "severity": "warning"}]}
        )
        engine = ValidationEngine(spec)
        outcome = engine.validate_batch(RecordBatch([{"id": None}]), context)
        assert len(outcome.accepted) == 1
        assert outcome.warnings == 1

    def test_disabled_engine_passes_everything(self, context):
        engine = ValidationEngine(ValidationSpec(enabled=False))
        outcome = engine.validate_batch(RecordBatch([{"id": None}]), context)
        assert len(outcome.accepted) == 1

    def test_max_errors_breaker(self, context):
        engine = self._engine(max_errors=1)
        with pytest.raises(ValidationError, match="max_errors"):
            engine.validate_batch(RecordBatch([{"id": None}, {"id": None}]), context)

    def test_error_rate_breaker_waits_for_warm_up(self, context):
        """A single bad first row must not trip a 5% threshold."""
        engine = self._engine(max_error_rate=0.05)
        engine.validate_batch(RecordBatch([{"id": None, "amount": 1}]), context)  # 100% but n=1
        good = [{"id": i, "amount": 1} for i in range(150)]
        engine.validate_batch(RecordBatch(good), context)
        assert engine.summary.records_rejected == 1

    def test_error_rate_breaker_fires_after_warm_up(self, context):
        engine = self._engine(max_error_rate=0.05)
        bad = [{"id": None, "amount": 1} for _ in range(150)]
        with pytest.raises(ValidationError, match="max_error_rate"):
            engine.validate_batch(RecordBatch(bad), context)

    def test_schema_block_generates_rules(self, context):
        spec = ValidationSpec.model_validate(
            {"schema": {"id": {"type": "integer", "nullable": False}}}
        )
        engine = ValidationEngine(spec)
        outcome = engine.validate_batch(RecordBatch([{"id": None}, {"id": 5}]), context)
        assert len(outcome.accepted) == 1

    def test_summary_reports_by_rule_and_field(self, context):
        engine = self._engine()
        engine.validate_batch(
            RecordBatch([{"id": None, "amount": -1}, {"id": 2, "amount": -5}]), context
        )
        report = engine.report()
        assert report["by_rule"]["range"] == 2
        assert report["by_rule"]["not_null"] == 1
        assert report["by_field"]["amount"] == 2
        assert 0 < report["error_rate"] <= 1

    def test_samples_are_bounded(self, context):
        engine = self._engine()
        engine.validate_batch(RecordBatch([{"id": None} for _ in range(200)]), context)
        assert len(engine.report()["samples"]) == 50

    def test_metrics_are_emitted(self, context, metrics):
        engine = self._engine()
        engine.validate_batch(RecordBatch([{"id": None, "amount": 1}]), context)
        labels = {"pipeline": context.pipeline_id, "task": context.task_id}
        assert metrics.get_counter("validation_violations_total", labels) == 1
        assert metrics.get_counter("rows_quarantined_total", labels) == 1

    def test_reset_clears_state(self, context):
        engine = self._engine()
        engine.validate_batch(RecordBatch([{"id": 1, "amount": 1}]), context)
        engine.reset()
        assert engine.summary.records_checked == 0
