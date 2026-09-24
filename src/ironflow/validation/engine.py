"""Validation engine: applies rules and enforces the violation policy.

The engine splits each batch into *accepted* and *rejected* records and decides
what happens to the rejects according to
:class:`~ironflow.core.types.OnViolation`:

``fail``
    Raise immediately.  Transactional sinks roll back, so the destination is
    left exactly as it was.  Correct for financial data where a partial load is
    worse than no load.
``quarantine``
    Route rejects to the task's ``reject_destination`` together with the reason.
    The default, because it keeps the pipeline moving while preserving every bad
    record for analysis - a dropped record is a record nobody will ever
    investigate.
``drop``
    Discard the record; it goes nowhere.
``warn``
    Keep the record in the load and report its violations as warnings.  It is
    neither quarantined nor counted towards the circuit breakers: choosing
    ``warn`` is choosing to load the data anyway.

Two independent circuit breakers stop a run whose data has gone systemically
wrong: an absolute reject count (``max_errors``) and a reject *rate*
(``max_error_rate``).  The rate is only evaluated after a warm-up of 100 records,
otherwise a single bad first row trips a 5 % threshold.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from ironflow.config.models import ValidationSpec
from ironflow.core.context import ExecutionContext
from ironflow.core.errors import ValidationError
from ironflow.core.events import EventType
from ironflow.core.types import OnViolation, Record, RecordBatch, Severity, Violation
from ironflow.observability.metrics import Metric
from ironflow.validation.rules import Rule, build_rules, rules_from_schema

logger = logging.getLogger(__name__)

#: Records processed before the error-rate breaker is armed.
RATE_WARMUP_RECORDS = 100

#: Key added to quarantined records carrying the reasons.
REJECT_REASON_KEY = "_ironflow_violations"
REJECT_INDEX_KEY = "_ironflow_record_index"


@dataclass(slots=True)
class ValidationOutcome:
    """Result of validating one batch."""

    accepted: RecordBatch
    rejected: list[Record] = field(default_factory=list)
    violations: list[Violation] = field(default_factory=list)
    warnings: int = 0

    @property
    def rejected_count(self) -> int:
        return len(self.rejected)


@dataclass(slots=True)
class ValidationSummary:
    """Aggregate statistics across a whole task."""

    records_checked: int = 0
    records_rejected: int = 0
    violations_total: int = 0
    by_rule: dict[str, int] = field(default_factory=dict)
    by_field: dict[str, int] = field(default_factory=dict)
    by_severity: dict[str, int] = field(default_factory=dict)
    samples: list[dict[str, Any]] = field(default_factory=list)

    @property
    def error_rate(self) -> float:
        if not self.records_checked:
            return 0.0
        return self.records_rejected / self.records_checked

    @property
    def pass_rate(self) -> float:
        return 1.0 - self.error_rate

    def record(self, violation: Violation) -> None:
        self.violations_total += 1
        self.by_rule[violation.rule] = self.by_rule.get(violation.rule, 0) + 1
        if violation.field:
            self.by_field[violation.field] = self.by_field.get(violation.field, 0) + 1
        key = violation.severity.value
        self.by_severity[key] = self.by_severity.get(key, 0) + 1
        # Keep a bounded sample: enough to diagnose, small enough to store in
        # the run-history row without bloating the database.
        if len(self.samples) < 50:
            self.samples.append(violation.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "records_checked": self.records_checked,
            "records_rejected": self.records_rejected,
            "violations_total": self.violations_total,
            "error_rate": round(self.error_rate, 6),
            "pass_rate": round(self.pass_rate, 6),
            "by_rule": dict(sorted(self.by_rule.items(), key=lambda kv: -kv[1])),
            "by_field": dict(sorted(self.by_field.items(), key=lambda kv: -kv[1])),
            "by_severity": self.by_severity,
            "samples": self.samples,
        }


class ValidationEngine:
    """Applies a :class:`ValidationSpec` to a stream of batches."""

    def __init__(self, spec: ValidationSpec | None, *, task_name: str = "") -> None:
        self.spec = spec or ValidationSpec(enabled=False)
        self.task_name = task_name
        self.summary = ValidationSummary()
        self._rules: list[Rule] = []
        if self.spec.enabled:
            specs = list(self.spec.rules)
            if self.spec.schema_:
                # Schema-derived rules run first: a type failure explains a
                # downstream business-rule failure, so report it first.
                specs = rules_from_schema(self.spec.schema_) + specs
            self._rules = build_rules(specs)
        self._global_index = 0

    @property
    def enabled(self) -> bool:
        return self.spec.enabled and bool(self._rules)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    def reset(self) -> None:
        """Clear stateful rules and counters between runs."""
        for rule in self._rules:
            rule.reset()
        self.summary = ValidationSummary()
        self._global_index = 0

    def validate_batch(self, batch: RecordBatch, context: ExecutionContext) -> ValidationOutcome:
        """Validate one batch and apply the violation policy."""
        if not self.enabled:
            self.summary.records_checked += len(batch)
            return ValidationOutcome(accepted=batch)

        accepted: list[Record] = []
        rejected: list[Record] = []
        all_violations: list[Violation] = []
        warnings = 0

        for record in batch.records:
            index = self._global_index
            self._global_index += 1

            violations: list[Violation] = []
            for rule in self._rules:
                violations.extend(rule.validate(record, index))

            for violation in violations:
                self.summary.record(violation)
            all_violations.extend(violations)

            blocking = [v for v in violations if v.severity.blocks_record]
            warnings += len(violations) - len(blocking)

            if blocking and self.spec.on_violation is OnViolation.WARN:
                # `warn` keeps the record: its violations are reported, and the
                # row is loaded like any other.  It used to be left out of the
                # load *and* routed to the rejects, which made `warn` a quieter
                # spelling of `quarantine` - rows an operator had chosen to keep
                # never reached the destination.
                warnings += len(blocking)
                accepted.append(record)
            elif blocking:
                self.summary.records_rejected += 1
                self._handle_rejection(record, blocking, rejected, index)
            else:
                accepted.append(record)

        self.summary.records_checked += len(batch)
        self._emit_metrics(context, all_violations, len(rejected))
        self._check_breakers(context)

        return ValidationOutcome(
            accepted=batch.replace(accepted),
            rejected=rejected,
            violations=all_violations,
            warnings=warnings,
        )

    def _handle_rejection(
        self,
        record: Record,
        violations: list[Violation],
        rejected: list[Record],
        index: int,
    ) -> None:
        policy = self.spec.on_violation
        if policy is OnViolation.FAIL:
            raise ValidationError(
                "record failed validation and the policy is 'fail'",
                violations=[v.to_dict() for v in violations],
                context={"task": self.task_name, "record_index": index},
            )
        if policy is OnViolation.QUARANTINE:
            # The reject carries the original columns plus the reasons, so the
            # quarantine table is directly actionable.
            rejected.append(
                {
                    **record,
                    REJECT_INDEX_KEY: index,
                    REJECT_REASON_KEY: "; ".join(f"[{v.rule}] {v.message}" for v in violations),
                }
            )
        # DROP: nothing to do - the record is simply not appended anywhere.
        # (WARN never gets here: the record is kept, in `validate_batch`.)

    def _emit_metrics(
        self, context: ExecutionContext, violations: list[Violation], rejected: int
    ) -> None:
        if context.metrics is None:
            return
        labels = {"pipeline": context.pipeline_id, "task": context.task_id}
        if violations:
            context.metrics.counter(
                Metric.VALIDATION_VIOLATIONS,
                len(violations),
                labels=labels,
                help="Data-quality violations detected.",
            )
        if rejected:
            context.metrics.counter(Metric.ROWS_QUARANTINED, rejected, labels=labels)

        if rejected and context.events is not None:
            context.events.emit(
                EventType.RECORDS_QUARANTINED,
                pipeline_id=context.pipeline_id,
                execution_id=context.execution_id,
                task_id=context.task_id,
                count=rejected,
                error_rate=round(self.summary.error_rate, 6),
            )

    def _check_breakers(self, context: ExecutionContext) -> None:
        """Abort the task when rejects exceed the configured tolerances."""
        limit = self.spec.max_errors
        if limit is not None and self.summary.records_rejected > limit:
            raise ValidationError(
                "rejected record count exceeded max_errors",
                violations=self.summary.samples,
                context={
                    "task": self.task_name,
                    "rejected": self.summary.records_rejected,
                    "max_errors": limit,
                },
            )

        if (
            self.spec.max_error_rate < 1.0
            and self.summary.records_checked >= RATE_WARMUP_RECORDS
            and self.summary.error_rate > self.spec.max_error_rate
        ):
            raise ValidationError(
                "reject rate exceeded max_error_rate",
                violations=self.summary.samples,
                context={
                    "task": self.task_name,
                    "error_rate": round(self.summary.error_rate, 4),
                    "max_error_rate": self.spec.max_error_rate,
                    "checked": self.summary.records_checked,
                },
            )

    def report(self) -> dict[str, Any]:
        """Data-quality report for the run history and the CLI."""
        return {
            "task": self.task_name,
            "enabled": self.enabled,
            "rules": self.rule_count,
            "policy": self.spec.on_violation.value,
            **self.summary.to_dict(),
        }


def severity_of(value: str) -> Severity:
    """Parse a severity name, defaulting to ``ERROR`` for unknown input."""
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.ERROR


__all__ = [
    "REJECT_INDEX_KEY",
    "REJECT_REASON_KEY",
    "ValidationEngine",
    "ValidationOutcome",
    "ValidationSummary",
]
