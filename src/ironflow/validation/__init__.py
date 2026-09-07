"""Data-quality validation: rules and the engine that enforces them."""

from __future__ import annotations

from ironflow.validation.engine import (
    REJECT_REASON_KEY,
    ValidationEngine,
    ValidationOutcome,
    ValidationSummary,
)
from ironflow.validation.rules import RULE_REGISTRY, Rule, build_rule, build_rules, rule

__all__ = [
    "REJECT_REASON_KEY",
    "RULE_REGISTRY",
    "Rule",
    "ValidationEngine",
    "ValidationOutcome",
    "ValidationSummary",
    "build_rule",
    "build_rules",
    "rule",
]
