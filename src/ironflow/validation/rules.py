"""Data-quality rules.

Each rule is a small object that inspects one record and returns zero or more
:class:`~ironflow.core.types.Violation` objects.  Keeping them independent means
a rule can be unit-tested in three lines and that adding one never touches the
engine.

Rules are *stateless* with one deliberate exception: :class:`UniqueRule` and
:class:`SequenceRule` have to remember what they have seen.  They expose
:meth:`reset` so the engine can clear that state between runs, and they bound
their memory with an explicit cap - a uniqueness check over 200 million rows
would otherwise quietly become an OOM.

Severity drives behaviour: ``ERROR`` rejects the record, ``WARNING`` and ``INFO``
annotate it and let it through.  That split is what allows a pipeline to enforce
"orders must have a positive amount" while merely reporting "country code is not
ISO-3166".
"""

from __future__ import annotations

import abc
import logging
import re
from collections.abc import Callable, Iterable, Mapping
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any, ClassVar

from ironflow.config.models import ValidationRuleSpec
from ironflow.core.errors import ConfigurationError, TransformationError
from ironflow.core.registry import ComponentRegistry
from ironflow.core.types import FieldType, Record, Severity, Violation
from ironflow.expressions import compile_expression, record_scope
from ironflow.security.patterns import compile_untrusted

logger = logging.getLogger(__name__)

#: Cap on remembered keys for stateful rules.
MAX_TRACKED_KEYS = 5_000_000

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class Rule(abc.ABC):
    """Base class for validation rules."""

    #: Registered rule name.
    rule_type: str = "base"

    def __init__(self, spec: ValidationRuleSpec) -> None:
        self.spec = spec
        self.field = spec.field
        self.severity = spec.severity
        self.name = spec.type

    @abc.abstractmethod
    def check(self, record: Record, index: int) -> list[Violation]:
        """Return the violations this record triggers (empty means clean)."""
        raise NotImplementedError

    def validate(self, record: Record, index: int) -> list[Violation]:
        """Public entry point.  Bad *data* never raises; bad *configuration* does.

        The distinction matters.  An unexpected runtime error on one record is
        isolated so a single malformed row cannot abort a million-row load.  A
        :class:`ConfigurationError` is deterministic - it will fire identically
        on every record - so swallowing it would bury a misconfigured rule under
        a million warnings while the pipeline reports success.
        """
        try:
            return self.check(record, index)
        except ConfigurationError:
            raise
        except Exception as exc:
            logger.error("rule %r raised on record %d", self.name, index, exc_info=True)
            return [
                self.violation(
                    f"rule raised an internal error: {type(exc).__name__}",
                    index,
                    severity=Severity.WARNING,
                )
            ]

    def reset(self) -> None:
        """Clear per-run state.  No-op for stateless rules."""

    def violation(self, message: str, index: int, *, severity: Severity | None = None) -> Violation:
        return Violation(
            rule=self.name,
            field=self.field,
            message=self.spec.message or message,
            severity=severity or self.severity,
            record_index=index,
        )

    def option(self, key: str, default: Any = None, *, required: bool = False) -> Any:
        value = self.spec.options.get(key, default)
        if required and value is None:
            raise ConfigurationError(
                f"validation rule {self.name!r} requires option {key!r}",
                context={"rule": self.name},
            )
        return value

    def require_field(self) -> str:
        if not self.field:
            raise ConfigurationError(
                f"validation rule {self.name!r} requires a 'field'", context={"rule": self.name}
            )
        return self.field


RULE_REGISTRY: ComponentRegistry[Rule] = ComponentRegistry("validation rule")


def rule(name: str, *aliases: str) -> Any:
    """Class decorator registering a rule implementation."""

    def decorator(cls: type[Rule]) -> type[Rule]:
        cls.rule_type = name
        RULE_REGISTRY.register(name, cls, aliases=aliases)
        return cls

    return decorator


def _is_blank(value: Any) -> bool:
    return value is None or (isinstance(value, str) and not value.strip())


# --------------------------------------------------------------------------- #
# Presence
# --------------------------------------------------------------------------- #
@rule("not_null", "required")
class NotNullRule(Rule):
    """The field must be present and not null/blank.

    Options: ``allow_empty_string`` (default false).
    """

    def check(self, record: Record, index: int) -> list[Violation]:
        field = self.require_field()
        value = record.get(field)
        allow_empty = bool(self.option("allow_empty_string", False))
        missing = value is None if allow_empty else _is_blank(value)
        if missing:
            return [self.violation(f"'{field}' is required but was null or empty", index)]
        return []


@rule("required_columns", "schema_columns")
class RequiredColumnsRule(Rule):
    """Every named column must exist on the record.

    Options: ``columns`` (list, required).  Catches an upstream export that
    silently dropped a column - the failure that produces a table full of NULLs.
    """

    def check(self, record: Record, index: int) -> list[Violation]:
        columns: Iterable[str] = self.option("columns", required=True)
        missing = [c for c in columns if c not in record]
        if missing:
            return [self.violation(f"missing column(s): {', '.join(sorted(missing))}", index)]
        return []


# --------------------------------------------------------------------------- #
# Types and ranges
# --------------------------------------------------------------------------- #
@rule("type", "data_type")
class TypeRule(Rule):
    """The field must be convertible to the declared type.

    Options: ``expected`` (one of :class:`FieldType`), ``strict`` (reject
    convertible-but-wrong-typed values rather than accepting them).
    """

    def check(self, record: Record, index: int) -> list[Violation]:
        field = self.require_field()
        value = record.get(field)
        if value is None:
            return []
        expected = FieldType(str(self.option("expected", required=True)).lower())
        strict = bool(self.option("strict", False))
        if _matches_type(value, expected, strict=strict):
            return []
        return [
            self.violation(
                f"'{field}' should be {expected.value} but got "
                f"{type(value).__name__} ({value!r:.40})",
                index,
            )
        ]


def _matches_type(value: Any, expected: FieldType, *, strict: bool) -> bool:
    if expected is FieldType.STRING:
        return isinstance(value, str) if strict else True
    if expected is FieldType.BOOLEAN:
        if isinstance(value, bool):
            return True
        return not strict and str(value).strip().lower() in {
            "true",
            "false",
            "1",
            "0",
            "yes",
            "no",
            "y",
            "n",
        }
    if expected is FieldType.INTEGER:
        if isinstance(value, bool):
            return False
        if isinstance(value, int):
            return True
        if strict:
            return False
        try:
            return float(str(value).strip()).is_integer()
        except (TypeError, ValueError):
            return False
    if expected is FieldType.FLOAT:
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return True
        if strict:
            return False
        try:
            float(str(value).strip())
        except (TypeError, ValueError):
            return False
        return True
    if expected is FieldType.DECIMAL:
        try:
            Decimal(str(value))
        except (InvalidOperation, TypeError, ValueError):
            return False
        return True
    if expected in (FieldType.DATE, FieldType.DATETIME):
        if isinstance(value, (date, datetime)):
            return True
        try:
            datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return False
        return True
    if expected is FieldType.JSON:
        return isinstance(value, (dict, list))
    return True


@rule("range", "between")
class RangeRule(Rule):
    """A numeric field must fall inside ``[min, max]``.

    Options: ``min``, ``max``, ``exclusive`` (default false).
    """

    def check(self, record: Record, index: int) -> list[Violation]:
        field = self.require_field()
        raw = record.get(field)
        if raw is None:
            return []
        try:
            value = float(raw)
        except (TypeError, ValueError):
            return [self.violation(f"'{field}' is not numeric ({raw!r:.40})", index)]

        minimum = self.option("min")
        maximum = self.option("max")
        exclusive = bool(self.option("exclusive", False))
        violations: list[Violation] = []

        if minimum is not None:
            too_small = value <= float(minimum) if exclusive else value < float(minimum)
            if too_small:
                violations.append(
                    self.violation(f"'{field}' ({value}) is below the minimum {minimum}", index)
                )
        if maximum is not None:
            too_big = value >= float(maximum) if exclusive else value > float(maximum)
            if too_big:
                violations.append(
                    self.violation(f"'{field}' ({value}) is above the maximum {maximum}", index)
                )
        return violations


@rule("length")
class LengthRule(Rule):
    """String length must be within bounds.

    Options: ``min``, ``max``, ``exact``.
    """

    def check(self, record: Record, index: int) -> list[Violation]:
        field = self.require_field()
        value = record.get(field)
        if value is None:
            return []
        length = len(str(value))
        exact = self.option("exact")
        if exact is not None and length != int(exact):
            return [
                self.violation(f"'{field}' must be exactly {exact} characters, got {length}", index)
            ]
        violations: list[Violation] = []
        minimum, maximum = self.option("min"), self.option("max")
        if minimum is not None and length < int(minimum):
            violations.append(
                self.violation(f"'{field}' is shorter than {minimum} characters", index)
            )
        if maximum is not None and length > int(maximum):
            violations.append(
                self.violation(f"'{field}' is longer than {maximum} characters", index)
            )
        return violations


# --------------------------------------------------------------------------- #
# Format
# --------------------------------------------------------------------------- #
@rule("regex", "pattern", "matches")
class RegexRule(Rule):
    """The field must match a regular expression.

    Options: ``pattern`` (required), ``ignore_case``, ``full_match``.

    The pattern is compiled once, at construction, on the time-bounded engine
    in :mod:`ironflow.security.patterns`.  A length cap alone never stopped a
    catastrophically backtracking pattern - ``(a|aa)+$`` is eight characters -
    so each match also carries a timeout, and a value the pattern cannot decide
    in time is rejected rather than waited on.
    """

    def __init__(self, spec: ValidationRuleSpec) -> None:
        super().__init__(spec)
        pattern = str(self.option("pattern", required=True))
        try:
            self._regex = compile_untrusted(
                pattern, ignore_case=bool(self.option("ignore_case", False))
            )
        except ConfigurationError as exc:
            exc.with_context(rule=self.name)
            raise
        self._full = bool(self.option("full_match", True))

    def check(self, record: Record, index: int) -> list[Violation]:
        field = self.require_field()
        value = record.get(field)
        if value is None:
            return []
        text = str(value)
        try:
            matched = self._regex.fullmatch(text) if self._full else self._regex.search(text)
        except TransformationError:
            return [
                self.violation(
                    f"'{field}' could not be checked: the pattern exceeded its time budget",
                    index,
                )
            ]
        if matched:
            return []
        return [self.violation(f"'{field}' does not match the required pattern", index)]


@rule("email")
class EmailRule(Rule):
    """The field must look like an email address."""

    def check(self, record: Record, index: int) -> list[Violation]:
        field = self.require_field()
        value = record.get(field)
        if _is_blank(value):
            return []
        if _EMAIL_RE.match(str(value).strip()):
            return []
        return [self.violation(f"'{field}' is not a valid email address", index)]


@rule("uuid")
class UuidRule(Rule):
    """The field must be a canonical UUID."""

    def check(self, record: Record, index: int) -> list[Violation]:
        field = self.require_field()
        value = record.get(field)
        if _is_blank(value):
            return []
        if _UUID_RE.match(str(value).strip()):
            return []
        return [self.violation(f"'{field}' is not a valid UUID", index)]


@rule("date_format")
class DateFormatRule(Rule):
    """The field must parse with ``strptime``.

    Options: ``format`` (default ISO 8601), ``min_date``, ``max_date``.
    """

    def check(self, record: Record, index: int) -> list[Violation]:
        field = self.require_field()
        value = record.get(field)
        if _is_blank(value):
            return []
        parsed: datetime | None
        if isinstance(value, (date, datetime)):
            parsed = (
                value
                if isinstance(value, datetime)
                else datetime.combine(value, datetime.min.time())
            )
        else:
            fmt = self.option("format")
            try:
                parsed = (
                    datetime.strptime(str(value).strip(), str(fmt))
                    if fmt
                    else datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
                )
            except (TypeError, ValueError):
                return [
                    self.violation(
                        f"'{field}' is not a valid date"
                        + (f" (expected format {fmt})" if fmt else ""),
                        index,
                    )
                ]

        if parsed is None:  # pragma: no cover - guarded by the branch above
            return []

        violations: list[Violation] = []
        for bound, comparator, label in (
            (self.option("min_date"), lambda a, b: a < b, "before"),
            (self.option("max_date"), lambda a, b: a > b, "after"),
        ):
            if bound is None:
                continue
            try:
                limit = datetime.fromisoformat(str(bound))
            except ValueError:
                continue
            left = parsed.replace(tzinfo=None) if parsed.tzinfo else parsed
            right = limit.replace(tzinfo=None) if limit.tzinfo else limit
            if comparator(left, right):
                violations.append(
                    self.violation(f"'{field}' is {label} the allowed bound {bound}", index)
                )
        return violations


# --------------------------------------------------------------------------- #
# Set membership and cross-field
# --------------------------------------------------------------------------- #
@rule("in_set", "allowed_values", "enum")
class InSetRule(Rule):
    """The field must be one of an allowed set.

    Options: ``values`` (required), ``case_sensitive`` (default true).
    """

    def __init__(self, spec: ValidationRuleSpec) -> None:
        super().__init__(spec)
        values = self.option("values", required=True)
        if not isinstance(values, (list, tuple, set)):
            raise ConfigurationError("'values' must be a list", context={"rule": self.name})
        self._case_sensitive = bool(self.option("case_sensitive", True))
        self._values = {str(v) if self._case_sensitive else str(v).lower() for v in values}

    def check(self, record: Record, index: int) -> list[Violation]:
        field = self.require_field()
        value = record.get(field)
        if value is None:
            return []
        candidate = str(value) if self._case_sensitive else str(value).lower()
        if candidate in self._values:
            return []
        return [self.violation(f"'{field}' value {value!r:.40} is not in the allowed set", index)]


@rule("unique", "distinct")
class UniqueRule(Rule):
    """The field (or a tuple of fields) must be unique across the run.

    Options: ``columns`` (defaults to ``field``), ``max_tracked``.

    Memory: one hash per distinct key.  The tracked-key cap stops the rule
    silently becoming the reason a job OOMs; once exceeded it degrades to a
    warning rather than pretending it is still checking.
    """

    def __init__(self, spec: ValidationRuleSpec) -> None:
        super().__init__(spec)
        columns = self.option("columns")
        self._columns = list(columns) if columns else ([self.field] if self.field else [])
        if not self._columns:
            raise ConfigurationError(
                "the unique rule requires 'field' or 'columns'", context={"rule": self.name}
            )
        self._seen: set[int] = set()
        self._limit = int(self.option("max_tracked", MAX_TRACKED_KEYS))
        self._overflowed = False

    def check(self, record: Record, index: int) -> list[Violation]:
        key = hash(tuple(_hashable(record.get(c)) for c in self._columns))
        if self._overflowed:
            return []
        if key in self._seen:
            return [self.violation(f"duplicate value for {', '.join(self._columns)}", index)]
        if len(self._seen) >= self._limit:
            self._overflowed = True
            logger.warning(
                "unique rule exceeded max_tracked=%d; uniqueness is no longer enforced "
                "for the remainder of this run",
                self._limit,
            )
            return []
        self._seen.add(key)
        return []

    def reset(self) -> None:
        self._seen.clear()
        self._overflowed = False


def _hashable(value: Any) -> Any:
    if isinstance(value, (dict, list, set)):
        import json

        return json.dumps(value, sort_keys=True, default=str)
    return value


@rule("expression", "business_rule", "custom")
class ExpressionRule(Rule):
    """A sandboxed boolean expression that must evaluate truthy.

    Options: ``expression`` (required).  Evaluated with
    :mod:`ironflow.expressions`, so the pipeline author gets real expressive
    power without the platform gaining an ``eval``.

    Example::

        - type: expression
          expression: "amount > 0 and (discount is None or discount <= amount)"
          message: "discount cannot exceed the order amount"
    """

    def __init__(self, spec: ValidationRuleSpec) -> None:
        super().__init__(spec)
        self._expression = compile_expression(str(self.option("expression", required=True)))

    def check(self, record: Record, index: int) -> list[Violation]:
        if self._expression.evaluate_bool(record_scope(record)):
            return []
        return [self.violation(f"business rule failed: {self._expression.source}", index)]


@rule("comparison", "field_comparison")
class ComparisonRule(Rule):
    """Compare two fields.

    Options: ``left`` (or ``field``), ``right``, ``operator``
    (``<``, ``<=``, ``>``, ``>=``, ``==``, ``!=``).
    """

    _OPERATORS: ClassVar[dict[str, Callable[[Any, Any], bool]]] = {
        "<": lambda a, b: a < b,
        "<=": lambda a, b: a <= b,
        ">": lambda a, b: a > b,
        ">=": lambda a, b: a >= b,
        "==": lambda a, b: a == b,
        "!=": lambda a, b: a != b,
    }

    def check(self, record: Record, index: int) -> list[Violation]:
        left_name = str(self.option("left", self.field, required=True))
        right_name = str(self.option("right", required=True))
        operator_symbol = str(self.option("operator", "<="))
        comparator = self._OPERATORS.get(operator_symbol)
        if comparator is None:
            raise ConfigurationError(
                "unsupported comparison operator",
                context={"operator": operator_symbol, "supported": sorted(self._OPERATORS)},
            )
        left, right = record.get(left_name), record.get(right_name)
        if left is None or right is None:
            return []
        try:
            passed = comparator(left, right)
        except TypeError:
            passed = comparator(str(left), str(right))
        if passed:
            return []
        return [
            self.violation(
                f"'{left_name}' ({left!r:.30}) {operator_symbol} "
                f"'{right_name}' ({right!r:.30}) does not hold",
                index,
            )
        ]


@rule("sequence", "monotonic")
class SequenceRule(Rule):
    """The field must never decrease across the stream.

    Options: ``strict`` (require strictly increasing).  Detects an out-of-order
    or replayed CDC feed, which incremental loads silently mis-handle otherwise.
    """

    def __init__(self, spec: ValidationRuleSpec) -> None:
        super().__init__(spec)
        self._previous: Any = None
        self._strict = bool(self.option("strict", False))

    def check(self, record: Record, index: int) -> list[Violation]:
        field = self.require_field()
        value = record.get(field)
        if value is None:
            return []
        if self._previous is not None:
            try:
                out_of_order = value <= self._previous if self._strict else value < self._previous
            except TypeError:
                out_of_order = str(value) < str(self._previous)
            if out_of_order:
                return [
                    self.violation(
                        f"'{field}' is out of order ({value!r:.30} after {self._previous!r:.30})",
                        index,
                    )
                ]
        self._previous = value
        return []

    def reset(self) -> None:
        self._previous = None


def build_rule(spec: ValidationRuleSpec) -> Rule:
    """Instantiate a rule from its specification."""
    return RULE_REGISTRY.create(spec.type, spec=spec)


def build_rules(specs: Iterable[ValidationRuleSpec]) -> list[Rule]:
    return [build_rule(spec) for spec in specs]


def rules_from_schema(schema: Mapping[str, Any]) -> list[ValidationRuleSpec]:
    """Expand a declarative column contract into rule specs.

    ``{"id": {"type": "integer", "nullable": false, "unique": true}}`` becomes a
    ``type`` rule, a ``not_null`` rule and a ``unique`` rule.  Authors get a
    compact schema block; the engine still sees ordinary rules.
    """

    def rule_spec(rule_type: str, column: str, **options: Any) -> ValidationRuleSpec:
        # model_validate, not the constructor: the extra options land in the
        # model's ``extra`` bag, which keyword arguments cannot express to a
        # type checker.
        return ValidationRuleSpec.model_validate({"type": rule_type, "field": column, **options})

    specs: list[ValidationRuleSpec] = []
    for column, contract in schema.items():
        if not isinstance(contract, Mapping):
            specs.append(rule_spec("type", column, expected=str(contract)))
            continue
        if contract.get("nullable") is False:
            specs.append(rule_spec("not_null", column))
        if "type" in contract:
            specs.append(rule_spec("type", column, expected=contract["type"]))
        if contract.get("unique"):
            specs.append(rule_spec("unique", column))
        if "min" in contract or "max" in contract:
            specs.append(
                rule_spec("range", column, min=contract.get("min"), max=contract.get("max"))
            )
        if "pattern" in contract:
            specs.append(rule_spec("regex", column, pattern=contract["pattern"]))
        if "values" in contract:
            specs.append(rule_spec("in_set", column, values=contract["values"]))
        if "max_length" in contract:
            specs.append(rule_spec("length", column, max=contract["max_length"]))
    return specs


__all__ = [
    "RULE_REGISTRY",
    "ComparisonRule",
    "ExpressionRule",
    "InSetRule",
    "NotNullRule",
    "RangeRule",
    "RegexRule",
    "Rule",
    "SequenceRule",
    "TypeRule",
    "UniqueRule",
    "build_rule",
    "build_rules",
    "rules_from_schema",
]
