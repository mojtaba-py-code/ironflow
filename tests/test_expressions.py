"""Tests for the sandboxed expression evaluator.

The first class is the important one: it is the escape-attempt suite.  If any of
those tests start passing the evaluation instead of blocking it, the platform
has an arbitrary-code-execution vulnerability reachable from a pipeline file.
"""

from __future__ import annotations

import pytest

from ironflow.core.errors import ConfigurationError, TransformationError
from ironflow.expressions import (
    MAX_EXPRESSION_LENGTH,
    SafeExpression,
    compile_expression,
    evaluate,
    evaluate_condition,
    record_scope,
)


class TestSandboxEscapes:
    """Every entry is a real technique used to break out of ``eval`` sandboxes."""

    @pytest.mark.parametrize(
        "attack",
        [
            '__import__("os").system("id")',
            '__builtins__["eval"]("1")',
            "().__class__.__bases__[0].__subclasses__()",
            "().__class__.__mro__[1].__subclasses__()",
            "(1).__class__.__base__.__subclasses__()",
            '"".__class__.__mro__[1].__subclasses__()',
            "open('/etc/passwd').read()",
            'eval("1+1")',
            'exec("x=1")',
            'compile("1", "s", "eval")',
            "globals()",
            "locals()",
            "vars()",
            'getattr(str, "upper")',
            "setattr(object, 'x', 1)",
            "delattr(str, 'upper')",
            "(lambda: 1)()",
            "[x for x in range(10)]",
            "{k: v for k, v in items}",
            "(y for y in range(3))",
            "x := 5",
            "f'{__import__}'",
            "import os",
            "lambda: 1",
            "_secret",
            "row.__class__",
            "row.__dict__",
        ],
    )
    def test_escape_attempt_is_blocked(self, attack):
        with pytest.raises((ConfigurationError, TransformationError)):
            evaluate(attack, {"row": {"a": 1}, "items": [], "x": 1, "y": 1})

    def test_dunder_attribute_is_rejected_at_compile_time(self):
        with pytest.raises(ConfigurationError, match="attributes starting with"):
            compile_expression("params.__class__")

    def test_attribute_access_never_reaches_getattr(self):
        """Dotted syntax is a mapping lookup; a non-mapping yields None."""
        assert evaluate("value.anything", {"value": "a string"}) is None
        assert evaluate("value.anything", {"value": 42}) is None


class TestResourceLimits:
    def test_expression_length_is_capped(self):
        with pytest.raises(ConfigurationError, match="maximum length"):
            compile_expression("1 + " * (MAX_EXPRESSION_LENGTH // 2) + "1")

    def test_complexity_is_capped(self):
        with pytest.raises(ConfigurationError, match="too complex"):
            compile_expression(" + ".join(["1"] * 500))

    def test_string_bomb_is_blocked(self):
        # Caught by the operand-type check: text arithmetic is refused outright.
        with pytest.raises(TransformationError):
            evaluate('"a" * 10000000', {})

    def test_sequence_bomb_is_blocked_by_the_size_guard(self):
        with pytest.raises(TransformationError, match="oversized"):
            evaluate("[0] * 10000000", {})

    def test_exponent_bomb_is_blocked(self):
        with pytest.raises(TransformationError, match="exponent"):
            evaluate("9 ** 999999999", {})

    def test_small_exponents_still_work(self):
        assert evaluate("2 ** 10", {}) == 1024

    def test_the_pow_function_is_bounded_like_the_operator(self):
        """``pow()`` was a second, unguarded route to the same integer bomb.

        ``pow(2, 5_000_000)`` builds a five-million-bit integer in well under a
        second, so the operator guard alone left the cost unbounded.
        """
        with pytest.raises(TransformationError, match="exponent"):
            evaluate("pow(2, 5000000)", {})

    def test_ordinary_pow_calls_still_work(self):
        assert evaluate("pow(2, 10)", {}) == 1024


class TestEvaluation:
    @pytest.mark.parametrize(
        ("expression", "names", "expected"),
        [
            ("1 + 2 * 3", {}, 7),
            ("(1 + 2) * 3", {}, 9),
            ("10 / 4", {}, 2.5),
            ("10 // 4", {}, 2),
            ("10 % 3", {}, 1),
            ("-x", {"x": 5}, -5),
            ("not flag", {"flag": False}, True),
            ("a > b", {"a": 2, "b": 1}, True),
            ("1 < x < 10", {"x": 5}, True),
            ("1 < x < 3", {"x": 5}, False),
            ("x in [1, 2, 3]", {"x": 2}, True),
            ("x not in [1, 2]", {"x": 3}, True),
            ("x if x else 'fallback'", {"x": ""}, "fallback"),
            ("x is None", {"x": None}, True),
            ("{'a': 1}['a']", {}, 1),
            ("[1, 2, 3][1]", {}, 2),
            ("'abcdef'[1:3]", {}, "bc"),
        ],
    )
    def test_operators(self, expression, names, expected):
        assert evaluate(expression, names) == expected

    @pytest.mark.parametrize(
        "expression",
        ["price * qty", "price - 1", "price / 2", "amount + 1"],
    )
    def test_text_arithmetic_is_refused_rather_than_silently_wrong(self, expression):
        """``"12.50" * 2`` is valid Python and yields "12.5012.50" - never intended."""
        with pytest.raises(TransformationError, match="cast the column"):
            evaluate(expression, {"price": "12.50", "qty": 2, "amount": "5"})

    def test_string_concatenation_still_works(self):
        assert evaluate("a + b", {"a": "foo", "b": "bar"}) == "foobar"

    def test_boolean_short_circuit(self):
        """``and``/``or`` must short-circuit or null-guards do not work."""
        assert evaluate("x is not None and x > 5", {"x": None}) is False
        assert evaluate("x or 'default'", {"x": None}) == "default"

    def test_division_by_zero_yields_null_like_sql(self):
        assert evaluate("1 / 0", {}) is None

    def test_missing_key_yields_none(self):
        assert evaluate('row["absent"]', {"row": {"a": 1}}) is None

    def test_unknown_name_is_an_error(self):
        """A typo in a column name must fail loudly, not null out a whole load."""
        with pytest.raises(TransformationError, match="unknown name"):
            evaluate("nonexistent_column + 1", {"a": 1})

    def test_dotted_mapping_access(self):
        scope = record_scope({"amount": 1}, params={"force": True}, state={"prev": 5})
        assert evaluate("params.force", scope) is True
        assert evaluate("state.prev", scope) == 5
        assert evaluate("params.absent", scope) is None


class TestFunctions:
    @pytest.mark.parametrize(
        ("expression", "expected"),
        [
            ("abs(-5)", 5),
            ("round(3.14159, 2)", 3.14),
            ("min(3, 1, 2)", 1),
            ("max([3, 1, 2])", 3),
            ("upper('abc')", "ABC"),
            ("lower('ABC')", "abc"),
            ("strip('  x  ')", "x"),
            ("len('abcd')", 4),
            ("concat('a', 'b', 'c')", "abc"),
            ("replace('a-b', '-', '_')", "a_b"),
            ("contains('hello', 'ell')", True),
            ("startswith('hello', 'he')", True),
            ("coalesce(None, None, 'x')", "x"),
            ("is_null('')", True),
            ("is_null('  ')", True),
            ("is_not_null('a')", True),
            ("default(None, 0)", 0),
            ("int('42')", 42),
            ("int('1,234')", 1234),
            ("float('3.5')", 3.5),
            ("int('abc')", None),
            ("str(None)", ""),
            ("regex_match('^a.*z$', 'abcz')", True),
            ("year('2026-03-04')", 2026),
            ("days_between('2026-01-10', '2026-01-01')", 9),
            ("sorted([3, 1, 2])", [1, 2, 3]),
            ("join('-', ['a', 'b'])", "a-b"),
        ],
    )
    def test_builtin_functions(self, expression, expected):
        assert evaluate(expression, {}) == expected

    def test_unknown_function_is_rejected_with_suggestions(self):
        with pytest.raises(ConfigurationError, match="unknown function") as info:
            compile_expression("system('ls')")
        assert "available" in info.value.context

    def test_arg_unpacking_is_rejected(self):
        with pytest.raises(ConfigurationError, match="not allowed"):
            compile_expression("max(*values)")
        with pytest.raises(ConfigurationError, match="not allowed"):
            compile_expression("max(**values)")

    def test_regex_pattern_length_is_capped(self):
        with pytest.raises(TransformationError, match="too long"):
            evaluate(f"regex_match('{'a' * 250}', 'x')", {})


class TestCompilation:
    def test_syntax_errors_are_reported_clearly(self):
        with pytest.raises(ConfigurationError, match="syntax error"):
            compile_expression("1 +")

    def test_empty_expression_is_rejected(self):
        for bad in ("", "   ", None):
            with pytest.raises(ConfigurationError):
                SafeExpression(bad)  # type: ignore[arg-type]

    def test_compilation_is_cached(self):
        assert compile_expression("1 + 1") is compile_expression("1 + 1")

    def test_evaluate_condition_coerces_to_bool(self):
        assert evaluate_condition("amount", {"amount": 5}) is True
        assert evaluate_condition("amount", {"amount": 0}) is False


class TestRecordScope:
    def test_columns_are_bound_directly_and_under_row(self):
        scope = record_scope({"amount": 10, "name": "x"})
        assert evaluate("amount * 2", scope) == 20
        assert evaluate('row["amount"] * 2', scope) == 20

    def test_row_alias_disambiguates_a_column_named_like_a_function(self):
        scope = record_scope({"len": 5})
        assert evaluate('row["len"]', scope) == 5
