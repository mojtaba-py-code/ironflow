"""Regular expressions written in pipeline files and run against untrusted data.

:mod:`re` backtracks without limit and has no timeout, so a six-character
pattern such as ``(a|aa)+$`` turns a forty-character field into minutes of CPU:
a denial of service reachable from a validation rule in a pipeline file.  A
length cap does not help, because the dangerous patterns are the short ones.

Patterns authored in configuration therefore compile with the :mod:`regex`
engine instead.  It sidesteps catastrophic backtracking on most of the classic
shapes outright (``(a+)+$`` answers in a millisecond) and, for the ones it
cannot, honours a per-match timeout.  Three layers:

* every match runs under :data:`MATCH_TIMEOUT_SECONDS`;
* a pattern that times out :data:`MAX_TIMEOUTS` times is disabled for the rest
  of the process - a timeout alone would still let a million-row load spend
  ``rows x timeout`` of CPU on one bad pattern;
* a timeout surfaces as :class:`TransformationError`, so the record follows the
  ``on_error`` or quarantine policy instead of aborting the run.

Fixed patterns in the codebase keep using :mod:`re`; this module is only for
patterns that arrive from a pipeline definition.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from functools import lru_cache
from typing import Any, Final

import regex

from ironflow.core.errors import ConfigurationError, TransformationError

MAX_PATTERN_LENGTH: Final = 500
#: A well-formed pattern answers in microseconds even on a long field, so a
#: quarter of a second is generous for honest input and cheap for hostile input.
MATCH_TIMEOUT_SECONDS: Final = 0.25
#: Timeouts tolerated per pattern before it is disabled for the process.
MAX_TIMEOUTS: Final = 3


class UntrustedPattern:
    """A compiled regular expression whose every match is time-bounded."""

    __slots__ = ("_compiled", "_lock", "_timeouts", "pattern")

    def __init__(self, pattern: str, *, ignore_case: bool = False) -> None:
        if not isinstance(pattern, str):
            raise ConfigurationError("a regular expression must be a string")
        if len(pattern) > MAX_PATTERN_LENGTH:
            raise ConfigurationError(
                "regular expression is too long",
                context={"length": len(pattern), "limit": MAX_PATTERN_LENGTH},
            )
        flags = regex.VERSION0 | (regex.IGNORECASE if ignore_case else 0)
        try:
            self._compiled = regex.compile(pattern, flags)
        except regex.error as exc:
            raise ConfigurationError(
                "invalid regular expression",
                context={"pattern": pattern[:80], "detail": str(exc)},
                cause=exc,
            ) from exc
        self.pattern = pattern
        self._timeouts = 0
        self._lock = threading.Lock()

    def search(self, text: str) -> bool:
        """True when the pattern matches anywhere in ``text``."""
        return self._run(self._compiled.search, text)

    def fullmatch(self, text: str) -> bool:
        """True when the pattern matches the whole of ``text``."""
        return self._run(self._compiled.fullmatch, text)

    def _run(self, method: Callable[..., Any], text: str) -> bool:
        if self._timeouts >= MAX_TIMEOUTS:
            raise TransformationError(
                "regular expression disabled after repeated timeouts",
                context={"pattern": self.pattern[:80], "timeouts": self._timeouts},
            )
        try:
            return method(text, timeout=MATCH_TIMEOUT_SECONDS) is not None
        except TimeoutError as exc:
            with self._lock:
                self._timeouts += 1
            raise TransformationError(
                "regular expression exceeded its time budget on this value",
                context={"pattern": self.pattern[:80], "limit_seconds": MATCH_TIMEOUT_SECONDS},
                cause=exc,
            ) from exc


@lru_cache(maxsize=256)
def compile_untrusted(pattern: str, *, ignore_case: bool = False) -> UntrustedPattern:
    """Compile once per process; the timeout counter lives on the cached object."""
    return UntrustedPattern(pattern, ignore_case=ignore_case)


__all__ = [
    "MATCH_TIMEOUT_SECONDS",
    "MAX_PATTERN_LENGTH",
    "MAX_TIMEOUTS",
    "UntrustedPattern",
    "compile_untrusted",
]
