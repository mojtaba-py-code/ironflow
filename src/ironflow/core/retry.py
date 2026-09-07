"""Retry policy with exponential backoff, full jitter and a circuit breaker.

Why full jitter
---------------
Fixed or purely exponential backoff synchronises every worker that failed at the
same moment, so the retry storm hits the recovering dependency all at once.
Full jitter (``sleep = uniform(0, min(cap, base * 2**n))``) spreads the retries
and is the variant AWS measured as having the lowest completion time and load.

What is retried
---------------
Only errors the caller explicitly classified as transient.  IronFlow exceptions
carry a ``retryable`` flag, so a malformed record (``ValidationError``) is never
retried while a socket timeout is.  Retrying a deterministic failure just burns
the error budget and delays the alert.
"""

from __future__ import annotations

import functools
import logging
import random
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any, TypeVar

from ironflow.core.errors import IronFlowError, RetryExceededError

T = TypeVar("T")

logger = logging.getLogger(__name__)

#: Standard-library exceptions that are always transient.
DEFAULT_TRANSIENT: tuple[type[BaseException], ...] = (
    TimeoutError,
    OSError,
    ConnectionResetError,
)


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """Declarative retry configuration."""

    max_attempts: int = 3
    initial_delay: float = 0.5
    max_delay: float = 30.0
    multiplier: float = 2.0
    jitter: bool = True
    retry_on: tuple[type[BaseException], ...] = DEFAULT_TRANSIENT

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be >= 1")
        if self.initial_delay < 0 or self.max_delay < 0:
            raise ValueError("delays must be non-negative")
        if self.multiplier < 1:
            raise ValueError("multiplier must be >= 1")

    @classmethod
    def disabled(cls) -> RetryPolicy:
        return cls(max_attempts=1, initial_delay=0.0)

    def should_retry(self, exc: BaseException) -> bool:
        """Decide whether ``exc`` is worth another attempt."""
        if isinstance(exc, IronFlowError):
            return exc.retryable
        return isinstance(exc, self.retry_on)

    def delay_for(self, attempt: int) -> float:
        """Backoff for a 1-based ``attempt`` number."""
        raw = self.initial_delay * (self.multiplier ** max(0, attempt - 1))
        capped = min(raw, self.max_delay)
        if not self.jitter:
            return capped
        return random.uniform(0.0, capped)  # noqa: S311 - jitter, not crypto

    def delays(self) -> Iterable[float]:  # pragma: no cover - introspection helper
        return (self.delay_for(i) for i in range(1, self.max_attempts))


class CircuitBreaker:
    """Stop hammering a dependency that is consistently failing.

    After ``failure_threshold`` consecutive failures the breaker opens and every
    call fails fast for ``reset_timeout`` seconds.  The first call after the
    timeout is a probe: success closes the breaker, failure re-opens it.
    """

    __slots__ = ("_failures", "_opened_at", "_reset_timeout", "_threshold", "name")

    def __init__(self, name: str, failure_threshold: int = 5, reset_timeout: float = 60.0) -> None:
        self.name = name
        self._threshold = max(1, failure_threshold)
        self._reset_timeout = max(0.0, reset_timeout)
        self._failures = 0
        self._opened_at: float | None = None

    @property
    def is_open(self) -> bool:
        if self._opened_at is None:
            return False
        # Once the reset timeout has elapsed the breaker is half-open: report it
        # as closed so exactly one probe request gets through.
        return time.monotonic() - self._opened_at < self._reset_timeout

    def record_success(self) -> None:
        self._failures = 0
        self._opened_at = None

    def record_failure(self) -> None:
        self._failures += 1
        if self._failures >= self._threshold:
            self._opened_at = time.monotonic()

    def raise_if_open(self) -> None:
        if self.is_open:
            from ironflow.core.errors import ConnectionError as IFConnectionError

            raise IFConnectionError(
                f"circuit breaker open for {self.name!r}",
                context={"failures": self._failures, "reset_timeout": self._reset_timeout},
            )


def call_with_retry(
    func: Callable[[], T],
    policy: RetryPolicy,
    *,
    description: str = "operation",
    sleep: Callable[[float], None] = time.sleep,
    on_retry: Callable[[int, BaseException, float], None] | None = None,
    breaker: CircuitBreaker | None = None,
) -> T:
    """Invoke ``func`` under ``policy``.

    ``sleep`` is injected so tests can run instantly without monkey-patching the
    ``time`` module globally.
    """
    last_exc: BaseException | None = None
    for attempt in range(1, policy.max_attempts + 1):
        if breaker is not None:
            breaker.raise_if_open()
        try:
            result = func()
        except BaseException as exc:
            last_exc = exc
            if breaker is not None:
                breaker.record_failure()
            if not policy.should_retry(exc) or attempt >= policy.max_attempts:
                break
            delay = policy.delay_for(attempt)
            logger.warning(
                "retrying %s after failure (attempt %d/%d, sleeping %.2fs): %s",
                description,
                attempt,
                policy.max_attempts,
                delay,
                exc,
            )
            if on_retry is not None:
                on_retry(attempt, exc, delay)
            if delay:
                sleep(delay)
        else:
            if breaker is not None:
                breaker.record_success()
            return result

    assert last_exc is not None
    if policy.max_attempts > 1 and policy.should_retry(last_exc):
        raise RetryExceededError(
            f"{description} failed after {policy.max_attempts} attempts",
            attempts=policy.max_attempts,
            cause=last_exc,
            context={"last_error": str(last_exc)},
        ) from last_exc
    raise last_exc


def retryable(
    policy: RetryPolicy | None = None, *, description: str | None = None
) -> Callable[[Callable[..., T]], Callable[..., T]]:
    """Decorator form of :func:`call_with_retry`."""
    effective = policy or RetryPolicy()

    def decorator(func: Callable[..., T]) -> Callable[..., T]:
        @functools.wraps(func)
        def wrapper(*args: Any, **kwargs: Any) -> T:
            return call_with_retry(
                lambda: func(*args, **kwargs),
                effective,
                description=description or func.__qualname__,
            )

        return wrapper

    return decorator


__all__ = [
    "CircuitBreaker",
    "RetryPolicy",
    "call_with_retry",
    "retryable",
]
