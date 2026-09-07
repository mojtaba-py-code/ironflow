"""Exception hierarchy for the platform.

Design notes
------------
Every failure raised by IronFlow derives from :class:`IronFlowError`, so a
caller can install a single ``except`` clause at the process boundary without
swallowing genuine programming errors (``TypeError``, ``AttributeError`` ...).

Errors carry a machine readable ``code`` and a ``context`` mapping.  The code is
what dashboards and alert rules match on; the context is what an on-call
engineer reads.  Both are rendered into the structured log record, and the
context is passed through :func:`ironflow.security.masking.redact_mapping`
before it is ever logged, so a connection string in ``context`` cannot leak a
password.

The ``retryable`` flag lets the retry policy decide mechanically whether an
operation may be attempted again instead of pattern-matching on messages.
"""

from __future__ import annotations

from typing import Any


class IronFlowError(Exception):
    """Base class for every error raised by the platform."""

    #: Stable identifier used by alerting rules; overridden per subclass.
    code: str = "IRONFLOW_ERROR"
    #: Whether a retry could plausibly succeed without operator intervention.
    retryable: bool = False

    def __init__(
        self,
        message: str,
        *,
        context: dict[str, Any] | None = None,
        cause: BaseException | None = None,
        retryable: bool | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.context: dict[str, Any] = dict(context or {})
        self.cause = cause
        if retryable is not None:
            self.retryable = retryable
        if cause is not None and self.__cause__ is None:
            self.__cause__ = cause

    def with_context(self, **values: Any) -> IronFlowError:
        """Attach extra diagnostic values and return ``self`` for chaining."""
        self.context.update(values)
        return self

    def to_dict(self) -> dict[str, Any]:
        """Serialise the error for logs, API responses and run history rows."""
        return {
            "error": type(self).__name__,
            "code": self.code,
            "message": self.message,
            "retryable": self.retryable,
            "context": self.context,
        }

    def __str__(self) -> str:  # pragma: no cover - trivial formatting
        if not self.context:
            return self.message
        rendered = ", ".join(f"{k}={v!r}" for k, v in sorted(self.context.items()))
        return f"{self.message} ({rendered})"


# --------------------------------------------------------------------------- #
# Configuration / bootstrap
# --------------------------------------------------------------------------- #
class ConfigurationError(IronFlowError):
    """Raised when a pipeline specification or setting is missing or invalid."""

    code = "CONFIG_INVALID"


class SecretError(ConfigurationError):
    """Raised when a secret cannot be resolved or decrypted."""

    code = "SECRET_UNAVAILABLE"


class RegistryError(ConfigurationError):
    """Raised when an unknown component type is requested from a registry."""

    code = "COMPONENT_UNKNOWN"


# --------------------------------------------------------------------------- #
# Security
# --------------------------------------------------------------------------- #
class SecurityError(IronFlowError):
    """Base class for security policy violations."""

    code = "SECURITY_VIOLATION"


class AuthenticationError(SecurityError):
    """Credentials were absent, malformed or rejected by the remote system."""

    code = "AUTH_FAILED"


class AuthorizationError(SecurityError):
    """The authenticated principal lacks the permission for this action."""

    code = "AUTH_FORBIDDEN"


# --------------------------------------------------------------------------- #
# Connectivity
# --------------------------------------------------------------------------- #
class ConnectionError(IronFlowError):
    """A source or destination could not be reached."""

    code = "CONNECTION_FAILED"
    retryable = True


class RateLimitError(ConnectionError):
    """A remote endpoint asked us to slow down."""

    code = "RATE_LIMITED"
    retryable = True


# --------------------------------------------------------------------------- #
# ETL stages
# --------------------------------------------------------------------------- #
class ExtractionError(IronFlowError):
    """Reading from a source failed."""

    code = "EXTRACTION_FAILED"


class TransformationError(IronFlowError):
    """A transformation step failed."""

    code = "TRANSFORMATION_FAILED"


class ValidationError(IronFlowError):
    """Records violated the configured data-quality contract."""

    code = "VALIDATION_FAILED"

    def __init__(
        self,
        message: str,
        *,
        violations: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(message, **kwargs)
        self.violations = violations or []

    def to_dict(self) -> dict[str, Any]:
        payload = super().to_dict()
        payload["violations"] = self.violations[:50]
        payload["violation_count"] = len(self.violations)
        return payload


class LoadingError(IronFlowError):
    """Writing to a destination failed."""

    code = "LOADING_FAILED"


class SchemaError(IronFlowError):
    """The observed schema is incompatible with the declared contract."""

    code = "SCHEMA_INCOMPATIBLE"


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
class PipelineError(IronFlowError):
    """A pipeline run failed as a whole."""

    code = "PIPELINE_FAILED"


class TaskError(PipelineError):
    """A single task within a pipeline failed."""

    code = "TASK_FAILED"


class CircularDependencyError(ConfigurationError):
    """The task graph contains a cycle and cannot be ordered."""

    code = "DAG_CYCLE"


class RetryExceededError(IronFlowError):
    """All retry attempts were exhausted."""

    code = "RETRY_EXCEEDED"

    def __init__(self, message: str, *, attempts: int, **kwargs: Any) -> None:
        super().__init__(message, **kwargs)
        self.attempts = attempts
        self.context.setdefault("attempts", attempts)


class CheckpointError(IronFlowError):
    """A checkpoint could not be written or restored."""

    code = "CHECKPOINT_FAILED"


class SchedulerError(IronFlowError):
    """A schedule expression is invalid or a scheduled trigger failed."""

    code = "SCHEDULER_FAILED"


__all__ = [
    "AuthenticationError",
    "AuthorizationError",
    "CheckpointError",
    "CircularDependencyError",
    "ConfigurationError",
    "ConnectionError",
    "ExtractionError",
    "IronFlowError",
    "LoadingError",
    "PipelineError",
    "RateLimitError",
    "RegistryError",
    "RetryExceededError",
    "SchedulerError",
    "SchemaError",
    "SecretError",
    "SecurityError",
    "TaskError",
    "TransformationError",
    "ValidationError",
]
