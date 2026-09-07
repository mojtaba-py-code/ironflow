"""Connector base classes and the shared runtime they are given.

Every connector receives two objects:

``spec``
    The :class:`~ironflow.config.models.ConnectorSpec` from the pipeline file -
    untrusted input, validated by the connector itself.
``runtime``
    :class:`ConnectorRuntime`: platform settings, the secret resolver and the
    allow-listed data roots.  Injecting these (rather than importing
    ``get_settings()`` inside each connector) is what makes connectors testable
    without touching the environment, and what guarantees every connector shares
    the same security policy.

Lifecycle is ``open -> read``/``write* -> commit|rollback -> close``, mirroring a
database transaction.  Sinks that cannot be transactional (a REST endpoint)
implement ``commit``/``rollback`` as documented no-ops rather than pretending.
"""

from __future__ import annotations

import abc
import logging
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from types import TracebackType
from typing import Any, TypeVar

from ironflow.config.models import ConnectorSpec
from ironflow.config.settings import Settings, get_settings
from ironflow.core.context import ExecutionContext
from ironflow.core.errors import ConfigurationError, LoadingError
from ironflow.core.registry import ComponentRegistry
from ironflow.core.retry import RetryPolicy
from ironflow.core.types import DatasetSchema, LoadMode, RecordBatch, RecordStream
from ironflow.security.guards import resolve_within
from ironflow.security.secrets import SecretResolver

logger = logging.getLogger(__name__)

T = TypeVar("T")


@dataclass(slots=True)
class ConnectorRuntime:
    """Platform services handed to every connector."""

    settings: Settings = field(default_factory=get_settings)
    secrets: SecretResolver = field(default_factory=SecretResolver)

    @property
    def data_roots(self) -> tuple[Path, ...]:
        """Directories connectors may touch.  Empty tuple means unrestricted."""
        return tuple(Path(p).expanduser().resolve() for p in self.settings.data_roots)

    def resolve_path(self, path: str | Path, *, must_exist: bool = False) -> Path:
        """Resolve a configured path inside the allow-listed roots."""
        return resolve_within(path, self.data_roots, must_exist=must_exist)


class BaseConnector(abc.ABC):
    """Shared option parsing and lifecycle bookkeeping."""

    #: Registered type name; set by the ``@source``/``@sink`` decorators.
    connector_type: str = "base"

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        self.spec = spec
        self.runtime = runtime or ConnectorRuntime()
        self.name = spec.name or spec.type
        self._opened = False
        self._closed = False

    # -- option helpers ---------------------------------------------------- #
    def option(self, key: str, default: T | None = None, *, required: bool = False) -> Any:
        """Read a connector-specific option from the spec's extra keys."""
        value = self.spec.options.get(key, default)
        if required and value is None:
            raise ConfigurationError(
                f"connector {self.name!r} requires option {key!r}",
                context={"connector": self.name, "type": self.spec.type},
            )
        return value

    def int_option(self, key: str, default: int, *, minimum: int = 1, maximum: int = 2**53) -> int:
        raw = self.option(key, default)
        try:
            value = int(raw)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                f"option {key!r} must be an integer", context={"connector": self.name}
            ) from exc
        if not minimum <= value <= maximum:
            raise ConfigurationError(
                f"option {key!r} must be between {minimum} and {maximum}",
                context={"connector": self.name, "value": value},
            )
        return value

    def bool_option(self, key: str, default: bool) -> bool:
        raw = self.option(key, default)
        if isinstance(raw, bool):
            return raw
        return str(raw).strip().lower() in {"1", "true", "yes", "on"}

    def str_option(self, key: str, default: str | None = None, *, required: bool = False) -> str:
        value = self.option(key, default, required=required)
        if value is None:
            return ""
        return str(value)

    def list_option(self, key: str, default: Sequence[str] = ()) -> list[str]:
        value = self.option(key, None)
        if value is None:
            return list(default)
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, (list, tuple)):
            return [str(item) for item in value]
        raise ConfigurationError(
            f"option {key!r} must be a list or comma-separated string",
            context={"connector": self.name},
        )

    def secret_option(self, key: str, *, required: bool = False) -> str | None:
        """Resolve an option through the secret resolver (``env:``/``enc:``...)."""
        raw = self.option(key)
        if raw is None:
            if required:
                raise ConfigurationError(
                    f"connector {self.name!r} requires secret option {key!r}",
                    context={"connector": self.name},
                )
            return None
        return self.runtime.secrets.reveal(raw, name=f"{self.name}.{key}")

    @property
    def batch_size(self) -> int:
        return self.spec.batch_size or self.runtime.settings.default_batch_size

    @property
    def retry_policy(self) -> RetryPolicy:
        spec = self.spec.retry
        if spec is None:
            return RetryPolicy()
        return RetryPolicy(
            max_attempts=spec.max_attempts,
            initial_delay=spec.initial_delay,
            max_delay=spec.max_delay,
            multiplier=spec.multiplier,
            jitter=spec.jitter,
        )

    # -- lifecycle --------------------------------------------------------- #
    def open(self, context: ExecutionContext) -> None:
        """Acquire resources.  Idempotent."""
        if self._opened:
            return
        self._on_open(context)
        self._opened = True
        self._closed = False
        logger.debug("connector opened", extra={"connector": self.name})

    def close(self) -> None:
        """Release resources.  Idempotent and exception-safe."""
        if self._closed or not self._opened:
            self._closed = True
            return
        try:
            self._on_close()
        finally:
            self._closed = True
            self._opened = False
            logger.debug("connector closed", extra={"connector": self.name})

    def _on_open(self, context: ExecutionContext) -> None:
        """Hook for subclasses."""

    def _on_close(self) -> None:
        """Hook for subclasses."""

    def __enter__(self) -> BaseConnector:  # pragma: no cover - thin wrapper
        self.open(ExecutionContext(pipeline_id="adhoc"))
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:  # pragma: no cover - thin wrapper
        self.close()

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r}, type={self.spec.type!r})"


class BaseSource(BaseConnector, abc.ABC):
    """Base class for data sources."""

    @abc.abstractmethod
    def read(self, context: ExecutionContext) -> RecordStream:
        """Yield batches lazily."""
        raise NotImplementedError

    def describe(self) -> DatasetSchema:
        """Schema discovery.  Default: unknown until the first batch is read."""
        return DatasetSchema()

    def count(self) -> int | None:
        """Total rows if cheaply knowable, else ``None`` (used for progress)."""
        return None


class BaseSink(BaseConnector, abc.ABC):
    """Base class for destinations."""

    #: True when ``rollback`` genuinely undoes writes.  Surfaced by
    #: ``ironflow pipeline validate`` so operators know which destinations can
    #: leave partial data behind on failure.
    transactional: bool = False

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self.rows_written = 0

    @abc.abstractmethod
    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        """Write a batch; return the number of rows accepted."""
        raise NotImplementedError

    def commit(self) -> None:
        """Make writes durable.  Default no-op for non-transactional sinks."""

    def rollback(self) -> None:
        """Undo writes since the last commit.  Default no-op."""
        if not self.transactional and self.rows_written:
            logger.warning(
                "sink %r is not transactional; %d rows already written cannot be rolled back",
                self.name,
                self.rows_written,
            )

    @property
    def mode(self) -> LoadMode:
        return self.spec.mode

    def _assert_writable(self) -> None:
        if not self._opened:
            raise LoadingError("sink was not opened before write", context={"connector": self.name})


# --------------------------------------------------------------------------- #
# Registries
# --------------------------------------------------------------------------- #
SOURCE_REGISTRY: ComponentRegistry[BaseSource] = ComponentRegistry("source")
SINK_REGISTRY: ComponentRegistry[BaseSink] = ComponentRegistry("sink")


def source(name: str, *aliases: str) -> Any:
    """Class decorator registering a source implementation."""

    def decorator(cls: type[BaseSource]) -> type[BaseSource]:
        cls.connector_type = name
        SOURCE_REGISTRY.register(name, cls, aliases=aliases)
        return cls

    return decorator


def sink(name: str, *aliases: str) -> Any:
    """Class decorator registering a sink implementation."""

    def decorator(cls: type[BaseSink]) -> type[BaseSink]:
        cls.connector_type = name
        SINK_REGISTRY.register(name, cls, aliases=aliases)
        return cls

    return decorator


__all__ = [
    "SINK_REGISTRY",
    "SOURCE_REGISTRY",
    "BaseConnector",
    "BaseSink",
    "BaseSource",
    "ConnectorRuntime",
    "sink",
    "source",
]
