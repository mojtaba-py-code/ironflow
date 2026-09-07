"""The narrow interfaces every pluggable component implements.

These are :class:`typing.Protocol` classes rather than ABCs on purpose: a
connector implemented in a third-party package does not need to import
IronFlow's base classes to satisfy the contract, and ``mypy`` still checks the
shape structurally.  Concrete helper base classes live in
:mod:`ironflow.connectors.base` for the common case.

Dependency direction: engines depend on these protocols only.  Nothing here
imports a connector, which is what keeps the dependency graph acyclic and the
engines trivially mockable.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from ironflow.core.context import ExecutionContext
from ironflow.core.types import DatasetSchema, RecordBatch, RecordStream, Violation


@runtime_checkable
class DataSource(Protocol):
    """Anything that can produce record batches."""

    name: str

    def open(self, context: ExecutionContext) -> None:
        """Acquire connections/handles.  Must be idempotent."""

    def read(self, context: ExecutionContext) -> RecordStream:
        """Yield batches lazily.  Implementations must not buffer everything."""
        ...

    def describe(self) -> DatasetSchema:
        """Best-effort schema discovery; may return an empty schema."""
        ...

    def close(self) -> None:
        """Release resources.  Must be safe to call twice."""


@runtime_checkable
class DataSink(Protocol):
    """Anything that can consume record batches."""

    name: str

    def open(self, context: ExecutionContext) -> None: ...

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        """Write a batch and return the number of rows accepted."""
        ...

    def commit(self) -> None:
        """Make previously written rows durable/visible."""

    def rollback(self) -> None:
        """Discard everything written since ``open``/last ``commit``."""

    def close(self) -> None: ...


@runtime_checkable
class Transformation(Protocol):
    """A per-batch, order-preserving transformation."""

    name: str

    def apply(self, batch: RecordBatch, context: ExecutionContext) -> RecordBatch: ...


@runtime_checkable
class StreamTransformation(Protocol):
    """A transformation that needs to see more than one batch at a time.

    Used for sorts, joins, aggregations and global deduplication.  Implementers
    must document their memory profile - these are the only components in the
    pipeline allowed to hold the full dataset.
    """

    name: str
    blocking: bool

    def apply_stream(self, stream: RecordStream, context: ExecutionContext) -> RecordStream: ...


@runtime_checkable
class RecordValidator(Protocol):
    """A single data-quality rule."""

    name: str

    def validate(self, record: dict[str, Any], index: int) -> list[Violation]: ...


@runtime_checkable
class StateStore(Protocol):
    """Durable key/value storage for watermarks and checkpoints."""

    def get(self, namespace: str, key: str) -> Any | None: ...

    def set(self, namespace: str, key: str, value: Any) -> None: ...

    def delete(self, namespace: str, key: str) -> None: ...


@runtime_checkable
class Notifier(Protocol):
    """Delivery channel for pipeline notifications."""

    name: str

    def notify(self, subject: str, body: str, payload: dict[str, Any]) -> bool: ...


__all__ = [
    "DataSink",
    "DataSource",
    "Notifier",
    "RecordValidator",
    "StateStore",
    "StreamTransformation",
    "Transformation",
]
