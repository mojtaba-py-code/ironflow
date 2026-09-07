"""Transformation base classes and registries.

Two kinds of transformation, deliberately distinguished at the type level:

:class:`Transformation`
    Sees one batch, returns one batch.  Composable, streaming, constant memory.
    The overwhelming majority of real work (rename, cast, mask, filter) fits
    here.
:class:`StreamTransformation`
    Sees the whole stream.  Necessary for sorts, joins and aggregations.  These
    declare ``blocking = True`` so the engine can log where the pipeline stops
    streaming - the single most useful piece of information when a job's memory
    profile is a surprise.

Keeping them separate means the cost of a blocking operation is visible in the
pipeline definition rather than hidden inside an innocuous-looking step.
"""

from __future__ import annotations

import abc
import logging
from collections.abc import Iterator
from typing import Any

from ironflow.config.models import TransformSpec
from ironflow.core.context import ExecutionContext
from ironflow.core.errors import ConfigurationError
from ironflow.core.registry import ComponentRegistry
from ironflow.core.types import Record, RecordBatch, RecordStream

logger = logging.getLogger(__name__)


class BaseTransformation(abc.ABC):
    """Common option handling for both flavours."""

    transform_type: str = "base"
    blocking: bool = False

    def __init__(self, spec: TransformSpec) -> None:
        self.spec = spec
        self.name = spec.name or spec.type

    def option(self, key: str, default: Any = None, *, required: bool = False) -> Any:
        value = self.spec.options.get(key, default)
        if required and value is None:
            raise ConfigurationError(
                f"transformation {self.name!r} requires option {key!r}",
                context={"transformation": self.name, "type": self.spec.type},
            )
        return value

    def str_option(self, key: str, default: str | None = None, *, required: bool = False) -> str:
        value = self.option(key, default, required=required)
        return "" if value is None else str(value)

    def bool_option(self, key: str, default: bool) -> bool:
        value = self.option(key, default)
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def int_option(self, key: str, default: int) -> int:
        try:
            return int(self.option(key, default))
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                f"option {key!r} must be an integer",
                context={"transformation": self.name},
            ) from exc

    def list_option(
        self, key: str, default: list[str] | None = None, *, required: bool = False
    ) -> list[str]:
        value = self.option(key, None, required=required)
        if value is None:
            return list(default or [])
        if isinstance(value, str):
            return [item.strip() for item in value.split(",") if item.strip()]
        if isinstance(value, (list, tuple)):
            return [str(item) for item in value]
        raise ConfigurationError(
            f"option {key!r} must be a list", context={"transformation": self.name}
        )

    def dict_option(self, key: str, *, required: bool = False) -> dict[str, Any]:
        value = self.option(key, None, required=required)
        if value is None:
            return {}
        if not isinstance(value, dict):
            raise ConfigurationError(
                f"option {key!r} must be a mapping", context={"transformation": self.name}
            )
        return dict(value)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(name={self.name!r})"


class Transformation(BaseTransformation, abc.ABC):
    """A per-batch transformation."""

    blocking = False

    @abc.abstractmethod
    def apply(self, batch: RecordBatch, context: ExecutionContext) -> RecordBatch:
        raise NotImplementedError


class RecordTransformation(Transformation, abc.ABC):
    """Convenience base for transformations that work record by record.

    Returning ``None`` from :meth:`transform_record` drops the record, which is
    how filters are expressed without a separate mechanism.
    """

    @abc.abstractmethod
    def transform_record(self, record: Record, context: ExecutionContext) -> Record | None:
        raise NotImplementedError

    def apply(self, batch: RecordBatch, context: ExecutionContext) -> RecordBatch:
        transformed: list[Record] = []
        for record in batch.records:
            result = self.transform_record(record, context)
            if result is not None:
                transformed.append(result)
        return batch.replace(transformed)


class StreamTransformation(BaseTransformation, abc.ABC):
    """A transformation that consumes the whole stream.

    Subclasses must document their memory profile in the class docstring.
    """

    blocking = True

    @abc.abstractmethod
    def apply_stream(self, stream: RecordStream, context: ExecutionContext) -> RecordStream:
        raise NotImplementedError

    @staticmethod
    def _rebatch(records: list[Record], size: int, source: str) -> Iterator[RecordBatch]:
        """Re-chunk a materialised list back into batches."""
        for index in range(0, len(records), size):
            yield RecordBatch(records[index : index + size], sequence=index // size, source=source)


TRANSFORM_REGISTRY: ComponentRegistry[BaseTransformation] = ComponentRegistry("transformation")


def transformation(name: str, *aliases: str) -> Any:
    """Class decorator registering a transformation implementation."""

    def decorator(cls: type[BaseTransformation]) -> type[BaseTransformation]:
        cls.transform_type = name
        TRANSFORM_REGISTRY.register(name, cls, aliases=aliases)
        return cls

    return decorator


def build_transformation(spec: TransformSpec) -> BaseTransformation:
    """Instantiate a transformation from its specification."""
    return TRANSFORM_REGISTRY.create(spec.type, spec=spec)


__all__ = [
    "TRANSFORM_REGISTRY",
    "BaseTransformation",
    "RecordTransformation",
    "StreamTransformation",
    "Transformation",
    "build_transformation",
    "transformation",
]
