"""Connector factory - the single place a :class:`ConnectorSpec` becomes an object.

Centralising construction buys three things:

* every connector is handed the *same* :class:`ConnectorRuntime`, so the
  security policy (data roots, secret resolution, TLS) cannot be bypassed by a
  connector that forgot to ask for it;
* the ``type`` string is resolved through the registry, so a pipeline file can
  never name an arbitrary import path;
* construction errors are wrapped with the task/connector name, which is what
  turns "KeyError: 'path'" into "task 'load_orders': connector 'csv' requires
  option 'path'".
"""

from __future__ import annotations

import logging
from typing import Any

from ironflow.config.models import ConnectorSpec
from ironflow.config.settings import Settings, get_settings
from ironflow.connectors.base import (
    SINK_REGISTRY,
    SOURCE_REGISTRY,
    BaseSink,
    BaseSource,
    ConnectorRuntime,
)
from ironflow.core.errors import ConfigurationError, IronFlowError
from ironflow.security.secrets import SecretResolver

logger = logging.getLogger(__name__)


class ConnectorFactory:
    """Builds sources and sinks from their specifications."""

    def __init__(
        self,
        settings: Settings | None = None,
        secrets: SecretResolver | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.secrets = secrets or SecretResolver(allow_literal=self.settings.allow_literal_secrets)
        self.runtime = ConnectorRuntime(settings=self.settings, secrets=self.secrets)

    def create_source(self, spec: ConnectorSpec, *, context: str = "") -> BaseSource:
        return self._create(SOURCE_REGISTRY, spec, kind="source", context=context)

    def create_sink(self, spec: ConnectorSpec, *, context: str = "") -> BaseSink:
        return self._create(SINK_REGISTRY, spec, kind="sink", context=context)

    def _create(self, registry: Any, spec: ConnectorSpec, *, kind: str, context: str) -> Any:
        try:
            connector = registry.create(spec.type, spec=spec, runtime=self.runtime)
        except IronFlowError as exc:
            exc.with_context(role=kind, task=context or None, connector=spec.label)
            raise
        except TypeError as exc:  # pragma: no cover - signals a bad plugin
            raise ConfigurationError(
                f"{kind} {spec.type!r} could not be constructed",
                context={"detail": str(exc)},
                cause=exc,
            ) from exc
        logger.debug("built %s %r for %s", kind, spec.label, context or "adhoc")
        return connector

    def validate(self, spec: ConnectorSpec, *, kind: str) -> list[str]:
        """Check a spec without connecting; returns human-readable problems.

        Used by ``ironflow pipeline validate`` so an operator can catch a typo
        without credentials for the target system.
        """
        registry = SOURCE_REGISTRY if kind == "source" else SINK_REGISTRY
        if spec.type not in registry:
            return [f"unknown {kind} type {spec.type!r}; available: {', '.join(registry.names())}"]
        try:
            self._create(registry, spec, kind=kind, context="validate")
        except IronFlowError as exc:
            return [str(exc)]
        return []


def describe_connectors() -> dict[str, list[dict[str, str]]]:
    """Registry inventory for ``ironflow connectors list`` and the API."""

    def _describe(registry: Any) -> list[dict[str, str]]:
        seen: dict[str, dict[str, str]] = {}
        for name in registry.names():
            cls = registry.get(name)
            doc = (cls.__doc__ or "").strip().splitlines()
            summary = doc[0] if doc else ""
            entry = seen.setdefault(
                cls.__name__,
                {"class": cls.__name__, "types": name, "summary": summary},
            )
            if entry["types"] != name and name not in entry["types"].split(", "):
                entry["types"] = f"{entry['types']}, {name}"
        return sorted(seen.values(), key=lambda item: item["types"])

    return {"sources": _describe(SOURCE_REGISTRY), "sinks": _describe(SINK_REGISTRY)}


__all__ = ["ConnectorFactory", "describe_connectors"]
