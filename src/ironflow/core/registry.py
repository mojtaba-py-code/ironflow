"""Generic component registry - the factory behind every ``type:`` key in YAML.

A pipeline specification names components by string (``type: csv``,
``type: mask_pii``).  The registry maps those strings to constructors, which is
what lets the configuration layer stay free of imports and lets operators add a
connector without touching the engine.

Two safety properties matter here:

* **No dynamic import of arbitrary paths.**  A registry only resolves names that
  were explicitly registered by IronFlow itself or by a plugin the operator
  installed.  A malicious pipeline YAML therefore cannot make the process
  import ``os.system`` - the worst it can do is name a component that does not
  exist, which raises :class:`RegistryError`.
* **Immutability after freeze.**  Once the application has bootstrapped, the
  registry is frozen so a later code path cannot silently swap an implementation.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from typing import Generic, TypeVar

from ironflow.core.errors import RegistryError

T = TypeVar("T")


class ComponentRegistry(Generic[T]):
    """Name -> factory mapping with helpful failure messages."""

    __slots__ = ("_factories", "_frozen", "_kind")

    def __init__(self, kind: str) -> None:
        self._kind = kind
        self._factories: dict[str, Callable[..., T]] = {}
        self._frozen = False

    @property
    def kind(self) -> str:
        return self._kind

    def register(
        self,
        name: str,
        factory: Callable[..., T] | None = None,
        *,
        aliases: tuple[str, ...] = (),
        replace: bool = False,
    ) -> Callable[[Callable[..., T]], Callable[..., T]] | Callable[..., T]:
        """Register ``factory`` under ``name``; usable as a decorator.

        >>> sources = ComponentRegistry[object]("source")
        >>> @sources.register("noop")
        ... class Noop: ...
        >>> sources.create("noop") is not None
        True
        """

        def _register(func: Callable[..., T]) -> Callable[..., T]:
            if self._frozen:
                raise RegistryError(
                    f"cannot register {self._kind} {name!r}: registry is frozen",
                    context={"kind": self._kind, "name": name},
                )
            for key in (name, *aliases):
                normalised = self._normalise(key)
                if normalised in self._factories and not replace:
                    raise RegistryError(
                        f"{self._kind} {key!r} is already registered",
                        context={"kind": self._kind, "name": key},
                    )
                self._factories[normalised] = func
            return func

        if factory is not None:
            return _register(factory)
        return _register

    def get(self, name: str) -> Callable[..., T]:
        """Look up a factory or raise a :class:`RegistryError` listing options."""
        try:
            return self._factories[self._normalise(name)]
        except KeyError:
            raise RegistryError(
                f"unknown {self._kind} type {name!r}",
                context={"kind": self._kind, "name": name, "available": self.names()},
            ) from None

    def create(self, name: str, /, **kwargs: object) -> T:
        """Instantiate the component registered under ``name``."""
        return self.get(name)(**kwargs)

    def names(self) -> list[str]:
        return sorted(self._factories)

    def freeze(self) -> None:
        self._frozen = True

    def __contains__(self, name: object) -> bool:
        return isinstance(name, str) and self._normalise(name) in self._factories

    def __iter__(self) -> Iterator[str]:
        return iter(sorted(self._factories))

    def __len__(self) -> int:
        return len(self._factories)

    def as_mapping(self) -> Mapping[str, Callable[..., T]]:
        return dict(self._factories)

    @staticmethod
    def _normalise(name: str) -> str:
        return name.strip().lower().replace("-", "_")


__all__ = ["ComponentRegistry"]
