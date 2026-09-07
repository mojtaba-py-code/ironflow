"""Secret resolution.

A pipeline file never contains a plaintext credential.  Instead it contains a
*reference* that this module resolves at run time:

======================  ====================================================
Reference               Resolution
======================  ====================================================
``env:PGPASSWORD``      ``os.environ["PGPASSWORD"]``
``file:/run/secrets/x`` contents of the file, stripped (Docker/K8s secrets)
``enc:<envelope>``      decrypted with :class:`CryptoService`
``ironflow:v1:...``     a bare ciphertext envelope, decrypted
``literal:<value>``     an explicit escape hatch, warned about at load time
======================  ====================================================

Resolved values are wrapped in :class:`SecretStr`, whose ``__repr__``/``__str__``
render ``***`` so a stray ``print``/f-string/traceback cannot leak them.  The
plaintext is only reachable through the explicit ``.reveal()`` call, which makes
every leak site greppable in review.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ironflow.core.errors import SecretError
from ironflow.security.crypto import CryptoService, is_encrypted

logger = logging.getLogger(__name__)

ENV_PREFIX = "env:"
FILE_PREFIX = "file:"
ENC_PREFIX = "enc:"
LITERAL_PREFIX = "literal:"


class SecretStr:
    """A string that refuses to render itself.

    Not a ``str`` subclass on purpose: inheriting from ``str`` would make the
    value leak through every implicit conversion the language performs.
    """

    __slots__ = ("_source", "_value")

    def __init__(self, value: str, *, source: str = "unknown") -> None:
        self._value = value
        self._source = source

    def reveal(self) -> str:
        """Return the plaintext.  Every call site should be reviewable."""
        return self._value

    @property
    def source(self) -> str:
        return self._source

    def __bool__(self) -> bool:
        return bool(self._value)

    def __len__(self) -> int:
        return len(self._value)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, SecretStr):
            return self._value == other._value
        return NotImplemented

    def __hash__(self) -> int:
        return hash(("SecretStr", self._value))

    def __repr__(self) -> str:
        return f"SecretStr(source={self._source!r}, value='***')"

    def __str__(self) -> str:
        return "***"


class SecretResolver:
    """Resolves secret references, with a per-instance cache.

    The cache means a pipeline that opens 30 database connections performs one
    scrypt derivation rather than 30 - each derivation is ~100 ms by design.
    """

    def __init__(
        self,
        *,
        crypto: CryptoService | None = None,
        environ: Mapping[str, str] | None = None,
        allow_literal: bool = True,
        file_roots: tuple[str, ...] = (),
    ) -> None:
        self._crypto = crypto
        self._environ = environ if environ is not None else os.environ
        self._allow_literal = allow_literal
        self._file_roots = file_roots
        self._cache: dict[str, SecretStr] = {}

    @property
    def crypto(self) -> CryptoService | None:
        return self._crypto

    def resolve(self, reference: Any, *, name: str = "secret") -> SecretStr | None:
        """Resolve a reference to a :class:`SecretStr` (``None`` passes through)."""
        if reference is None:
            return None
        if isinstance(reference, SecretStr):
            return reference
        if not isinstance(reference, str):
            raise SecretError("secret reference must be a string", context={"name": name})

        cached = self._cache.get(reference)
        if cached is not None:
            return cached

        resolved = self._resolve_uncached(reference, name=name)
        self._cache[reference] = resolved
        return resolved

    def reveal(
        self, reference: Any, *, name: str = "secret", default: str | None = None
    ) -> str | None:
        """Resolve and immediately unwrap - for handing to a driver."""
        secret = self.resolve(reference, name=name)
        return secret.reveal() if secret is not None else default

    def resolve_mapping(self, mapping: Mapping[str, Any]) -> dict[str, Any]:
        """Resolve every value in a mapping that looks like a reference."""
        out: dict[str, Any] = {}
        for key, value in mapping.items():
            if isinstance(value, str) and self.is_reference(value):
                out[key] = self.resolve(value, name=key)
            elif isinstance(value, Mapping):
                out[key] = self.resolve_mapping(value)
            else:
                out[key] = value
        return out

    @staticmethod
    def is_reference(value: str) -> bool:
        return value.startswith(
            (ENV_PREFIX, FILE_PREFIX, ENC_PREFIX, LITERAL_PREFIX)
        ) or is_encrypted(value)

    # -- internals --------------------------------------------------------- #
    def _resolve_uncached(self, reference: str, *, name: str) -> SecretStr:
        if reference.startswith(ENV_PREFIX):
            return self._from_env(reference[len(ENV_PREFIX) :].strip(), name=name)
        if reference.startswith(FILE_PREFIX):
            return self._from_file(reference[len(FILE_PREFIX) :].strip(), name=name)
        if reference.startswith(ENC_PREFIX):
            return self._decrypt(reference[len(ENC_PREFIX) :].strip(), name=name)
        if is_encrypted(reference):
            return self._decrypt(reference, name=name)
        if reference.startswith(LITERAL_PREFIX):
            return self._literal(reference[len(LITERAL_PREFIX) :], name=name)
        # No prefix: treat as a literal but complain loudly.
        return self._literal(reference, name=name)

    def _from_env(self, var: str, *, name: str) -> SecretStr:
        if not var:
            raise SecretError("empty environment variable name", context={"name": name})
        value = self._environ.get(var)
        if value is None:
            raise SecretError(
                "environment variable is not set",
                context={"name": name, "env_var": var},
            )
        return SecretStr(value, source=f"env:{var}")

    def _from_file(self, path: str, *, name: str) -> SecretStr:
        from ironflow.security.guards import resolve_within

        resolved = resolve_within(path, self._file_roots)
        if not resolved.is_file():
            raise SecretError(
                "secret file not found", context={"name": name, "path": str(resolved)}
            )
        try:
            content = Path(resolved).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SecretError(
                "unable to read secret file", context={"name": name, "path": str(resolved)}
            ) from exc
        return SecretStr(content, source=f"file:{resolved.name}")

    def _decrypt(self, envelope: str, *, name: str) -> SecretStr:
        if self._crypto is None:
            raise SecretError(
                "encrypted secret found but no encryption key is configured; "
                "set IRONFLOW_ENCRYPTION_KEY",
                context={"name": name},
            )
        return SecretStr(self._crypto.decrypt(envelope), source="encrypted")

    def _literal(self, value: str, *, name: str) -> SecretStr:
        if not self._allow_literal:
            raise SecretError(
                "literal secrets are disabled by policy; use env:, file: or enc:",
                context={"name": name},
            )
        logger.warning(
            "secret %r is stored as a literal value; move it to env:/file:/enc: "
            "before committing this configuration",
            name,
        )
        return SecretStr(value, source="literal")


__all__ = ["SecretResolver", "SecretStr"]
