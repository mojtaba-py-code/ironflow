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

What a reference may reach is the operator's decision, not the pipeline's.  A
pipeline file is untrusted input, and a REST sink will carry whatever it
resolves to any public host the file names - so ``env:`` and ``file:`` used to
be a read-anything-and-send-it primitive: ``token: env:IRONFLOW_JWT_SECRET``
went out as a bearer header.  :meth:`SecretResolver.for_pipelines` is the one
constructor code handling a pipeline should use: IronFlow's own settings are
never readable, ``env:`` is limited to ``IRONFLOW_PIPELINE_ENV`` when that is
set, and ``file:`` to ``IRONFLOW_SECRET_FILE_ROOTS``.
"""

from __future__ import annotations

import fnmatch
import logging
import os
from collections.abc import Iterable, Mapping, Sequence
from functools import lru_cache
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


@lru_cache(maxsize=1)
def platform_env_names() -> frozenset[str]:
    """The variables that configure IronFlow itself, upper-cased.

    ``IRONFLOW_JWT_SECRET``, ``IRONFLOW_ENCRYPTION_KEY``,
    ``IRONFLOW_STATE_DATABASE_URL`` and every other setting.  Derived from the
    settings model, so a secret added there is protected without anyone
    remembering to list it here.
    """
    from ironflow.config.settings import Settings  # deferred: config imports security

    return frozenset(f"IRONFLOW_{name.upper()}" for name in Settings.model_fields)


class EnvironmentPolicy:
    """Which process environment variables a pipeline file may read.

    Both routes into the environment - ``${NAME}`` interpolation in the loader
    and ``env:NAME`` references here - go through :meth:`check`.

    IronFlow's own settings are refused unconditionally: no pipeline has a
    reason to read the key that signs API tokens.  Past that, ``allow`` is an
    allow-list of glob patterns; empty means "anything else", which is why
    production refuses to start with it empty.  Names compare case-insensitively
    on Windows, where the environment is case-insensitive, and exactly
    elsewhere - but the platform names are refused in any case, because
    pydantic-settings reads ``ironflow_jwt_secret`` as the setting too.
    """

    __slots__ = ("_allow", "_deny")

    def __init__(self, *, allow: Iterable[str] = (), deny: Iterable[str] = ()) -> None:
        self._allow = tuple(pattern.strip() for pattern in allow if pattern.strip())
        self._deny = frozenset(name.upper() for name in deny)

    @classmethod
    def from_settings(cls, settings: Any) -> EnvironmentPolicy:
        return cls(allow=settings.pipeline_env, deny=platform_env_names())

    @classmethod
    def default(cls) -> EnvironmentPolicy:
        """No allow-list, but the platform's own settings stay off-limits."""
        return cls(deny=platform_env_names())

    def check(self, name: str) -> None:
        if name.upper() in self._deny:
            raise SecretError(
                "pipeline files cannot read IronFlow's own configuration",
                context={"env_var": name},
            )
        if self._allow and not any(fnmatch.fnmatch(name, pattern) for pattern in self._allow):
            raise SecretError(
                "environment variable is not in IRONFLOW_PIPELINE_ENV",
                context={"env_var": name, "allowed": list(self._allow)},
            )


class SecretResolver:
    """Resolves secret references, with a per-instance cache.

    The cache means a pipeline that opens 30 database connections performs one
    scrypt derivation rather than 30 - each derivation is ~100 ms by design.

    ``file:`` references need ``file_roots``: with none, they are refused
    rather than read from anywhere.  ``env:`` references pass ``env_policy``,
    which by default still keeps IronFlow's own settings out of reach.
    """

    def __init__(
        self,
        *,
        crypto: CryptoService | None = None,
        environ: Mapping[str, str] | None = None,
        allow_literal: bool = True,
        file_roots: Sequence[str | Path] = (),
        env_policy: EnvironmentPolicy | None = None,
        encryption_key: str = "",
    ) -> None:
        self._crypto = crypto
        # Turned into a CryptoService on the first `enc:` reference, so a
        # malformed key fails the pipeline that needs it rather than every one.
        self._encryption_key = encryption_key
        self._environ = environ if environ is not None else os.environ
        self._allow_literal = allow_literal
        self._file_roots = tuple(file_roots)
        self._env_policy = env_policy or EnvironmentPolicy.default()
        self._cache: dict[str, SecretStr] = {}

    @classmethod
    def for_pipelines(cls, settings: Any) -> SecretResolver:
        """The resolver for anything a pipeline file names.

        Applies the operator's policy - literal secrets, the environment
        allow-list, the secret-file roots - and carries the platform key, so an
        ``enc:`` reference in a connector actually decrypts.  (Connectors were
        built with no key at all, which made the documented ``enc:`` form fail
        with "no encryption key is configured" even when one was.)
        """
        return cls(
            encryption_key=settings.encryption_key,
            allow_literal=settings.allow_literal_secrets,
            file_roots=tuple(settings.secret_file_roots),
            env_policy=EnvironmentPolicy.from_settings(settings),
        )

    @property
    def crypto(self) -> CryptoService | None:
        if self._crypto is None and self._encryption_key:
            self._crypto = CryptoService.from_key(self._encryption_key)
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
        try:
            self._env_policy.check(var)
        except SecretError as exc:
            exc.with_context(name=name)
            raise
        value = self._environ.get(var)
        if value is None:
            raise SecretError(
                "environment variable is not set",
                context={"name": name, "env_var": var},
            )
        return SecretStr(value, source=f"env:{var}")

    def _from_file(self, path: str, *, name: str) -> SecretStr:
        from ironflow.core.errors import SecurityError
        from ironflow.security.guards import resolve_within

        # `resolve_within` reads an empty root list as "unrestricted", which is
        # right for a caller that has decided so and wrong as a default: with no
        # roots configured, `file:/home/app/.ssh/id_ed25519` in a pipeline file
        # was read and handed to whatever connector asked for it.
        if not self._file_roots:
            raise SecretError(
                "file: secret references are disabled; set IRONFLOW_SECRET_FILE_ROOTS "
                "to the directories secrets may be read from",
                context={"name": name},
            )
        try:
            resolved = resolve_within(path, self._file_roots)
        except SecurityError as exc:
            # Still a SecurityError: an escape attempt must stay distinguishable
            # from a typo in metrics and alerts.
            raise SecurityError(
                "secret file is outside IRONFLOW_SECRET_FILE_ROOTS",
                context={"name": name, "roots": [str(root) for root in self._file_roots]},
            ) from exc
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
        crypto = self.crypto
        if crypto is None:
            raise SecretError(
                "encrypted secret found but no encryption key is configured; "
                "set IRONFLOW_ENCRYPTION_KEY",
                context={"name": name},
            )
        return SecretStr(crypto.decrypt(envelope), source="encrypted")

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


__all__ = ["EnvironmentPolicy", "SecretResolver", "SecretStr", "platform_env_names"]
