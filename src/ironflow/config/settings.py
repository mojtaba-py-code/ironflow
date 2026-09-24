"""Application settings.

Precedence (highest first): explicit constructor argument, environment variable,
``.env`` file, built-in default.  That is the standard twelve-factor ordering and
it is what makes the same image runnable in dev, CI and production without a
rebuild.

Everything here is *platform* configuration (where the state database lives, how
noisy the logs are, whether auth is on).  Pipeline definitions live in YAML and
are modelled separately - conflating the two is how projects end up redeploying
the service to change a filter.

Security defaults are deliberately the strict ones: SSRF protection on, literal
secrets disallowed in production profiles, data roots confined.  A misconfigured
deployment should fail closed.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, computed_field, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

from ironflow.core.errors import ConfigurationError

Environment = Literal["local", "development", "staging", "production"]

#: Below this length a JWT signing secret is guessable, so it is not a secret.
MIN_JWT_SECRET_LENGTH = 32


def _default_home() -> Path:
    """Base directory for state, logs and checkpoints."""
    override = os.environ.get("IRONFLOW_HOME")
    if override:
        return Path(override).expanduser()
    return Path.cwd() / ".ironflow"


class Settings(BaseSettings):
    """Runtime configuration for the platform."""

    model_config = SettingsConfigDict(
        env_prefix="IRONFLOW_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # -- identity ---------------------------------------------------------- #
    environment: Environment = "local"
    service_name: str = "ironflow"

    # -- paths ------------------------------------------------------------- #
    home: Path = Field(default_factory=_default_home)
    pipelines_dir: Path = Field(default=Path("pipelines"))
    # ``NoDecode`` stops pydantic-settings from JSON-decoding the raw env value
    # before our validator runs, so ``IRONFLOW_DATA_ROOTS=/a,/b`` works as well
    # as a JSON array. Without it the plain comma form raises SettingsError.
    data_roots: Annotated[list[Path], NoDecode] = Field(
        default_factory=list,
        description=(
            "Directories connectors may read/write. Empty means unrestricted, "
            "which is refused in production."
        ),
    )

    # -- logging ----------------------------------------------------------- #
    log_level: str = "INFO"
    log_json: bool = False
    log_file: Path | None = None
    log_max_bytes: int = Field(default=50 * 1024 * 1024, ge=1024)
    log_backup_count: int = Field(default=5, ge=0, le=100)

    # -- state store ------------------------------------------------------- #
    state_database_url: str = ""
    state_pool_size: int = Field(default=5, ge=1, le=100)
    state_max_overflow: int = Field(default=10, ge=0, le=100)
    state_echo: bool = False

    # -- execution --------------------------------------------------------- #
    default_batch_size: int = Field(default=10_000, ge=1, le=1_000_000)
    max_parallel_tasks: int = Field(default=4, ge=1, le=64)
    task_timeout: float = Field(default=3600.0, gt=0)
    checkpoint_enabled: bool = True

    # -- security ---------------------------------------------------------- #
    auth_enabled: bool = False
    jwt_secret: str = ""
    jwt_issuer: str = "ironflow"
    jwt_audience: str = "ironflow-api"
    encryption_key: str = ""
    allow_literal_secrets: bool = True
    allow_private_network: bool = Field(
        default=False,
        description="Permit connectors to reach private/loopback addresses (SSRF guard off).",
    )
    audit_enabled: bool = True
    audit_file: Path | None = None
    mask_pii_in_reports: bool = True

    # -- what a pipeline file may read ------------------------------------- #
    # A pipeline file is untrusted input, and both of these used to be
    # unbounded: `${NAME}` and `env:NAME` read any variable in the process -
    # IRONFLOW_JWT_SECRET and IRONFLOW_ENCRYPTION_KEY included - and `file:`
    # read any file the process could open.
    pipeline_env: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description=(
            "Environment variables pipeline files may read through ${NAME} and env:NAME, "
            "as glob patterns (PG*, API_TOKEN). Empty means any variable except IronFlow's "
            "own settings, which is refused in production."
        ),
    )
    secret_file_roots: Annotated[list[Path], NoDecode] = Field(
        default_factory=list,
        description=(
            "Directories file: secret references may read from, e.g. /run/secrets. "
            "Empty disables file: references."
        ),
    )

    # -- http -------------------------------------------------------------- #
    http_timeout: float = Field(default=30.0, gt=0, le=600)
    http_max_retries: int = Field(default=3, ge=0, le=10)
    http_verify_tls: bool = True
    http_max_response_bytes: int = Field(default=256 * 1024 * 1024, ge=1024)
    http_allowed_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description=(
            "If set, the only hosts (and their subdomains) HTTP connectors, OAuth token "
            "endpoints and webhook/Slack notifications may contact."
        ),
    )
    http_private_hosts: Annotated[list[str], NoDecode] = Field(
        default_factory=list,
        description=(
            "Private destinations pipelines may reach despite the SSRF guard: host names "
            "or CIDR ranges. Link-local addresses (cloud metadata) are never reachable."
        ),
    )

    # -- api --------------------------------------------------------------- #
    api_host: str = "127.0.0.1"
    api_port: int = Field(default=8080, ge=1, le=65535)
    api_cors_origins: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # ---------------------------------------------------------------- #
    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}")
        return upper

    @field_validator(
        "data_roots",
        "api_cors_origins",
        "pipeline_env",
        "secret_file_roots",
        "http_allowed_hosts",
        "http_private_hosts",
        mode="before",
    )
    @classmethod
    def _split_csv(cls, value: Any) -> Any:
        """Accept ``A,B,C`` from the environment as well as a JSON list.

        These fields carry ``NoDecode``, so pydantic-settings hands us the raw
        string and this validator owns both forms.
        """
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                import json

                try:
                    return json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"value looks like JSON but does not parse: {exc}") from exc
            return [item.strip() for item in stripped.split(",") if item.strip()]
        return value

    @model_validator(mode="after")
    def _reject_weak_jwt_secret(self) -> Settings:
        """Authentication that is switched on but unkeyed is worse than none.

        ``verify_token`` compares an HMAC computed with ``jwt_secret``.  With an
        empty secret that HMAC is reproducible by anyone, so a self-signed
        ``admin`` token verifies - while the operator believes the API is
        protected.  This used to be checked only under ``environment=production``,
        which left ``staging`` and ``development`` - environments that routinely
        hold a copy of production data - open to exactly that forgery.  The rule
        now holds everywhere, and it fails at construction so the process never
        reaches the point of serving requests.
        """
        if self.auth_enabled and len(self.jwt_secret) < MIN_JWT_SECRET_LENGTH:
            raise ValueError(
                "auth_enabled is true but jwt_secret is shorter than "
                f"{MIN_JWT_SECRET_LENGTH} characters. Set IRONFLOW_JWT_SECRET to a "
                "high-entropy value (for example: openssl rand -base64 48), or set "
                "IRONFLOW_AUTH_ENABLED=false to run without authentication."
            )
        return self

    @model_validator(mode="after")
    def _finalise(self) -> Settings:
        if not self.state_database_url:
            db_path = (self.home / "state.db").as_posix()
            object.__setattr__(self, "state_database_url", f"sqlite:///{db_path}")
        if self.log_file is None and self.environment != "local":
            object.__setattr__(self, "log_file", self.home / "logs" / "ironflow.log")
        if self.audit_file is None:
            object.__setattr__(self, "audit_file", self.home / "audit" / "audit.jsonl")
        return self

    # ---------------------------------------------------------------- #
    @computed_field  # type: ignore[prop-decorator]
    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def checkpoint_dir(self) -> Path:
        return self.home / "checkpoints"

    @property
    def reports_dir(self) -> Path:
        return self.home / "reports"

    def ensure_directories(self) -> None:
        """Create the state directories.  Called once during bootstrap."""
        for directory in (self.home, self.checkpoint_dir, self.reports_dir):
            directory.mkdir(parents=True, exist_ok=True)

    def validate_production_hardening(self) -> list[str]:
        """Return the list of production requirements this config violates.

        Called by ``ironflow config check`` and at API start-up.  Reporting all
        problems at once beats failing on the first one and sending the operator
        around the loop five times.
        """
        problems: list[str] = []
        if not self.is_production:
            return problems
        if not self.auth_enabled:
            problems.append("auth_enabled must be true in production")
        # A weak jwt_secret cannot reach this point: `_reject_weak_jwt_secret`
        # refuses to construct such a Settings in any environment.
        if not self.encryption_key:
            problems.append("encryption_key (IRONFLOW_ENCRYPTION_KEY) must be set")
        if self.allow_literal_secrets:
            problems.append("allow_literal_secrets must be false in production")
        if self.allow_private_network:
            problems.append("allow_private_network must be false in production")
        if not self.data_roots:
            problems.append("data_roots must confine connectors to explicit directories")
        if not self.pipeline_env:
            problems.append(
                "pipeline_env (IRONFLOW_PIPELINE_ENV) must list the environment variables "
                "pipeline files may read"
            )
        if not self.http_verify_tls:
            problems.append("http_verify_tls must not be disabled")
        if not self.audit_enabled:
            problems.append("audit_enabled must be true in production")
        if self.state_database_url.startswith("sqlite"):
            problems.append(
                "state_database_url should point at a server database "
                "(SQLite cannot serve concurrent workers safely)"
            )
        return problems

    def assert_production_hardening(self) -> None:
        problems = self.validate_production_hardening()
        if problems:
            raise ConfigurationError(
                "configuration is not production-hardened",
                context={"problems": problems},
            )

    def redacted(self) -> dict[str, Any]:
        """Settings dump suitable for logs and ``ironflow config show``."""
        from ironflow.security.masking import redact_mapping

        return redact_mapping(self.model_dump(mode="json"))


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Process-wide settings singleton.

    Cached because reading ``.env`` on every access would be wasteful and would
    let the configuration change mid-run, which makes incidents unreproducible.
    Tests call :func:`reset_settings`.
    """
    return Settings()


def reset_settings() -> None:
    """Clear the cache (tests, and after an explicit config reload)."""
    get_settings.cache_clear()


__all__ = ["Settings", "get_settings", "reset_settings"]
