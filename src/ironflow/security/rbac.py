"""Role-based access control and token verification.

Model
-----
``Permission`` is a fine-grained verb-on-noun (``pipeline:run``).  ``Role``
bundles permissions.  ``Principal`` is the authenticated actor and holds roles
plus an optional set of pipeline name patterns it is scoped to - so a team can
be granted ``pipeline:run`` on ``sales_*`` without gaining it everywhere.

The built-in roles follow least privilege: ``viewer`` cannot mutate anything,
``operator`` can run and retry but cannot edit configuration or read secrets,
``admin`` can.  Nothing grants ``secret:read`` except ``admin``.

Token verification implements HS256 JWT validation directly (``hmac`` +
``hashlib``) rather than pulling in a JWT library, and does the three things
CVE reports show implementations getting wrong:

1. The ``alg`` header is checked against an allow-list *before* verification, so
   ``alg: none`` and RS256/HS256 confusion are impossible.
2. The signature is compared in constant time.
3. ``exp``/``nbf``/``iss``/``aud`` are all enforced, with a bounded clock skew.
"""

from __future__ import annotations

import base64
import enum
import fnmatch
import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from ironflow.core.errors import AuthenticationError, AuthorizationError


class Permission(str, enum.Enum):
    """Every guarded action in the platform."""

    PIPELINE_READ = "pipeline:read"
    PIPELINE_RUN = "pipeline:run"
    PIPELINE_WRITE = "pipeline:write"
    PIPELINE_DELETE = "pipeline:delete"
    SCHEDULE_MANAGE = "schedule:manage"
    RUN_HISTORY_READ = "run:read"
    RUN_RETRY = "run:retry"
    METRICS_READ = "metrics:read"
    AUDIT_READ = "audit:read"
    SECRET_READ = "secret:read"  # noqa: S105 - a permission name, not a credential
    SECRET_WRITE = "secret:write"  # noqa: S105 - a permission name, not a credential


@dataclass(frozen=True, slots=True)
class Role:
    """A named bundle of permissions."""

    name: str
    permissions: frozenset[Permission]
    description: str = ""

    def has(self, permission: Permission) -> bool:
        return permission in self.permissions


VIEWER = Role(
    name="viewer",
    description="Read-only access to pipelines, run history and metrics.",
    permissions=frozenset(
        {
            Permission.PIPELINE_READ,
            Permission.RUN_HISTORY_READ,
            Permission.METRICS_READ,
        }
    ),
)

OPERATOR = Role(
    name="operator",
    description="Runs, retries and schedules pipelines. Cannot edit config or read secrets.",
    permissions=VIEWER.permissions
    | frozenset(
        {
            Permission.PIPELINE_RUN,
            Permission.RUN_RETRY,
            Permission.SCHEDULE_MANAGE,
        }
    ),
)

ENGINEER = Role(
    name="engineer",
    description="Authors pipeline definitions in addition to operator rights.",
    permissions=OPERATOR.permissions
    | frozenset({Permission.PIPELINE_WRITE, Permission.AUDIT_READ}),
)

ADMIN = Role(
    name="admin",
    description="Full control including secret management.",
    permissions=frozenset(Permission),
)

BUILTIN_ROLES: dict[str, Role] = {r.name: r for r in (VIEWER, OPERATOR, ENGINEER, ADMIN)}

#: Used by the CLI when authentication is disabled for local development.
SYSTEM_ROLE = ADMIN


@dataclass(frozen=True, slots=True)
class Principal:
    """An authenticated actor."""

    subject: str
    roles: tuple[Role, ...] = ()
    pipeline_scopes: tuple[str, ...] = ("*",)
    attributes: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def system(cls, subject: str = "system") -> Principal:
        """Local/CLI principal used when auth is not enabled."""
        return cls(subject=subject, roles=(SYSTEM_ROLE,))

    @classmethod
    def anonymous(cls) -> Principal:
        return cls(subject="anonymous", roles=(), pipeline_scopes=())

    @property
    def permissions(self) -> frozenset[Permission]:
        out: frozenset[Permission] = frozenset()
        for role in self.roles:
            out |= role.permissions
        return out

    @property
    def role_names(self) -> tuple[str, ...]:
        return tuple(r.name for r in self.roles)

    def has_permission(self, permission: Permission) -> bool:
        return permission in self.permissions

    def can_access_pipeline(self, pipeline_name: str) -> bool:
        return any(fnmatch.fnmatch(pipeline_name, pattern) for pattern in self.pipeline_scopes)

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "roles": list(self.role_names),
            "pipeline_scopes": list(self.pipeline_scopes),
        }


class AccessControl:
    """Central authorisation decision point.

    Every denial is raised as :class:`AuthorizationError`; the caller is
    expected to funnel that into the audit log, which is why the decision is
    made in one place rather than sprinkled through the command handlers.
    """

    def __init__(self, *, enabled: bool = True) -> None:
        self.enabled = enabled

    def authorize(
        self,
        principal: Principal | None,
        permission: Permission,
        *,
        pipeline: str | None = None,
    ) -> Principal:
        """Return the principal if allowed, else raise."""
        if not self.enabled:
            return principal or Principal.system()
        if principal is None:
            raise AuthenticationError(
                "no authenticated principal", context={"permission": permission.value}
            )
        if not principal.has_permission(permission):
            raise AuthorizationError(
                f"principal lacks permission {permission.value}",
                context={
                    "subject": principal.subject,
                    "roles": list(principal.role_names),
                    "permission": permission.value,
                },
            )
        if pipeline is not None and not principal.can_access_pipeline(pipeline):
            raise AuthorizationError(
                "principal is not scoped to this pipeline",
                context={"subject": principal.subject, "pipeline": pipeline},
            )
        return principal

    def check(
        self, principal: Principal | None, permission: Permission, *, pipeline: str | None = None
    ) -> bool:
        """Non-raising variant used to grey out UI actions."""
        try:
            self.authorize(principal, permission, pipeline=pipeline)
        except (AuthenticationError, AuthorizationError):
            return False
        return True


# --------------------------------------------------------------------------- #
# JWT (HS256)
# --------------------------------------------------------------------------- #
_ALLOWED_ALGORITHMS = frozenset({"HS256", "HS384", "HS512"})
_DIGESTS = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    return base64.urlsafe_b64decode(segment + padding)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _require_signing_secret(secret: str) -> None:
    """Refuse to sign or verify with an empty key.

    HMAC with an empty key is still a valid HMAC, so an unkeyed deployment
    accepts any token an attacker signs the same way.  Failing loudly here is
    the last line of defence behind ``Settings._reject_weak_jwt_secret``, and it
    also covers callers that build a token outside the settings object.
    """
    if not secret:
        raise AuthenticationError("no JWT signing secret is configured; set IRONFLOW_JWT_SECRET")


def issue_token(
    claims: dict[str, Any], secret: str, *, algorithm: str = "HS256", expires_in: int = 3600
) -> str:
    """Mint an HS256 JWT (used by the API's local login and by tests)."""
    _require_signing_secret(secret)
    if algorithm not in _ALLOWED_ALGORITHMS:
        raise AuthenticationError("unsupported JWT algorithm", context={"alg": algorithm})
    now = int(datetime.now(UTC).timestamp())
    payload = {"iat": now, "nbf": now, "exp": now + expires_in, **claims}
    header = {"alg": algorithm, "typ": "JWT"}
    signing_input = (
        f"{_b64url_encode(json.dumps(header, separators=(',', ':')).encode())}."
        f"{_b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}"
    )
    signature = hmac.new(
        secret.encode("utf-8"), signing_input.encode("ascii"), _DIGESTS[algorithm]
    ).digest()
    return f"{signing_input}.{_b64url_encode(signature)}"


def verify_token(
    token: str,
    secret: str,
    *,
    algorithms: frozenset[str] = _ALLOWED_ALGORITHMS,
    issuer: str | None = None,
    audience: str | None = None,
    leeway: int = 30,
) -> dict[str, Any]:
    """Verify an HS256/384/512 JWT and return its claims."""
    _require_signing_secret(secret)
    parts = token.split(".")
    if len(parts) != 3:
        raise AuthenticationError("malformed token")

    header_b64, payload_b64, signature_b64 = parts
    try:
        header = json.loads(_b64url_decode(header_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        signature = _b64url_decode(signature_b64)
    except (ValueError, TypeError) as exc:
        raise AuthenticationError("token is not valid base64/JSON") from exc

    algorithm = header.get("alg")
    # Checked *before* verification: never let the token choose "none".
    if algorithm not in algorithms or algorithm not in _DIGESTS:
        raise AuthenticationError("token algorithm is not allowed", context={"alg": algorithm})

    expected = hmac.new(
        secret.encode("utf-8"),
        f"{header_b64}.{payload_b64}".encode("ascii"),
        _DIGESTS[algorithm],
    ).digest()
    if not hmac.compare_digest(expected, signature):
        raise AuthenticationError("token signature verification failed")

    now = int(datetime.now(UTC).timestamp())
    exp = payload.get("exp")
    if exp is not None and now > int(exp) + leeway:
        raise AuthenticationError("token has expired")
    nbf = payload.get("nbf")
    if nbf is not None and now + leeway < int(nbf):
        raise AuthenticationError("token is not yet valid")
    if issuer is not None and payload.get("iss") != issuer:
        raise AuthenticationError("unexpected token issuer")
    if audience is not None:
        aud = payload.get("aud")
        allowed = aud if isinstance(aud, list) else [aud]
        if audience not in allowed:
            raise AuthenticationError("unexpected token audience")
    return payload


def principal_from_claims(claims: dict[str, Any]) -> Principal:
    """Map verified JWT claims onto a :class:`Principal`.

    Unknown role names are dropped rather than failing the request, so removing
    a role from the platform cannot lock out every holder of an existing token.
    """
    role_names = claims.get("roles") or []
    if isinstance(role_names, str):
        role_names = [role_names]
    roles = tuple(BUILTIN_ROLES[name] for name in role_names if name in BUILTIN_ROLES)
    scopes = claims.get("pipelines") or ["*"]
    if isinstance(scopes, str):
        scopes = [scopes]
    return Principal(
        subject=str(claims.get("sub", "unknown")),
        roles=roles,
        pipeline_scopes=tuple(scopes),
        attributes={k: v for k, v in claims.items() if k not in {"roles", "pipelines"}},
    )


__all__ = [
    "ADMIN",
    "BUILTIN_ROLES",
    "ENGINEER",
    "OPERATOR",
    "VIEWER",
    "AccessControl",
    "Permission",
    "Principal",
    "Role",
    "issue_token",
    "principal_from_claims",
    "verify_token",
]
