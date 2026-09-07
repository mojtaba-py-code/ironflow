"""Security building blocks: crypto, secrets, masking, guards and RBAC."""

from __future__ import annotations

from ironflow.security.crypto import CryptoService, generate_key, is_encrypted
from ironflow.security.guards import (
    quote_identifier,
    resolve_within,
    safe_filename,
    validate_identifier,
    validate_url,
)
from ironflow.security.masking import (
    REDACTED,
    detect_pii_columns,
    hash_value,
    mask,
    mask_auto,
    mask_card,
    mask_email,
    redact_mapping,
    redact_url,
)
from ironflow.security.rbac import (
    BUILTIN_ROLES,
    AccessControl,
    Permission,
    Principal,
    Role,
    issue_token,
    principal_from_claims,
    verify_token,
)
from ironflow.security.secrets import SecretResolver, SecretStr

__all__ = [
    "BUILTIN_ROLES",
    "REDACTED",
    "AccessControl",
    "CryptoService",
    "Permission",
    "Principal",
    "Role",
    "SecretResolver",
    "SecretStr",
    "detect_pii_columns",
    "generate_key",
    "hash_value",
    "is_encrypted",
    "issue_token",
    "mask",
    "mask_auto",
    "mask_card",
    "mask_email",
    "principal_from_claims",
    "quote_identifier",
    "redact_mapping",
    "redact_url",
    "resolve_within",
    "safe_filename",
    "validate_identifier",
    "validate_url",
    "verify_token",
]
