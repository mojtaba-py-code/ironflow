"""Symmetric encryption and key handling.

Choices and rationale
---------------------
* **Fernet (AES-128-CBC + HMAC-SHA256)** rather than raw AES.  Fernet is
  authenticated, versioned and carries its own IV and timestamp, which removes
  the three mistakes hand-rolled AES code usually makes: ECB mode, a reused IV
  and no MAC.
* **Scrypt** for password-derived keys (N=2^15, r=8, p=1).  Scrypt is
  memory-hard, so a leaked ciphertext plus a weak passphrase is far more
  expensive to brute-force than with PBKDF2 at comparable settings.
* **Keys never come from the pipeline YAML.**  The key is read from an
  environment variable or a key file whose permissions are checked.  A YAML file
  lives in git; an environment variable does not.
* **Salts are random per encryption operation** and stored alongside the
  ciphertext, so the same plaintext encrypts to different bytes each time.

The ciphertext envelope is ``ironflow:v1:<b64 salt>:<fernet token>`` so the
format is self-describing and can be rotated without ambiguity.
"""

from __future__ import annotations

import base64
import hmac
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from ironflow.core.errors import ConfigurationError, SecretError

ENVELOPE_PREFIX = "ironflow"
ENVELOPE_VERSION = "v1"
SALT_BYTES = 16

# Scrypt parameters: ~32 MiB of memory per derivation.
_SCRYPT_N = 2**15
_SCRYPT_R = 8
_SCRYPT_P = 1
_KEY_BYTES = 32


def generate_key() -> str:
    """Generate a fresh URL-safe base64 Fernet key."""
    return Fernet.generate_key().decode("ascii")


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a Fernet-compatible key from ``passphrase`` using scrypt."""
    if not passphrase:
        raise ConfigurationError("passphrase must not be empty")
    kdf = Scrypt(salt=salt, length=_KEY_BYTES, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    raw = kdf.derive(passphrase.encode("utf-8"))
    return base64.urlsafe_b64encode(raw)


@dataclass(frozen=True, slots=True)
class CryptoService:
    """Encrypt/decrypt short secrets such as connection passwords.

    Instantiate through :meth:`from_passphrase` (operator-supplied passphrase)
    or :meth:`from_key` (a managed 32-byte key, e.g. from a KMS).
    """

    _key: bytes
    _passphrase: str | None = None

    # -- construction ------------------------------------------------------ #
    @classmethod
    def from_key(cls, key: str | bytes) -> CryptoService:
        raw = key.encode("ascii") if isinstance(key, str) else key
        try:
            Fernet(raw)
        except (ValueError, TypeError) as exc:
            raise ConfigurationError(
                "invalid encryption key: expected 32 url-safe base64-encoded bytes"
            ) from exc
        return cls(_key=raw)

    @classmethod
    def from_passphrase(cls, passphrase: str) -> CryptoService:
        """Passphrase mode - the salt is generated per ``encrypt`` call."""
        return cls(_key=b"", _passphrase=passphrase)

    @classmethod
    def from_env(cls, env_var: str = "IRONFLOW_ENCRYPTION_KEY") -> CryptoService:
        """Load a managed key from the environment.

        Raises rather than falling back to a default key: a silent fallback
        would encrypt production secrets with a key an attacker can read in the
        source tree.
        """
        value = os.environ.get(env_var, "").strip()
        if not value:
            raise SecretError(
                f"environment variable {env_var} is not set",
                context={"env_var": env_var},
            )
        return cls.from_key(value)

    @classmethod
    def from_key_file(cls, path: str | Path) -> CryptoService:
        """Load a key from a file, refusing world/group-readable files."""
        key_path = Path(path).expanduser()
        if not key_path.is_file():
            raise SecretError("key file not found", context={"path": str(key_path)})
        _assert_private_file(key_path)
        return cls.from_key(key_path.read_text(encoding="ascii").strip())

    # -- operations -------------------------------------------------------- #
    def encrypt(self, plaintext: str) -> str:
        """Return the ``ironflow:v1:<salt>:<token>`` envelope for ``plaintext``."""
        salt = secrets.token_bytes(SALT_BYTES)
        fernet = Fernet(self._resolve_key(salt))
        token = fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")
        salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii")
        return f"{ENVELOPE_PREFIX}:{ENVELOPE_VERSION}:{salt_b64}:{token}"

    def decrypt(self, envelope: str) -> str:
        """Reverse :meth:`encrypt`; raises :class:`SecretError` on tampering."""
        parts = envelope.split(":", 3)
        if len(parts) != 4 or parts[0] != ENVELOPE_PREFIX:
            raise SecretError("value is not an IronFlow ciphertext envelope")
        if parts[1] != ENVELOPE_VERSION:
            raise SecretError("unsupported ciphertext version", context={"version": parts[1]})
        try:
            salt = base64.urlsafe_b64decode(parts[2])
        except (ValueError, TypeError) as exc:
            raise SecretError("malformed ciphertext salt") from exc

        fernet = Fernet(self._resolve_key(salt))
        try:
            return fernet.decrypt(parts[3].encode("ascii")).decode("utf-8")
        except InvalidToken as exc:
            # Deliberately vague: distinguishing "wrong key" from "tampered
            # ciphertext" hands an attacker an oracle.
            raise SecretError("unable to decrypt secret (wrong key or tampered data)") from exc

    def _resolve_key(self, salt: bytes) -> bytes:
        if self._passphrase is not None:
            return derive_key(self._passphrase, salt)
        return self._key

    def __repr__(self) -> str:  # pragma: no cover - avoids key leaks in tracebacks
        mode = "passphrase" if self._passphrase is not None else "key"
        return f"CryptoService(mode={mode!r})"


def is_encrypted(value: object) -> bool:
    """Cheap check for the ciphertext envelope prefix."""
    return isinstance(value, str) and value.startswith(f"{ENVELOPE_PREFIX}:{ENVELOPE_VERSION}:")


def constant_time_equals(a: str, b: str) -> bool:
    """Timing-safe string comparison for tokens and signatures."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _assert_private_file(path: Path) -> None:
    """Reject key material readable by anyone other than the owner.

    POSIX only - on Windows the permission bits are not meaningful, so the check
    is skipped rather than producing a false sense of security.
    """
    if os.name != "posix":  # pragma: no cover - platform dependent
        return
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SecretError(
            "key file is accessible by group or others; expected mode 0600",
            context={"path": str(path), "mode": oct(stat.S_IMODE(mode))},
        )


__all__ = [
    "CryptoService",
    "constant_time_equals",
    "derive_key",
    "generate_key",
    "is_encrypted",
]
