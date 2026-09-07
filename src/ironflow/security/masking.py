"""PII masking, pseudonymisation and log redaction primitives.

Three distinct operations that are often conflated:

``mask``
    Irreversible, human-readable partial hiding (``j***@example.com``).  Used in
    reports and support tooling where a human needs to recognise a value.
``hash_value``
    Deterministic pseudonymisation with a keyed HMAC-SHA256.  Same input plus
    same key gives the same token, so joins still work downstream, but the token
    cannot be reversed and cannot be rainbow-tabled because of the key.  A plain
    SHA-256 of an email address is *not* anonymisation - the space is small
    enough to enumerate.
``redact``
    Wholesale replacement with ``***`` for anything heading into a log sink.

The detectors are intentionally conservative regexes: they are a safety net for
values a developer forgot to declare sensitive, not a substitute for declaring
them in the schema.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import Iterable, Mapping
from typing import Any

REDACTED = "***REDACTED***"

#: Key names whose values must never reach a log or a report.
SENSITIVE_KEY_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"pass(word|wd|phrase)?$",
        r"secret",
        r"token",
        r"api[_-]?key",
        r"access[_-]?key",
        r"private[_-]?key",
        # Catches encryption_key, signing_key, jwt_key, and a bare "key".
        r"(^|[_-])key$",
        r"encryption",
        r"signature",
        r"credential",
        r"authorization",
        r"auth$",
        r"session[_-]?id",
        r"cookie",
        r"ssn",
        r"national[_-]?id",
        r"card[_-]?number",
        r"cvv",
        r"iban",
        r"dsn",
        r"connection[_-]?string",
    )
)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_CARD_RE = re.compile(r"^(?:\d[ -]?){13,19}$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_PHONE_RE = re.compile(r"^\+?\d[\d\s().-]{7,}\d$")
_URL_CREDENTIALS_RE = re.compile(r"(?P<scheme>[a-zA-Z][\w+.-]*://)(?P<user>[^/@\s:]+):[^/@\s]*@")


def is_sensitive_key(key: str) -> bool:
    """True when a mapping key looks like it holds a secret."""
    return any(pattern.search(key) for pattern in SENSITIVE_KEY_PATTERNS)


def looks_like_pii(value: str) -> bool:
    """Heuristic detector used to warn operators about undeclared PII."""
    candidate = value.strip()
    if not candidate:
        return False
    return bool(
        _EMAIL_RE.match(candidate)
        or _IPV4_RE.match(candidate)
        or (_CARD_RE.match(candidate) and luhn_valid(candidate))
        or _PHONE_RE.match(candidate)
    )


def luhn_valid(number: str) -> bool:
    """Luhn checksum - separates real card numbers from long digit strings."""
    digits = [int(c) for c in re.sub(r"[ -]", "", number) if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def mask(value: Any, *, keep_start: int = 0, keep_end: int = 4, mask_char: str = "*") -> str:
    """Partially hide a value while keeping it recognisable.

    Short values are masked entirely - revealing 4 of 5 characters is not
    masking.
    """
    text = str(value)
    if not text:
        return text
    keep_start = max(0, keep_start)
    keep_end = max(0, keep_end)
    if len(text) <= keep_start + keep_end or len(text) < 4:
        return mask_char * len(text)
    head = text[:keep_start]
    tail = text[len(text) - keep_end :] if keep_end else ""
    return f"{head}{mask_char * (len(text) - keep_start - keep_end)}{tail}"


def mask_email(value: Any) -> str:
    """``john.doe@corp.com`` -> ``j*******@corp.com``."""
    text = str(value)
    if "@" not in text:
        return mask(text, keep_end=0)
    local, _, domain = text.partition("@")
    hidden = local[0] + "*" * max(1, len(local) - 1) if local else "*"
    return f"{hidden}@{domain}"


def mask_card(value: Any) -> str:
    """Keep the last four digits, the maximum PCI-DSS permits for display."""
    digits = re.sub(r"\D", "", str(value))
    if len(digits) <= 4:
        return "*" * len(digits)
    return "*" * (len(digits) - 4) + digits[-4:]


def mask_auto(value: Any) -> str:
    """Pick the most appropriate masker for a value's apparent type."""
    text = str(value)
    if _EMAIL_RE.match(text):
        return mask_email(text)
    if _CARD_RE.match(text) and luhn_valid(text):
        return mask_card(text)
    return mask(text)


def hash_value(value: Any, *, key: str | bytes | None = None, algorithm: str = "sha256") -> str:
    """Deterministic pseudonymisation.

    With ``key`` the result is an HMAC (recommended - resistant to dictionary
    attacks).  Without a key it degrades to a plain digest, which is acceptable
    only for high-entropy inputs such as UUIDs.
    """
    payload = str(value).encode("utf-8")
    if key is None:
        return hashlib.new(algorithm, payload).hexdigest()
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    return hmac.new(key_bytes, payload, algorithm).hexdigest()


def redact_url(url: str) -> str:
    """Strip the password from a URL while keeping it diagnosable."""
    return _URL_CREDENTIALS_RE.sub(r"\g<scheme>\g<user>:***@", url)


def is_redactable(value: Any) -> bool:
    """Only values that could actually carry a secret are worth redacting.

    A bool or a number cannot hold a credential, and blanking
    ``allow_literal_secrets: false`` would hide a policy flag an operator needs
    to see in ``ironflow config show`` while protecting nothing.
    """
    return not isinstance(value, (bool, int, float)) and value is not None


def redact_value(key: str, value: Any) -> Any:
    """Redact ``value`` when ``key`` names a secret, else pass it through."""
    if is_sensitive_key(key) and is_redactable(value):
        return REDACTED
    if isinstance(value, str) and "://" in value:
        return redact_url(value)
    return value


def redact_mapping(
    data: Mapping[str, Any], *, extra_keys: Iterable[str] = (), _depth: int = 0
) -> dict[str, Any]:
    """Recursively redact a mapping before it reaches a log or an API response.

    Recursion is capped at 12 levels so a self-referential structure cannot
    turn a log call into a stack overflow.
    """
    if _depth > 12:  # pragma: no cover - defensive bound
        return {"...": "max depth reached"}
    extra = {k.lower() for k in extra_keys}
    result: dict[str, Any] = {}
    for key, value in data.items():
        if (is_sensitive_key(key) or key.lower() in extra) and is_redactable(value):
            result[key] = REDACTED
        elif isinstance(value, Mapping):
            result[key] = redact_mapping(value, extra_keys=extra, _depth=_depth + 1)
        elif isinstance(value, (list, tuple)):
            result[key] = [
                redact_mapping(v, extra_keys=extra, _depth=_depth + 1)
                if isinstance(v, Mapping)
                else redact_value(key, v)
                for v in value
            ]
        else:
            result[key] = redact_value(key, value)
    return result


def detect_pii_columns(records: Iterable[Mapping[str, Any]], sample: int = 100) -> dict[str, str]:
    """Scan a record sample and report columns that look like PII.

    Returns ``{column: detected_kind}``.  Surfaced by ``ironflow pipeline
    validate`` so an operator finds undeclared PII before the first production
    run, not after.
    """
    findings: dict[str, str] = {}
    for index, record in enumerate(records):
        if index >= sample:
            break
        for key, value in record.items():
            if key in findings:
                continue
            if is_sensitive_key(key):
                findings[key] = "sensitive_name"
            elif isinstance(value, str):
                text = value.strip()
                if _EMAIL_RE.match(text):
                    findings[key] = "email"
                elif _CARD_RE.match(text) and luhn_valid(text):
                    findings[key] = "card_number"
                elif _IPV4_RE.match(text):
                    findings[key] = "ip_address"
                elif _PHONE_RE.match(text):
                    findings[key] = "phone"
    return findings


__all__ = [
    "REDACTED",
    "detect_pii_columns",
    "hash_value",
    "is_redactable",
    "is_sensitive_key",
    "looks_like_pii",
    "luhn_valid",
    "mask",
    "mask_auto",
    "mask_card",
    "mask_email",
    "redact_mapping",
    "redact_url",
    "redact_value",
]
