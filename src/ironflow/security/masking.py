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
from urllib.parse import unquote

from ironflow.core.errors import ConfigurationError

REDACTED = "***REDACTED***"

#: Digests permitted for pseudonymisation. All are collision-resistant and
#: fixed-length. MD5 and SHA-1 are excluded because a pipeline that asks for one
#: is almost always copying an old example rather than making an informed
#: choice, and this is the one function whose whole purpose is to be
#: irreversible. The variable-length SHAKE family is excluded because it needs a
#: length argument that this signature has nowhere to put.
ALLOWED_HASH_ALGORITHMS: frozenset[str] = frozenset(
    {"sha256", "sha384", "sha512", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s"}
)

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
        # Deliberately not "database_url": that would blank state_database_url
        # in `config show`, hiding the host and database an operator runs it
        # to check. redact_url masks only the credentials inside the URL.
    )
)

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$")
_CARD_RE = re.compile(r"^(?:\d[ -]?){13,19}$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
_PHONE_RE = re.compile(r"^\+?\d[\d\s().-]{7,}\d$")

#: A URL inside arbitrary text - a bare DSN, a log line, an error message. The
#: token runs to the next whitespace rather than to the next "/" or "@",
#: because the credential being hunted may contain either.
_URL_TOKEN_RE = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*://\S*")
#: The ``name=`` of a parameter. Only the name is consumed, so ``;user=u;
#: password=p`` still yields the second parameter after the first.
_URL_PARAM_RE = re.compile(r"(?<=[?&;])(?P<name>[^=&;#?/\s]+)=")
#: Credential parameters whose names :func:`is_sensitive_key` does not cover:
#: ODBC's ``pwd`` and the ``sig`` of an Azure SAS URL, which is a bearer token.
_SENSITIVE_URL_PARAMS = frozenset({"pwd", "sig"})
_URL_MASK = "***"


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

    ``algorithm`` is checked against :data:`ALLOWED_HASH_ALGORITHMS` rather than
    passed straight to :mod:`hashlib`.  A pipeline file asking for ``md5`` would
    otherwise get MD5 tokens silently, in the one operation whose entire purpose
    is that the original cannot be recovered.
    """
    if algorithm not in ALLOWED_HASH_ALGORITHMS:
        raise ConfigurationError(
            "hash algorithm is not allowed for pseudonymisation",
            context={"algorithm": algorithm, "allowed": sorted(ALLOWED_HASH_ALGORITHMS)},
        )
    payload = str(value).encode("utf-8")
    if key is None:
        return hashlib.new(algorithm, payload).hexdigest()
    key_bytes = key.encode("utf-8") if isinstance(key, str) else key
    return hmac.new(key_bytes, payload, algorithm).hexdigest()


def redact_url(url: str) -> str:
    """Mask the credentials in every URL inside ``url``, keeping it diagnosable.

    ``url`` may be a bare URL or any text containing URLs, such as a log line.
    The userinfo password and the values of credential-like query parameters
    (``password``, ``token``, ``api_key``, ``sslpassword``, ``sig`` ...) become
    ``***``; the scheme, user, host, port, database and every other parameter
    stay readable, because they are what an operator needs to see.

    The userinfo is deliberately not handed to ``urlsplit`` or SQLAlchemy's
    ``make_url``. Real DSNs carry unencoded passwords, and both parsers split
    those at the wrong character: ``urlsplit`` ends the authority at the first
    ``/``, so the tail of a base64 password lands in the path; ``make_url`` ends
    the password at its first ``@``. Either way the rest of the password is
    printed as if it were the host. The password is therefore taken as
    everything between the first ``:`` of the userinfo and the *last* ``@``.
    Where the text is ambiguous - an ``@`` after the host, say - that masks
    more than strictly necessary, never less; a leaked password is the worse
    failure. Plain string operations cannot raise, so malformed input (a broken
    IPv6 literal, stray brackets) is masked rather than crashing the log call.
    """
    return _URL_TOKEN_RE.sub(lambda match: _redact_url_token(match.group(0)), url)


def _redact_url_token(token: str) -> str:
    scheme, separator, rest = token.partition("://")
    spans: list[tuple[int, int]] = []

    at = rest.rfind("@")
    colon = rest.find(":", 0, at) if at != -1 else -1
    # A "/", "?", "#" or "[" before that colon means it is not in a userinfo -
    # it is a path, a query, or an IPv6 literal - so there is no password.
    if colon != -1 and not any(char in rest[:colon] for char in "/?#["):
        spans.append((colon + 1, at))

    for match in _URL_PARAM_RE.finditer(rest):
        name = unquote(match.group("name"))
        if is_sensitive_key(name) or name.lower() in _SENSITIVE_URL_PARAMS:
            # The value runs to the next "&", not to ";" or "#": a password may
            # contain either, and masking a fragment by mistake costs nothing.
            end = rest.find("&", match.end())
            spans.append((match.end(), len(rest) if end == -1 else end))

    return f"{scheme}{separator}{_mask_spans(rest, spans)}"


def _mask_spans(text: str, spans: list[tuple[int, int]]) -> str:
    """Replace each span with ``***``, merging overlaps into one mask.

    Empty spans are left alone: showing ``***`` for a password that is not set
    would send an operator chasing the wrong problem.
    """
    merged: list[list[int]] = []
    for start, end in sorted(span for span in spans if span[1] > span[0]):
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    pieces: list[str] = []
    cursor = 0
    for start, end in merged:
        pieces.extend((text[cursor:start], _URL_MASK))
        cursor = end
    pieces.append(text[cursor:])
    return "".join(pieces)


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
    "ALLOWED_HASH_ALGORITHMS",
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
