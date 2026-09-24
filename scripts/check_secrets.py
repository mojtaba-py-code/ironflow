#!/usr/bin/env python3
"""Refuse to commit anything that looks like a credential.

Deliberately simple and conservative.  This is a tripwire for the accident -
someone pasting a real DSN into a pipeline file to "test it quickly" - not a
defence against a determined insider.  It runs as a pre-commit hook and in CI.

Every git-tracked file is scanned, ``.github`` included - a workflow file is
exactly where a token gets pasted.  The only exceptions are binary files and
the entries of :data:`ALLOWLIST`, each of which says why it is there.  Outside
a git checkout the working tree is walked instead.

Flagged: private key blocks and AWS, GitHub, Slack and JWT credentials by
format; passwords inside URLs; files whose name means key material
(``*.pem``, ``.env.*``); and a secret-named key assigned a literal, quoted or
not - YAML and ``.env`` files need no quotes.  References and stand-ins are not
secrets and are ignored: ``env:``/``file:``/``enc:`` references, ``${VAR}``,
``***``, ``<password>``, ``changeme``, anything marked as an example, empty
values.

Standard library only, so it runs before anything is installed.

Exit codes: ``0`` clean, ``1`` findings, ``2`` nothing was scanned.
"""

from __future__ import annotations

import fnmatch
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Allowance:
    """A deliberate exception to the scan.

    ``path`` is an fnmatch pattern over the repository-relative path.  With
    ``value`` only that literal is allowed and the rest of the file is still
    scanned; with ``name_only`` only the file's sensitive name is allowed.
    With neither the whole file is skipped - keep that for trees of fixtures.
    """

    path: str
    reason: str
    value: str | None = None
    name_only: bool = False


#: Every exception to the scan, with its reason. Each one is a place a real
#: secret could go unnoticed, so keep them few and as narrow as the reason allows.
ALLOWLIST: tuple[Allowance, ...] = (
    Allowance(
        "tests/*",
        reason="fixtures are fake credentials that exercise redaction and this scanner",
    ),
    Allowance("docs/*", reason="the documentation shows what connection strings look like"),
    Allowance(
        ".env.example",
        name_only=True,
        reason="the template of variables to set; its values are placeholders, and scanned",
    ),
    Allowance(
        ".github/workflows/ci.yml",
        value="ironflow",
        reason="the password of the throwaway PostgreSQL service container that the "
        "integration job starts; it exists only inside that job",
    ),
)

#: Marker an author can add to a line that is a deliberate example.
ALLOW_MARKER = "pragma: allowlist secret"

#: The last word of a key whose value is a secret: ``password``, ``DB_PASSWORD``,
#: ``client_secret``, ``IRONFLOW_JWT_SECRET``, ``api-key``, ``refresh_token`` ...
_SENSITIVE_KEY_ENDING = (
    r"(?:pass(?:word|wd|phrase)|pwd|secret|token|"
    r"(?:api|access|secret|private|signing|encryption|hash|hmac)[_-]?key)"
)


@dataclass(frozen=True)
class Rule:
    """A credential shape. The ``secret`` group, when present, is the value itself."""

    label: str
    pattern: re.Pattern[str]
    #: Minimum length of the value; shorter ones are too weak a signal.
    min_length: int = 0
    #: Whether an unquoted match counts in source code, where it is an expression.
    in_code_unquoted: bool = True


#: Patterns must be specific: a noisy scanner gets disabled, and a disabled
#: scanner protects nothing.
RULES: tuple[Rule, ...] = (
    Rule("private key block", re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----")),
    Rule("AWS access key id", re.compile(r"\b(?P<secret>(?:AKIA|ASIA)[0-9A-Z]{16})\b")),
    Rule(
        "AWS secret access key",
        re.compile(
            r"(?i)\b(?:aws_?)?secret_?access_?key[\"']?\s*[:=]\s*[\"']?"
            r"(?P<secret>[A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"
        ),
    ),
    Rule(
        "GitHub token",
        re.compile(r"\b(?P<secret>gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{36,})"),
    ),
    Rule("Slack token", re.compile(r"\b(?P<secret>xox[baprs]-[0-9A-Za-z][0-9A-Za-z-]{8,})")),
    Rule(
        "Slack webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/(?P<secret>T[A-Za-z0-9/_-]{20,})"),
    ),
    Rule(
        "JSON Web Token",
        re.compile(r"\b(?P<secret>eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,})"),
    ),
    Rule(
        "URL with an inline password",
        # Up to the last "@" of the token: an unencoded password may contain one.
        re.compile(r"\b[A-Za-z][A-Za-z0-9+.\-]*://[^\s:/@'\"]*:(?P<secret>[^\s'\"]+)@[^\s@'\"]"),
        min_length=3,
    ),
    Rule(
        "assigned secret literal",
        # Not after "$" or "${": ${DB_PASSWORD:-dev} is a variable with a default.
        re.compile(
            r"(?i)(?<![\w.\-$])(?<!\$\{)[\w.\-]*?" + _SENSITIVE_KEY_ENDING + r"[\"']?\s*[:=]\s*"
            r"(?:(?P<quote>[\"'])(?P<secret>[^\"'\r\n]*)(?P=quote)|(?P<bare>[^\s\"'#,;)}\]]+))"
        ),
        min_length=8,
        in_code_unquoted=False,
    ),
)

#: Files whose name alone means key material or a filled-in environment.
SENSITIVE_FILE_NAMES = (
    ".env",
    ".env.*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.ppk",
    "*.jks",
    "*.keystore",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
)

#: In these an unquoted right-hand side is an expression, not a literal.
CODE_SUFFIXES = frozenset(
    {".py", ".pyi", ".js", ".jsx", ".ts", ".tsx", ".go", ".java", ".kt", ".rb", ".rs", ".cs"}
)

#: Walked only outside a git checkout: tooling and VCS state, not project content.
_WALK_SKIP_DIRS = frozenset(
    {".git", ".venv", "venv", "node_modules", "__pycache__", ".mypy_cache", ".ruff_cache"}
    | {".pytest_cache", "htmlcov", "build", "dist"}
)

_PLACEHOLDER_WORDS = frozenset(
    {"password", "passwd", "secret", "token", "none", "null", "nil", "true", "false"}
    | {"yes", "no", "on", "off", "undefined", "required", "string", "changeit"}
)
_PLACEHOLDER_PARTS = (
    "example",
    "changeme",
    "change_me",
    "change-me",
    "placeholder",
    "redacted",
    "dummy",
    "your_",
    "your-",
)
#: References (env:, file:, enc:, an encrypted envelope), templates (${VAR},
#: {name}, <name>, %s) and file paths name a secret; they do not contain one.
_REFERENCE_PREFIXES = (
    "env:",
    "file:",
    "enc:",
    "vault:",
    "ironflow:v1:",
    "$",
    "{",
    "<",
    "%",
    "/",
    "./",
    "../",
    "~/",
)


@dataclass(frozen=True)
class Finding:
    line: int
    label: str
    snippet: str
    secret: str | None = None


def is_placeholder(value: str) -> bool:
    """True for a reference, a template or an obvious stand-in rather than a secret."""
    text = value.strip()
    lowered = text.lower()
    return (
        not text
        or lowered in _PLACEHOLDER_WORDS
        or lowered.startswith(_REFERENCE_PREFIXES)
        or any(part in lowered for part in _PLACEHOLDER_PARTS)
        or set(text) <= set("*xX.")
    )


def find_secrets(
    text: str, *, code: bool = False, allowed: frozenset[str] = frozenset()
) -> list[Finding]:
    """Every line of ``text`` that holds a credential, at most one finding per line.

    ``code`` marks source code, where an unquoted assignment is an expression;
    ``allowed`` holds literals an :class:`Allowance` permits in this file.
    """
    findings: list[Finding] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        finding = _first_secret(line, code=code, allowed=allowed)
        if finding is not None:
            label, secret = finding
            findings.append(Finding(number, label, _snippet(line, secret), secret))
    return findings


def _first_secret(
    line: str, *, code: bool, allowed: frozenset[str]
) -> tuple[str, str | None] | None:
    for rule in RULES:
        for match in rule.pattern.finditer(line):
            groups = match.groupdict()
            bare = groups.get("bare")
            if bare is not None and code and not rule.in_code_unquoted:
                continue
            secret = groups.get("secret") if bare is None else bare
            if secret is None:
                return rule.label, None
            if len(secret.strip()) < rule.min_length or is_placeholder(secret):
                continue
            if secret in allowed:
                continue
            if rule.min_length >= 8 and any(char.isspace() for char in secret):
                continue  # a quoted sentence, not a credential
            return rule.label, secret
    return None


def _snippet(line: str, secret: str | None) -> str:
    """The line for context, with the secret masked.

    CI logs are often public: a scanner that echoes what it found has just
    published it a second time.
    """
    text = line.strip()
    if secret:
        text = text.replace(secret, "***")
    return text[:110]


def sensitive_file_label(name: str) -> str | None:
    lowered = name.lower()
    for pattern in SENSITIVE_FILE_NAMES:
        if fnmatch.fnmatchcase(lowered, pattern):
            return f"file that normally holds key material or credentials ({pattern})"
    return None


def allowances_for(relative: str) -> list[Allowance]:
    return [entry for entry in ALLOWLIST if fnmatch.fnmatchcase(relative, entry.path)]


def scan_file(path: Path, relative: str) -> list[Finding] | None:
    """Findings for one file, or ``None`` when it is skipped (allow-listed or binary)."""
    allowances = allowances_for(relative)
    if any(entry.value is None and not entry.name_only for entry in allowances):
        return None
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\0" in data[:8192]:
        return None

    findings: list[Finding] = []
    label = sensitive_file_label(path.name)
    if label and not any(entry.name_only for entry in allowances):
        findings.append(Finding(0, label, ""))
    findings += find_secrets(
        data.decode("utf-8", errors="replace"),
        code=path.suffix.lower() in CODE_SUFFIXES,
        allowed=frozenset(entry.value for entry in allowances if entry.value is not None),
    )
    return findings


def _git(*args: str) -> str:
    """Run git and return its output, decoded as the UTF-8 it writes.

    Not the locale's encoding: on Windows that is a legacy code page, which
    turns a non-ASCII file name into a path that does not exist.
    """
    return subprocess.run(  # noqa: S603 - fixed git subcommands, no shell
        ["git", *args],  # noqa: S607
        capture_output=True,
        check=True,
        encoding="utf-8",
        errors="surrogateescape",
    ).stdout


def repository_root() -> Path:
    try:
        output = _git("rev-parse", "--show-toplevel").strip()
    except (OSError, subprocess.CalledProcessError):
        return Path.cwd()
    return Path(output) if output else Path.cwd()


def candidate_files(argv: list[str], root: Path) -> list[Path]:
    """Decide what to scan.

    Order matters: explicit paths (how pre-commit invokes this) win, then the
    git index, then a filesystem walk.  The walk is not just an
    outside-a-repo fallback - it also covers an *empty* ``git ls-files``, which
    happens when the tree is untracked.  Without it the scanner reported
    "clean" after examining nothing, which is the worst possible outcome for a
    tripwire.  ``-z`` because git quotes unusual names otherwise, and a quoted
    name is a path that does not exist - silently unscanned.
    """
    explicit = [Path(a) for a in argv if Path(a).is_file()]
    if explicit:
        return explicit

    try:
        names = _git("-C", str(root), "ls-files", "-z").split("\0")
        tracked = [root / name for name in names if name]
        if tracked:
            return tracked
    except (OSError, subprocess.CalledProcessError):
        pass

    return [
        path
        for path in root.rglob("*")
        if path.is_file() and not _WALK_SKIP_DIRS.intersection(path.relative_to(root).parts)
    ]


def _relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    root = repository_root()
    total = scanned = skipped = 0
    for path in candidate_files(args, root):
        if not path.is_file():
            continue
        relative = _relative(path, root)
        findings = scan_file(path, relative)
        if findings is None:
            skipped += 1
            continue
        scanned += 1
        for finding in findings:
            total += 1
            where = f"{relative}:{finding.line}" if finding.line else relative
            print(f"{where}: possible {finding.label}", file=sys.stderr)
            if finding.snippet:
                print(f"    {finding.snippet}", file=sys.stderr)

    if total:
        print(
            f"\n{total} possible secret(s) found. Move the value to an environment "
            f"variable and reference it as env:NAME, or add '# {ALLOW_MARKER}' to the "
            "line if it is genuinely an example.",
            file=sys.stderr,
        )
        return 1

    # Report the counts: "clean" after scanning nothing is not clean.
    summary = f"{scanned} file(s) scanned, {skipped} allow-listed or binary"
    if not scanned and not args:
        print(f"nothing was scanned ({summary})", file=sys.stderr)
        return 2
    print(f"no credential-shaped literals found ({summary})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
