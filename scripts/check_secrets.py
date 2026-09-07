#!/usr/bin/env python3
"""Refuse to commit anything that looks like a credential.

Deliberately simple and conservative.  This is a tripwire for the accident -
someone pasting a real DSN into a pipeline file to "test it quickly" - not a
defence against a determined insider.  It runs as a pre-commit hook and in CI.

Exit codes: ``0`` clean, ``1`` findings.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

#: (name, pattern) pairs. Patterns must be specific: a noisy scanner gets
#: disabled, and a disabled scanner protects nothing.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "database URL with an inline password",
        # The password segment must not be a placeholder: `${VAR}`, `***`,
        # `<password>` and `env:NAME` are the documented ways to write one, and
        # flagging them trains people to ignore this scanner.
        re.compile(
            r"(postgresql|postgres|mysql|mongodb)(\+\w+)?://[^:/\s]+:"
            r"(?!\$\{|\*+@|<|env:|%s|\{\{)[^@\s]{3,}@"
        ),
    ),
    (
        "AWS access key id",
        re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    ),
    (
        "private key block",
        re.compile(r"-----BEGIN (RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    (
        "Slack webhook URL",
        re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9/_-]{20,}"),
    ),
    (
        "GitHub token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"),
    ),
    (
        "assigned secret literal",
        re.compile(
            r"(?i)\b(password|passwd|secret|api[_-]?key|access[_-]?token|jwt[_-]?secret)"
            r"\s*[:=]\s*[\"'][A-Za-z0-9+/=_@.\-]{12,}[\"']"
        ),
    ),
)

#: Files whose whole point is to show the shape of a credential.
EXCLUDED_NAMES = {".env.example", "check_secrets.py"}
EXCLUDED_DIRS = {".git", "docs", "tests", ".github", "node_modules", ".venv", "htmlcov"}
SCANNED_SUFFIXES = {".py", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".sh", ".md", ""}

#: Marker an author can add to a line that is a deliberate example.
ALLOW_MARKER = "pragma: allowlist secret"


def candidate_files(argv: list[str]) -> list[Path]:
    """Decide what to scan.

    Order matters: explicit paths (how pre-commit invokes this) win, then the
    git index, then a filesystem walk.  The walk is not just an
    outside-a-repo fallback - it also covers an *empty* ``git ls-files``, which
    happens when the tree is untracked.  Without it the scanner reported
    "clean" after examining nothing, which is the worst possible outcome for a
    tripwire.
    """
    explicit = [Path(a) for a in argv if Path(a).is_file()]
    if explicit:
        return explicit

    try:
        output = subprocess.run(
            ["git", "ls-files"],  # noqa: S607
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        tracked = [Path(line) for line in output.splitlines() if line.strip()]
        if tracked:
            return tracked
    except (OSError, subprocess.CalledProcessError):
        pass

    return [p for p in Path().rglob("*") if p.is_file()]


def should_scan(path: Path) -> bool:
    if path.name in EXCLUDED_NAMES:
        return False
    if any(part in EXCLUDED_DIRS for part in path.parts):
        return False
    return path.suffix.lower() in SCANNED_SUFFIXES


def scan(path: Path) -> list[tuple[int, str, str]]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []

    findings: list[tuple[int, str, str]] = []
    for number, line in enumerate(text.splitlines(), start=1):
        if ALLOW_MARKER in line:
            continue
        for label, pattern in PATTERNS:
            if pattern.search(line):
                findings.append((number, label, line.strip()[:110]))
                break
    return findings


def main(argv: list[str] | None = None) -> int:
    total = 0
    scanned = 0
    for path in candidate_files(argv if argv is not None else sys.argv[1:]):
        if not path.is_file() or not should_scan(path):
            continue
        scanned += 1
        for number, label, snippet in scan(path):
            total += 1
            print(f"{path}:{number}: possible {label}\n    {snippet}", file=sys.stderr)

    if total:
        print(
            f"\n{total} possible secret(s) found. Move the value to an environment "
            f"variable and reference it as env:NAME, or add '# {ALLOW_MARKER}' to the "
            "line if it is genuinely an example.",
            file=sys.stderr,
        )
        return 1

    # Report the file count: "clean" after scanning nothing is not clean.
    print(f"no credential-shaped literals found ({scanned} file(s) scanned)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
