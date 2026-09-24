"""Append-only audit trail with hash chaining and a head anchor.

Compliance frameworks (SOX, ISO 27001, PCI-DSS 10.x) require that privileged
actions be recorded and that the record be tamper-evident.  Ordinary log files
are neither: anyone with write access can edit a line and nothing detects it.

Chain
    Each entry stores the hash of ``previous_hash || canonical_payload``, so
    altering, inserting or removing an entry breaks the next link, and
    :meth:`AuditLog.verify` names the first broken entry.  A plain SHA-256
    chain, though, proves nothing to someone who can edit the file: they can
    re-derive every hash after their edit.  With ``IRONFLOW_ENCRYPTION_KEY``
    set, entries are chained with HMAC-SHA256 under a key derived from it, and
    rewriting the chain needs that key.  Every entry records its algorithm, so
    a log written before a key was configured still verifies.

Head anchor
    A chain cannot see its own end: deleting the last entries - or the whole
    file - leaves a chain that verifies from genesis.  After every append the
    entry count and head hash are written to ``<audit file>.head`` (MACed when
    keyed), and verification compares the log against it.  An operator who
    records the head off-host can also check the log against that copy, which
    catches what no local file can: the log and its anchor deleted or replaced
    together.

Several writers
    The API, the scheduler and every CLI run audit to the same file.  They take
    turns on ``<audit file>.lock``, and each re-reads the head under the lock
    when another process has written since it last did - chaining from the
    head it read at start-up forked the chain at the first run after anyone
    else's.  The lock is local: on a file system without working locks, give
    each host its own file.

This does not prevent tampering - it makes tampering *detectable*, which is
what the control actually asks for.  Preventing it requires shipping entries
off-host, which is why :class:`AuditLog` also accepts a sink callable.

Payloads run through :func:`redact_mapping` before hashing, so the audit trail
itself never becomes a secrets store.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import sys
import tempfile
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ironflow.core.context import utcnow
from ironflow.core.errors import ConfigurationError
from ironflow.security.masking import redact_mapping

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64

#: Per-entry chaining algorithms. Entries written before the field existed are SHA-256.
SHA256 = "sha256"
HMAC_SHA256 = "hmac-sha256"

#: Suffix of the file that anchors the head of the chain, next to the log.
ANCHOR_SUFFIX = ".head"
#: Suffix of the empty file the writing processes take turns on.
LOCK_SUFFIX = ".lock"

#: How long to wait for another process to release the lock before going on
#: without it: a verification of a very large log holds it for a while.
_LOCK_TIMEOUT_SECONDS = 30.0
_LOCK_POLL_SECONDS = 0.002

_AUDIT_KEY_CONTEXT = b"ironflow-audit-chain-v1"
_ANCHOR_MAC_CONTEXT = "ironflow-audit-head-v1"
_HASH_RE = re.compile(r"[0-9a-f]{64}")  # used with fullmatch: `$` admits a trailing newline


def derive_audit_key(encryption_key: str | None) -> bytes | None:
    """The audit chain's own key, derived from ``IRONFLOW_ENCRYPTION_KEY``.

    Derived rather than reused, so the key that protects secrets is never fed
    to a second primitive.  ``None`` when no encryption key is set, which leaves
    the chain unkeyed.
    """
    if not encryption_key or not encryption_key.strip():
        return None
    material = encryption_key.strip().encode("utf-8")
    return hmac.new(material, _AUDIT_KEY_CONTEXT, hashlib.sha256).digest()


@dataclass(frozen=True, slots=True)
class AuditEntry:
    """One tamper-evident record of a privileged action."""

    action: str
    actor: str
    outcome: str
    timestamp: datetime = field(default_factory=utcnow)
    resource: str | None = None
    correlation_id: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    previous_hash: str = GENESIS_HASH
    entry_hash: str = ""
    algorithm: str = SHA256

    def payload(self) -> dict[str, Any]:
        """The canonical, hash-covered content of the entry."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "action": self.action,
            "actor": self.actor,
            "outcome": self.outcome,
            "resource": self.resource,
            "correlation_id": self.correlation_id,
            "details": redact_mapping(self.details),
        }

    def compute_hash(self, key: bytes | None = None) -> str:
        """Hash the entry with its own algorithm; ``key`` is required for HMAC."""
        canonical = json.dumps(self.payload(), sort_keys=True, separators=(",", ":"), default=str)
        message = f"{self.previous_hash}{canonical}".encode()
        if self.algorithm == HMAC_SHA256:
            if key is None:
                raise ValueError("an hmac-sha256 audit entry cannot be hashed without the key")
            return hmac.new(key, message, hashlib.sha256).hexdigest()
        if self.algorithm == SHA256:
            return hashlib.sha256(message).hexdigest()
        raise ValueError(f"unknown audit hash algorithm {self.algorithm!r}")

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.payload(),
            "previous_hash": self.previous_hash,
            "hash": self.entry_hash,
            "algorithm": self.algorithm,
        }


@dataclass(frozen=True, slots=True)
class ChainVerification:
    """What :meth:`AuditLog.verify` found.

    ``problem`` is a stable code for scripts; ``detail`` says what is wrong in
    words an operator can act on.  ``entries`` and ``head`` describe the chain
    as far as it verified - on success, the head to record off-host - and
    ``keyed`` whether it is HMAC-keyed at that head.
    """

    intact: bool
    entries: int
    head: str
    keyed: bool = False
    broken_at: int | None = None
    problem: str | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "intact": self.intact,
            "broken_at": self.broken_at,
            "problem": self.problem,
            "detail": self.detail,
            "entries": self.entries,
            "head": self.head,
            "keyed": self.keyed,
        }


@dataclass(frozen=True, slots=True)
class _Anchor:
    """The recorded head: how many entries the log had, and the hash of the last."""

    entries: int
    head: str
    mac: str | None = None


class AuditLog:
    """Thread- and process-safe, append-only, hash-chained audit log with a head anchor.

    Writers in other processes are expected: every append, verification and
    read holds ``<audit file>.lock``, and an append first re-reads the head if
    the log changed since this process last touched it.
    """

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        sink: Callable[[AuditEntry], None] | None = None,
        enabled: bool = True,
        key: bytes | None = None,
    ) -> None:
        self._path = Path(path).expanduser() if path else None
        self._sink = sink
        self._enabled = enabled
        self._key = key
        self._algorithm = HMAC_SHA256 if key is not None else SHA256
        self._lock = threading.Lock()
        self._last_hash = GENESIS_HASH
        self._entries = 0
        #: Why the anchor must not be advanced, or None when it may be.
        self._anchor_problem: str | None = None
        self._anchor_problem_logged = False
        #: The log as this process last saw it; None forces a re-read.
        self._seen: tuple[int, int, int] | None = None
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            with self._across_processes():
                self._load_state()

    @property
    def path(self) -> Path | None:
        return self._path

    @property
    def anchor_path(self) -> Path | None:
        """``<audit file>.head``, where the entry count and head hash are anchored."""
        return self._path.with_name(self._path.name + ANCHOR_SUFFIX) if self._path else None

    @property
    def lock_path(self) -> Path | None:
        """``<audit file>.lock``, which every process takes before touching the log."""
        return self._path.with_name(self._path.name + LOCK_SUFFIX) if self._path else None

    @property
    def last_hash(self) -> str:
        return self._last_hash

    def record(
        self,
        action: str,
        *,
        actor: str,
        outcome: str = "success",
        resource: str | None = None,
        correlation_id: str | None = None,
        **details: Any,
    ) -> AuditEntry:
        """Append an entry.  Never raises - auditing must not break the job.

        A failure to write is escalated to ``logger.error`` so the monitoring
        system notices the gap, which is the compromise most audit
        implementations settle on between availability and completeness.
        """
        fields = {
            "action": action,
            "actor": actor,
            "outcome": outcome,
            "resource": resource,
            "correlation_id": correlation_id,
            "details": details,
        }
        with self._lock:
            if not self._enabled or self._path is None:
                entry = self._chain(fields)
            else:
                with self._across_processes():
                    self._catch_up()
                    entry = self._chain(fields)
                    self._append(entry)
            if self._enabled and self._sink is not None:
                try:
                    self._sink(entry)
                except Exception:
                    logger.error("audit sink failed", exc_info=True)
            return entry

    def read(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Read entries back, newest last."""
        if self._path is None or not self._path.exists():
            return []
        with self._lock, self._across_processes():
            entries = [json.loads(line) for line in self._iter_lines()]
        return entries[-limit:] if limit else entries

    def verify(self, *, expect_head: str | None = None) -> ChainVerification:
        """Re-derive the chain and check it against its anchor.

        ``expect_head`` is a head hash recorded earlier, off-host; the log must
        still contain it.  That is the one check a local anchor cannot provide,
        because whoever can delete the log can delete the anchor with it.  The
        first problem found is reported.  Raises :class:`ConfigurationError`
        only for an ``expect_head`` that is not a SHA-256 hex digest.
        """
        expected = _normalise_head(expect_head)
        if self._path is None:
            return ChainVerification(intact=True, entries=0, head=GENESIS_HASH)
        with self._lock, self._across_processes():
            return self._verify(expected)

    def verify_chain(self, *, expect_head: str | None = None) -> tuple[bool, int | None]:
        """:meth:`verify` as ``(intact, first_broken_index)``."""
        result = self.verify(expect_head=expect_head)
        return result.intact, result.broken_at

    # ------------------------------------------------------------------ #
    def _chain(self, fields: dict[str, Any]) -> AuditEntry:
        """The next entry, linked to the current head, which it becomes."""
        entry = AuditEntry(**fields, previous_hash=self._last_hash, algorithm=self._algorithm)
        entry = AuditEntry(**{**_as_kwargs(entry), "entry_hash": entry.compute_hash(self._key)})
        self._last_hash = entry.entry_hash
        return entry

    def _append(self, entry: AuditEntry) -> None:
        assert self._path is not None
        try:
            with self._path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(entry.to_dict(), default=str) + "\n")
        except OSError:
            logger.error("failed to persist audit entry", exc_info=True)
            # The entry is not in the file, so nothing may chain from it: the
            # next append re-reads the head from the file instead.
            self._seen = None
        else:
            self._entries += 1
            self._advance_anchor()
            self._seen = self._signature()

    def _catch_up(self) -> None:
        """Re-read the head if the log changed since this process last saw it."""
        if self._seen is not None and self._signature() == self._seen:
            return
        problem = self._anchor_problem
        self._last_hash, self._entries, self._anchor_problem = GENESIS_HASH, 0, None
        self._load_state()
        if self._anchor_problem != problem:
            self._anchor_problem_logged = False

    def _signature(self) -> tuple[int, int, int]:
        """Identity, size and modification time of the log - enough to see an append.

        Taken from an open handle: a path lookup can be answered from directory
        metadata, which on Windows may lag behind another process's write.
        """
        assert self._path is not None
        try:
            with self._path.open("rb") as handle:
                status = os.fstat(handle.fileno())
        except OSError:
            return (0, -1, 0)
        return (status.st_ino, status.st_size, status.st_mtime_ns)

    @contextmanager
    def _across_processes(self) -> Iterator[None]:
        assert self.lock_path is not None
        with _interprocess_lock(self.lock_path):
            yield

    def _verify(self, expected: str | None) -> ChainVerification:
        assert self._path is not None and self.anchor_path is not None
        anchor_name = self.anchor_path.name
        anchor, anchor_error = self._read_anchor()

        entries = 0
        previous = GENESIS_HASH
        keyed = False
        anchored_hash: str | None = None
        expected_seen = expected == GENESIS_HASH

        def broken(at: int | None, problem: str, detail: str) -> ChainVerification:
            return ChainVerification(
                intact=False,
                entries=entries,
                head=previous,
                keyed=keyed,
                broken_at=at,
                problem=problem,
                detail=detail,
            )

        log_exists = self._path.exists()
        for index, line in enumerate(self._iter_lines() if log_exists else ()):
            try:
                data = json.loads(line)
                algorithm = data.get("algorithm", SHA256)
                stored = data["hash"]
                rebuilt = AuditEntry(
                    action=data["action"],
                    actor=data["actor"],
                    outcome=data["outcome"],
                    timestamp=datetime.fromisoformat(data["timestamp"]),
                    resource=data.get("resource"),
                    correlation_id=data.get("correlation_id"),
                    details=data.get("details", {}),
                    previous_hash=previous,
                    algorithm=algorithm,
                )
            except (ValueError, KeyError, TypeError, AttributeError):
                return broken(index, "entry_unreadable", "it is not a well-formed audit entry")
            if not isinstance(stored, str) or not _HASH_RE.fullmatch(stored):
                return broken(index, "entry_unreadable", "its hash is not a SHA-256 hex digest")
            if data.get("previous_hash") != previous:
                return broken(
                    index,
                    "chain_broken",
                    "it does not link to the entry before it - "
                    "an entry was inserted, removed or reordered",
                )
            if algorithm == HMAC_SHA256:
                if self._key is None:
                    return broken(
                        index,
                        "key_required",
                        "it is keyed (HMAC-SHA256) and no audit key is configured - set "
                        "IRONFLOW_ENCRYPTION_KEY to the platform's key to verify it",
                    )
                keyed = True
            elif algorithm == SHA256:
                if keyed:
                    return broken(
                        index,
                        "downgraded",
                        "it is unkeyed although earlier entries are keyed - the log was "
                        "rewritten without the key from here on, or keying was switched off",
                    )
            else:
                return broken(index, "entry_unreadable", "it names an unknown hash algorithm")
            try:
                recomputed = rebuilt.compute_hash(self._key)
            except (AttributeError, TypeError, ValueError):
                return broken(index, "entry_unreadable", "it is not a well-formed audit entry")
            if not hmac.compare_digest(recomputed, stored):
                reason = "it does not match its hash - it was edited"
                if algorithm == HMAC_SHA256:
                    reason += ", or written under a different IRONFLOW_ENCRYPTION_KEY"
                return broken(index, "entry_modified", reason)
            previous = stored
            entries = index + 1
            if anchor is not None and entries == anchor.entries:
                anchored_hash = previous
            expected_seen = expected_seen or previous == expected

        if anchor_error is not None:
            detail = f"the head anchor {anchor_name} {anchor_error}"
            return broken(None, "anchor_unreadable", detail)
        if anchor is None:
            if entries:
                return broken(
                    None,
                    "anchor_missing",
                    f"the log has {_count(entries)} but no head anchor ({anchor_name}) - it "
                    "was deleted, or the log predates head anchoring, in which case the "
                    "next audited action creates one",
                )
        elif not entries:
            state = "empty" if log_exists else "missing"
            return broken(
                None,
                "log_missing",
                f"the log is {state} but its head anchor records {_count(anchor.entries)}",
            )
        else:
            if anchor.mac is not None:
                if self._key is None:
                    return broken(
                        None,
                        "key_required",
                        "the head anchor is keyed and no audit key is configured - "
                        "set IRONFLOW_ENCRYPTION_KEY to verify it",
                    )
                if not hmac.compare_digest(anchor.mac, _anchor_mac(self._key, anchor)):
                    return broken(
                        None,
                        "anchor_forged",
                        "the head anchor's MAC does not verify - it was written without "
                        "the platform key, or under a different one",
                    )
            elif self._key is not None:
                return broken(
                    None,
                    "anchor_unkeyed",
                    "the head anchor is not keyed although an audit key is configured - the "
                    "log may have been rewritten without the key (if the key was configured "
                    "only just now, the next audited action re-anchors with it)",
                )
            if entries < anchor.entries:
                return broken(
                    entries,
                    "truncated",
                    f"the log ends after {entries} of the {_count(anchor.entries)} its head "
                    "anchor records - the rest were deleted",
                )
            if anchored_hash != anchor.head:
                return broken(
                    anchor.entries - 1,
                    "anchor_mismatch",
                    "it is not the head the anchor records - the log was rewritten",
                )
            if entries > anchor.entries:
                return broken(
                    anchor.entries,
                    "unanchored_entries",
                    f"the anchor covers only the first {anchor.entries} of {_count(entries)} - "
                    "the rest were appended without updating it (an interrupted write, or "
                    "added by hand)",
                )
        if expected is not None and not expected_seen:
            return broken(
                None,
                "expected_head_missing",
                "the expected head is not in the log - entries up to it were deleted or rewritten",
            )
        return ChainVerification(intact=True, entries=entries, head=previous, keyed=keyed)

    def _advance_anchor(self) -> None:
        """Record the new head - unless the log no longer extends the anchor.

        An anchor that the log contradicts is evidence: of truncation, of a
        rewrite, of a deleted anchor.  Rewriting it from this process's view of
        the file would destroy exactly that evidence, so it is left alone, the
        reason is logged at ERROR once, and verification keeps reporting it.
        Recovery is deliberate: move the log and its anchor aside - keep them,
        they are the evidence - and a new chain starts.
        """
        assert self.anchor_path is not None
        if self._anchor_problem is not None:
            if not self._anchor_problem_logged:
                logger.error(
                    "audit head anchor left unchanged: %s; run `ironflow state audit --verify`",
                    self._anchor_problem,
                )
                self._anchor_problem_logged = True
            return
        anchor = _Anchor(entries=self._entries, head=self._last_hash)
        payload: dict[str, Any] = {"entries": anchor.entries, "head": anchor.head}
        if self._key is not None:
            payload["mac"] = _anchor_mac(self._key, anchor)
        try:
            _replace_file(self.anchor_path, json.dumps(payload))
        except OSError:
            logger.error("failed to update the audit head anchor", exc_info=True)

    def _load_state(self) -> None:
        """Find the head of the existing log and decide whether its anchor may advance.

        The anchor may advance when the log extends it, or when there is none
        yet: a new log, or one written before anchoring existed.  Entries that
        carry an ``algorithm`` were written by a version that anchors, so a
        missing anchor beside them was removed, and is not quietly recreated.
        """
        self._seen = self._signature()
        anchor, anchor_error = self._read_anchor()
        entries = 0
        last = GENESIS_HASH
        anchored_hash: str | None = None
        written_with_anchoring = False
        corrupt = False
        try:
            for line in self._iter_lines():
                data = json.loads(line)
                value = data.get("hash") if isinstance(data, dict) else None
                if not isinstance(value, str) or not _HASH_RE.fullmatch(value):
                    corrupt = True
                    break
                last = value
                entries += 1
                written_with_anchoring = "algorithm" in data
                if anchor is not None and entries == anchor.entries:
                    anchored_hash = last
        except FileNotFoundError:
            pass
        except (OSError, ValueError):
            corrupt = True

        self._entries = entries
        if corrupt:
            logger.warning("audit log is unreadable or corrupt; starting a new chain")
            self._anchor_problem = "the log is unreadable or corrupt"
            return
        self._last_hash = last
        if anchor_error is not None:
            self._anchor_problem = f"the head anchor {anchor_error}"
        elif anchor is None:
            if entries and written_with_anchoring:
                self._anchor_problem = "the head anchor is missing"
        elif entries < anchor.entries or anchored_hash != anchor.head:
            self._anchor_problem = "the log does not extend its head anchor"
        elif anchor.mac is not None and self._key is None:
            # Overwriting it unkeyed would downgrade the anchor.
            self._anchor_problem = "the head anchor is keyed but no audit key is configured"
        elif (
            anchor.mac is not None
            and self._key is not None
            and not hmac.compare_digest(anchor.mac, _anchor_mac(self._key, anchor))
        ):
            self._anchor_problem = "the head anchor's MAC does not verify"

    def _read_anchor(self) -> tuple[_Anchor | None, str | None]:
        """The recorded head, and why it is unusable when the file is damaged.

        ``(None, None)`` means there is no anchor file at all.
        """
        assert self.anchor_path is not None
        try:
            raw = self.anchor_path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None, None
        except OSError as exc:
            return None, f"cannot be read ({exc.strerror or exc})"
        try:
            data = json.loads(raw)
        except ValueError:
            return None, "is not valid JSON"
        if not isinstance(data, dict):
            return None, "is not a JSON object"
        entries, head, mac = data.get("entries"), data.get("head"), data.get("mac")
        # Anchors are only written after an append, so a count below one is forged.
        if not isinstance(entries, int) or isinstance(entries, bool) or entries < 1:
            return None, "has no valid entry count"
        if not isinstance(head, str) or not _HASH_RE.fullmatch(head):
            return None, "has no valid head hash"
        if mac is not None and (not isinstance(mac, str) or not _HASH_RE.fullmatch(mac)):
            return None, "has a malformed MAC"
        return _Anchor(entries=entries, head=head, mac=mac), None

    def _iter_lines(self) -> Iterator[str]:
        assert self._path is not None
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    yield stripped


def _count(entries: int) -> str:
    return f"{entries} entry" if entries == 1 else f"{entries} entries"


def _anchor_mac(key: bytes, anchor: _Anchor) -> str:
    message = f"{_ANCHOR_MAC_CONTEXT}\n{anchor.entries}\n{anchor.head}".encode()
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _normalise_head(value: str | None) -> str | None:
    if value is None:
        return None
    head = value.strip().lower()
    if not _HASH_RE.fullmatch(head):
        raise ConfigurationError(
            "an expected audit head must be a 64-character SHA-256 hex digest",
            context={"expected_head": value[:80]},
        )
    return head


if sys.platform == "win32":
    import msvcrt

    def _try_lock(descriptor: int) -> bool:
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
        except OSError:  # held by another process
            return False
        return True

    def _unlock(descriptor: int) -> None:
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)

else:
    import fcntl

    def _try_lock(descriptor: int) -> bool:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:  # held by another process
            return False
        return True

    def _unlock(descriptor: int) -> None:
        fcntl.flock(descriptor, fcntl.LOCK_UN)


@contextmanager
def _interprocess_lock(path: Path) -> Iterator[None]:
    """Hold ``path``'s exclusive lock for the block, so processes take turns.

    Opened read-only - locking needs no more, so an operator who can only read
    the audit directory can still take it.  When it cannot be taken at all - a
    file system without locks, a holder that does not let go in time - the
    block runs anyway, after a warning: an audit entry written without the lock
    beats one not written, and a verification without it beats none.
    """
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CREAT, 0o600)
        deadline = time.monotonic() + _LOCK_TIMEOUT_SECONDS
        while not _try_lock(descriptor):
            if time.monotonic() >= deadline:
                raise TimeoutError("another process has held it too long")
            time.sleep(_LOCK_POLL_SECONDS)
    except OSError as exc:
        logger.warning("audit log lock unavailable (%s); continuing without it", exc)
        if descriptor is not None:
            os.close(descriptor)
            descriptor = None
    try:
        yield
    finally:
        if descriptor is not None:
            with suppress(OSError):
                _unlock(descriptor)
            os.close(descriptor)


def _replace_file(path: Path, text: str) -> None:
    """Write ``text`` to a temporary file and move it over ``path``.

    The replace is atomic, so a reader - or a crash - sees the old anchor or
    the new one, never half of one.  Neither this file nor the log is fsynced;
    after a power cut the anchor can therefore be a step out of line with the
    log, and verification reports that rather than hiding it.
    """
    descriptor, name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
        temporary.replace(path)
    except BaseException:
        with suppress(OSError):
            temporary.unlink()
        raise


def _as_kwargs(entry: AuditEntry) -> dict[str, Any]:
    return {
        "action": entry.action,
        "actor": entry.actor,
        "outcome": entry.outcome,
        "timestamp": entry.timestamp,
        "resource": entry.resource,
        "correlation_id": entry.correlation_id,
        "details": entry.details,
        "previous_hash": entry.previous_hash,
        "algorithm": entry.algorithm,
    }


class NullAuditLog(AuditLog):
    """No-op implementation used in unit tests."""

    def __init__(self) -> None:
        super().__init__(path=None, enabled=False)


__all__ = [
    "ANCHOR_SUFFIX",
    "GENESIS_HASH",
    "HMAC_SHA256",
    "LOCK_SUFFIX",
    "SHA256",
    "AuditEntry",
    "AuditLog",
    "ChainVerification",
    "NullAuditLog",
    "derive_audit_key",
]
