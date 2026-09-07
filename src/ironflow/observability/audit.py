"""Append-only audit trail with hash chaining.

Compliance frameworks (SOX, ISO 27001, PCI-DSS 10.x) require that privileged
actions be recorded and that the record be tamper-evident.  Ordinary log files
are neither: anyone with write access can edit a line and nothing detects it.

Each entry stores the SHA-256 of ``previous_hash || canonical_payload``, so the
file forms a hash chain.  Altering or deleting any entry breaks every subsequent
link, and :meth:`AuditLog.verify_chain` finds the first broken index.  This does
not prevent tampering - it makes tampering *detectable*, which is what the
control actually asks for.  Preventing it requires shipping entries off-host,
which is why :class:`AuditLog` also accepts a sink callable.

Payloads run through :func:`redact_mapping` before hashing, so the audit trail
itself never becomes a secrets store.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from ironflow.core.context import utcnow
from ironflow.security.masking import redact_mapping

logger = logging.getLogger(__name__)

GENESIS_HASH = "0" * 64


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

    def compute_hash(self) -> str:
        canonical = json.dumps(self.payload(), sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(f"{self.previous_hash}{canonical}".encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {**self.payload(), "previous_hash": self.previous_hash, "hash": self.entry_hash}


class AuditLog:
    """Thread-safe, append-only, hash-chained audit log."""

    def __init__(
        self,
        path: str | Path | None = None,
        *,
        sink: Callable[[AuditEntry], None] | None = None,
        enabled: bool = True,
    ) -> None:
        self._path = Path(path).expanduser() if path else None
        self._sink = sink
        self._enabled = enabled
        self._lock = threading.Lock()
        self._last_hash = GENESIS_HASH
        if self._path is not None:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            self._last_hash = self._read_last_hash()

    @property
    def path(self) -> Path | None:
        return self._path

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
        with self._lock:
            entry = AuditEntry(
                action=action,
                actor=actor,
                outcome=outcome,
                resource=resource,
                correlation_id=correlation_id,
                details=details,
                previous_hash=self._last_hash,
            )
            entry = AuditEntry(**{**_as_kwargs(entry), "entry_hash": entry.compute_hash()})
            self._last_hash = entry.entry_hash

            if not self._enabled:
                return entry
            if self._path is not None:
                try:
                    with self._path.open("a", encoding="utf-8") as handle:
                        handle.write(json.dumps(entry.to_dict(), default=str) + "\n")
                except OSError:
                    logger.error("failed to persist audit entry", exc_info=True)
            if self._sink is not None:
                try:
                    self._sink(entry)
                except Exception:
                    logger.error("audit sink failed", exc_info=True)
            return entry

    def read(self, limit: int | None = None) -> list[dict[str, Any]]:
        """Read entries back, newest last."""
        if self._path is None or not self._path.exists():
            return []
        entries = [json.loads(line) for line in self._iter_lines()]
        return entries[-limit:] if limit else entries

    def verify_chain(self) -> tuple[bool, int | None]:
        """Re-derive the chain; returns ``(intact, first_broken_index)``."""
        if self._path is None or not self._path.exists():
            return True, None
        previous = GENESIS_HASH
        for index, line in enumerate(self._iter_lines()):
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                return False, index
            if data.get("previous_hash") != previous:
                return False, index
            rebuilt = AuditEntry(
                action=data["action"],
                actor=data["actor"],
                outcome=data["outcome"],
                timestamp=datetime.fromisoformat(data["timestamp"]),
                resource=data.get("resource"),
                correlation_id=data.get("correlation_id"),
                details=data.get("details", {}),
                previous_hash=previous,
            )
            if rebuilt.compute_hash() != data.get("hash"):
                return False, index
            previous = data["hash"]
        return True, None

    def _iter_lines(self) -> Iterator[str]:
        assert self._path is not None
        with self._path.open("r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped:
                    yield stripped

    def _read_last_hash(self) -> str:
        if self._path is None or not self._path.exists():
            return GENESIS_HASH
        last = GENESIS_HASH
        try:
            for line in self._iter_lines():
                last = json.loads(line).get("hash", last)
        except (OSError, json.JSONDecodeError):
            logger.warning("audit log is unreadable or corrupt; starting a new chain")
            return GENESIS_HASH
        return last


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
    }


class NullAuditLog(AuditLog):
    """No-op implementation used in unit tests."""

    def __init__(self) -> None:
        super().__init__(path=None, enabled=False)


__all__ = ["GENESIS_HASH", "AuditEntry", "AuditLog", "NullAuditLog"]
