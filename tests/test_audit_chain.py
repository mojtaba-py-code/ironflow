"""The audit trail must detect truncation, deletion and a re-derived chain.

A hash chain on its own cannot see its end, and an unkeyed one proves nothing
to someone who can edit the file. Before the head anchor and the keyed chain:

* deleting the last N entries left a chain that verified from genesis;
* deleting the whole file reported "audit chain intact";
* anyone who could edit the file could re-derive every hash after an edit.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

from ironflow.cli.context import EXIT_INVALID_CONFIG
from ironflow.cli.main import app
from ironflow.config.settings import get_settings, reset_settings
from ironflow.core.errors import ConfigurationError
from ironflow.observability.audit import (
    GENESIS_HASH,
    HMAC_SHA256,
    SHA256,
    AuditEntry,
    AuditLog,
    derive_audit_key,
)
from ironflow.security.crypto import generate_key
from ironflow.services.pipeline_service import PipelineService

KEY = derive_audit_key(generate_key())
OTHER_KEY = derive_audit_key(generate_key())


# --------------------------------------------------------------------------- #
# Helpers that play the part of someone with write access to the audit files.
# --------------------------------------------------------------------------- #
def anchor_path(log: Path) -> Path:
    return log.with_name(log.name + ".head")


def read_entries(log: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines() if line]


def write_entries(log: Path, entries: list[dict[str, Any]]) -> None:
    log.write_text("".join(json.dumps(entry) + "\n" for entry in entries), encoding="utf-8")


def rederive_unkeyed(
    log: Path, start: int, edit: Callable[[dict[str, Any]], None] = lambda entry: None
) -> list[dict[str, Any]]:
    """Edit entry ``start`` and recompute every hash after it with plain SHA-256.

    This is all an attacker without the key can do: the hash function is
    public, the key is not.
    """
    entries = read_entries(log)
    edit(entries[start])
    previous = entries[start - 1]["hash"] if start else GENESIS_HASH
    for data in entries[start:]:
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
        data.update(previous_hash=previous, hash=rebuilt.compute_hash(), algorithm=SHA256)
        previous = data["hash"]
    write_entries(log, entries)
    return entries


def filled(log: Path, count: int, *, key: bytes | None = None) -> AuditLog:
    audit = AuditLog(log, key=key)
    for index in range(count):
        audit.record("pipeline.run", actor=f"user{index}", resource="sales_daily")
    return audit


def rename_actor(entry: dict[str, Any]) -> None:
    entry["actor"] = "someone-else"


@pytest.fixture
def log(tmp_path: Path) -> Path:
    return tmp_path / "audit" / "audit.jsonl"


# --------------------------------------------------------------------------- #
class TestHeadAnchor:
    def test_every_append_anchors_the_count_and_head(self, log):
        audit = filled(log, 3)
        anchor = json.loads(anchor_path(log).read_text(encoding="utf-8"))
        assert anchor == {"entries": 3, "head": audit.last_hash}
        assert sorted(p.name for p in log.parent.iterdir()) == [
            "audit.jsonl",
            "audit.jsonl.head",
            "audit.jsonl.lock",
        ]

    def test_deleting_the_last_entries_is_detected(self, log):
        filled(log, 5)
        write_entries(log, read_entries(log)[:3])

        result = AuditLog(log).verify()
        assert not result.intact
        assert (result.problem, result.broken_at) == ("truncated", 3)
        assert "ends after 3 of the 5 entries" in result.detail
        assert AuditLog(log).verify_chain() == (False, 3)

    def test_deleting_the_whole_log_is_detected(self, log):
        filled(log, 3)
        log.unlink()
        result = AuditLog(log).verify()
        assert (result.intact, result.problem) == (False, "log_missing")
        assert "missing" in result.detail and "3 entries" in result.detail

    def test_emptying_the_log_is_detected(self, log):
        filled(log, 3)
        log.write_text("", encoding="utf-8")
        result = AuditLog(log).verify()
        assert result.problem == "log_missing"
        assert result.detail.startswith("the log is empty")

    def test_deleting_the_anchor_is_detected(self, log):
        filled(log, 3)
        anchor_path(log).unlink()
        result = AuditLog(log).verify()
        assert (result.intact, result.problem) == (False, "anchor_missing")

    @pytest.mark.parametrize(
        "content",
        [
            "not json",
            "[]",
            '{"entries": 0, "head": "' + "a" * 64 + '"}',
            '{"entries": true, "head": "' + "a" * 64 + '"}',
            '{"entries": 3, "head": "not-a-hash"}',
            '{"entries": 3, "head": "' + "a" * 64 + '", "mac": 7}',
        ],
    )
    def test_an_unreadable_anchor_is_detected(self, log, content):
        filled(log, 3)
        anchor_path(log).write_text(content, encoding="utf-8")
        result = AuditLog(log).verify()
        assert (result.intact, result.problem) == (False, "anchor_unreadable")

    def test_an_unkeyed_rewrite_of_the_tail_no_longer_matches_the_anchor(self, log):
        """The chain re-derives cleanly; only the anchor still knows the old head."""
        filled(log, 3)
        rederive_unkeyed(log, 1, rename_actor)
        result = AuditLog(log).verify()
        assert (result.problem, result.broken_at) == ("anchor_mismatch", 2)

    def test_entries_appended_behind_the_anchors_back_are_reported(self, log):
        filled(log, 2)
        entries = read_entries(log)
        write_entries(log, [*entries, dict(entries[-1])])  # a copy, chained after the head
        rederive_unkeyed(log, 2)
        result = AuditLog(log).verify()
        assert (result.problem, result.broken_at) == ("unanchored_entries", 2)

    def test_a_failed_anchor_update_never_raises_and_heals_on_the_next_append(
        self, log, monkeypatch, caplog
    ):
        audit = filled(log, 2)

        def disk_full(path: Path, text: str) -> None:
            raise OSError("disk full")

        with monkeypatch.context() as patch, caplog.at_level("ERROR"):
            patch.setattr("ironflow.observability.audit._replace_file", disk_full)
            audit.record("pipeline.run", actor="x")  # must not raise
        assert "failed to update the audit head anchor" in caplog.text
        assert AuditLog(log).verify().problem == "unanchored_entries"

        AuditLog(log).record("pipeline.run", actor="y")  # a new process picks up
        assert AuditLog(log).verify().intact


class TestTheWriterKeepsTheEvidence:
    """Re-anchoring from a damaged log would erase the very thing verify reports."""

    def test_a_truncated_log_is_not_re_anchored(self, log, caplog):
        filled(log, 5)
        write_entries(log, read_entries(log)[:3])
        with caplog.at_level("ERROR"):
            AuditLog(log).record("pipeline.run", actor="next-run")
        assert json.loads(anchor_path(log).read_text(encoding="utf-8"))["entries"] == 5
        assert "audit head anchor left unchanged" in caplog.text
        assert AuditLog(log).verify().problem == "truncated"

    def test_a_deleted_log_is_not_re_anchored(self, log):
        filled(log, 3)
        log.unlink()
        AuditLog(log).record("pipeline.run", actor="next-run")
        assert not AuditLog(log).verify().intact

    def test_a_deleted_anchor_is_not_recreated(self, log, caplog):
        filled(log, 3)
        anchor_path(log).unlink()
        with caplog.at_level("ERROR"):
            AuditLog(log).record("pipeline.run", actor="next-run")
        assert not anchor_path(log).exists()
        assert "the head anchor is missing" in caplog.text
        assert AuditLog(log).verify().problem == "anchor_missing"

    def test_a_log_written_before_anchoring_is_anchored_by_the_next_append(self, log):
        """Entries without an ``algorithm`` field predate the anchor; adopt them."""
        filled(log, 3)
        entries = read_entries(log)
        for entry in entries:
            del entry["algorithm"]
        write_entries(log, entries)
        anchor_path(log).unlink()
        assert AuditLog(log).verify().problem == "anchor_missing"

        AuditLog(log).record("pipeline.run", actor="first-run-after-upgrade")
        result = AuditLog(log).verify()
        assert (result.intact, result.entries) == (True, 4)


#: One writing process, started alongside others: it waits for ``go`` so the
#: appends of every writer overlap, and signals ``ready`` once it has opened the
#: log - which is when it reads the head it would otherwise chain from.
WRITER = """
import sys, time
from pathlib import Path
from ironflow.observability.audit import AuditLog
log, go, ready, count = Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), int(sys.argv[4])
audit = AuditLog(log)
ready.touch()
while not go.exists():
    time.sleep(0.001)
for index in range(count):
    audit.record("pipeline.run", actor=f"{ready.name}-{index}")
"""

#: Another process holding the audit lock until it is killed.
HOLDER = """
import sys, time
from pathlib import Path
from ironflow.observability.audit import _interprocess_lock
with _interprocess_lock(Path(sys.argv[1])):
    print("locked", flush=True)
    time.sleep(600)
"""


class TestSeveralWriters:
    """The API, the scheduler and an operator's CLI run all audit to one file.

    Each process used to chain from the head it read when it started, so the
    first run after someone else's reported the trail as tampered with.
    """

    def test_a_long_running_writer_picks_up_what_another_process_appended(self, log):
        server = filled(log, 2)  # `ironflow serve`, up for days
        AuditLog(log).record("pipeline.run", actor="cli")  # an operator's run meanwhile
        server.record("pipeline.run", actor="api")
        result = AuditLog(log).verify()
        assert (result.intact, result.entries) == (True, 4)

    def test_processes_appending_at_once_keep_one_chain(self, log, tmp_path):
        go, writers, count = tmp_path / "go", 3, 120
        readies = [tmp_path / f"writer{number}" for number in range(writers)]
        processes = [
            subprocess.Popen(  # noqa: S603 - the test's own interpreter and script
                [sys.executable, "-c", WRITER, str(log), str(go), str(ready), str(count)]
            )
            for ready in readies
        ]
        try:
            deadline = time.monotonic() + 60
            while not all(ready.exists() for ready in readies):
                assert time.monotonic() < deadline, "a writer did not start"
                assert all(process.poll() is None for process in processes)
                time.sleep(0.01)
            go.touch()
            assert [process.wait(timeout=120) for process in processes] == [0] * writers
        finally:
            for process in processes:
                process.kill()
        result = AuditLog(log).verify()
        assert (result.intact, result.detail) == (True, "")
        assert result.entries == writers * count

    def test_an_append_waits_while_another_process_holds_the_lock(self, log):
        audit = filled(log, 1)
        with subprocess.Popen(  # noqa: S603 - the test's own interpreter and script
            [sys.executable, "-c", HOLDER, str(audit.lock_path)],
            stdout=subprocess.PIPE,
            text=True,
        ) as holder:
            try:
                assert holder.stdout is not None
                assert holder.stdout.readline().strip() == "locked"
                appended = threading.Event()
                writer = threading.Thread(
                    target=lambda: (audit.record("pipeline.run", actor="waits"), appended.set())
                )
                writer.start()
                assert not appended.wait(0.5), "appended while another process held the lock"
                holder.kill()  # the lock goes with the process
                assert appended.wait(30)
                writer.join()
            finally:
                holder.kill()
        assert AuditLog(log).verify().entries == 2

    def test_without_the_lock_the_entry_is_still_written(self, log, monkeypatch, caplog):
        """A file system without locks must not cost the audit trail its entries."""
        audit = filled(log, 1)
        monkeypatch.setattr("ironflow.observability.audit._LOCK_TIMEOUT_SECONDS", 0.05)
        monkeypatch.setattr("ironflow.observability.audit._try_lock", lambda descriptor: False)
        with caplog.at_level("WARNING"):
            audit.record("pipeline.run", actor="unlocked")  # must not raise
        assert "audit log lock unavailable" in caplog.text
        assert AuditLog(log).verify().entries == 2

    def test_a_failed_write_does_not_leave_a_link_to_nothing(self, log, monkeypatch, caplog):
        """The next entry used to chain from the one that never reached the file."""
        audit = filled(log, 2)
        real_open = Path.open

        def disk_full(self: Path, mode: str = "r", *args: Any, **kwargs: Any) -> Any:
            if self == log and "a" in mode:
                raise OSError("disk full")
            return real_open(self, mode, *args, **kwargs)

        with monkeypatch.context() as patch, caplog.at_level("ERROR"):
            patch.setattr(Path, "open", disk_full)
            audit.record("pipeline.run", actor="lost")  # must not raise
        assert "failed to persist audit entry" in caplog.text

        audit.record("pipeline.run", actor="next")
        result = AuditLog(log).verify()
        assert (result.intact, result.entries) == (True, 3)


class TestExpectedHead:
    def test_a_head_recorded_earlier_verifies_after_more_entries(self, log):
        audit = filled(log, 3)
        recorded = audit.verify().head
        audit.record("pipeline.run", actor="later")
        assert AuditLog(log).verify(expect_head=recorded).intact

    def test_it_catches_the_log_and_anchor_deleted_together(self, log):
        """Nothing local is left to compare; only the off-host copy knows."""
        recorded = filled(log, 3).verify().head
        log.unlink()
        anchor_path(log).unlink()
        assert AuditLog(log).verify().intact
        result = AuditLog(log).verify(expect_head=recorded)
        assert (result.intact, result.problem) == (False, "expected_head_missing")

    def test_it_catches_a_log_and_anchor_rewritten_together(self, log):
        """An unkeyed log and anchor can be forged consistently - but not the old head."""
        recorded = filled(log, 3).verify().head
        forged = rederive_unkeyed(log, 0, rename_actor)
        anchor_path(log).write_text(
            json.dumps({"entries": 3, "head": forged[-1]["hash"]}), encoding="utf-8"
        )
        assert AuditLog(log).verify().intact
        assert AuditLog(log).verify(expect_head=recorded).problem == "expected_head_missing"

    def test_case_and_surrounding_whitespace_are_ignored(self, log):
        recorded = filled(log, 2).verify().head
        assert AuditLog(log).verify(expect_head=f"  {recorded.upper()}\n").intact

    @pytest.mark.parametrize("value", ["", "abc", "g" * 64, "a" * 63])
    def test_a_malformed_head_is_rejected(self, log, value):
        filled(log, 1)
        with pytest.raises(ConfigurationError, match="64-character"):
            AuditLog(log).verify(expect_head=value)


class TestKeyedChain:
    def test_the_audit_key_is_derived_not_reused(self):
        encryption_key = generate_key()
        derived = derive_audit_key(encryption_key)
        expected = hmac.new(
            encryption_key.encode(), b"ironflow-audit-chain-v1", hashlib.sha256
        ).digest()
        assert derived == expected
        assert derived != encryption_key.encode()
        assert derive_audit_key(f"  {encryption_key}\n") == derived
        for empty in (None, "", "   "):
            assert derive_audit_key(empty) is None

    def test_entries_and_anchor_are_keyed(self, log):
        audit = filled(log, 2, key=KEY)
        entries = read_entries(log)
        assert {entry["algorithm"] for entry in entries} == {HMAC_SHA256}
        anchor = json.loads(anchor_path(log).read_text(encoding="utf-8"))
        assert set(anchor) == {"entries", "head", "mac"}
        result = AuditLog(log, key=KEY).verify()
        assert (result.intact, result.keyed, result.head) == (True, True, audit.last_hash)

    def test_verifying_a_keyed_log_needs_the_key(self, log):
        filled(log, 2, key=KEY)
        result = AuditLog(log).verify()
        assert (result.problem, result.broken_at) == ("key_required", 0)
        assert "IRONFLOW_ENCRYPTION_KEY" in result.detail

    def test_an_edit_with_the_hash_recomputed_the_only_way_possible_is_detected(self, log):
        """Keep the keyed label and recompute SHA-256: the HMAC does not match."""
        filled(log, 3, key=KEY)
        entries = rederive_unkeyed(log, 1, rename_actor)
        for entry in entries[1:]:
            entry["algorithm"] = HMAC_SHA256
        write_entries(log, entries)
        result = AuditLog(log, key=KEY).verify()
        assert (result.problem, result.broken_at) == ("entry_modified", 1)

    def test_rewriting_the_tail_unkeyed_is_a_downgrade(self, log):
        filled(log, 3, key=KEY)
        forged = rederive_unkeyed(log, 1, rename_actor)
        anchor_path(log).write_text(
            json.dumps({"entries": 3, "head": forged[-1]["hash"]}), encoding="utf-8"
        )
        result = AuditLog(log, key=KEY).verify()
        assert (result.problem, result.broken_at) == ("downgraded", 1)

    def test_rewriting_everything_unkeyed_leaves_an_unkeyed_anchor(self, log):
        filled(log, 3, key=KEY)
        forged = rederive_unkeyed(log, 0, rename_actor)
        anchor_path(log).write_text(
            json.dumps({"entries": 3, "head": forged[-1]["hash"]}), encoding="utf-8"
        )
        assert AuditLog(log, key=KEY).verify().problem == "anchor_unkeyed"

    def test_rewriting_everything_unkeyed_but_keeping_the_anchor(self, log):
        filled(log, 3, key=KEY)
        rederive_unkeyed(log, 0, rename_actor)
        assert AuditLog(log, key=KEY).verify().problem == "anchor_mismatch"

    def test_truncating_and_forging_the_anchor_mac_is_detected(self, log):
        filled(log, 3, key=KEY)
        entries = read_entries(log)[:2]
        write_entries(log, entries)
        anchor_path(log).write_text(
            json.dumps({"entries": 2, "head": entries[-1]["hash"], "mac": "0" * 64}),
            encoding="utf-8",
        )
        assert AuditLog(log, key=KEY).verify().problem == "anchor_forged"

    def test_a_different_key_is_named_as_a_possible_cause(self, log):
        filled(log, 2, key=KEY)
        result = AuditLog(log, key=OTHER_KEY).verify()
        assert (result.problem, result.broken_at) == ("entry_modified", 0)
        assert "different IRONFLOW_ENCRYPTION_KEY" in result.detail

    def test_a_log_started_unkeyed_keeps_verifying_once_keyed(self, log):
        """Old entries record their algorithm, so configuring a key breaks nothing."""
        filled(log, 3)
        keyed = AuditLog(log, key=KEY)
        keyed.record("pipeline.run", actor="after-the-key")
        assert [entry["algorithm"] for entry in read_entries(log)] == [SHA256] * 3 + [HMAC_SHA256]
        result = AuditLog(log, key=KEY).verify()
        assert (result.intact, result.keyed, result.entries) == (True, True, 4)

    def test_removing_the_key_does_not_downgrade_the_anchor(self, log, caplog):
        filled(log, 2, key=KEY)
        anchored = anchor_path(log).read_text(encoding="utf-8")
        with caplog.at_level("ERROR"):
            AuditLog(log).record("pipeline.run", actor="no-key-any-more")
        assert anchor_path(log).read_text(encoding="utf-8") == anchored
        assert "keyed but no audit key is configured" in caplog.text
        assert AuditLog(log, key=KEY).verify().problem == "downgraded"


class TestServiceWiring:
    def test_the_service_keys_its_chain_from_the_encryption_key(self, settings, database):
        keyed_settings = settings.model_copy(update={"encryption_key": generate_key()})
        service = PipelineService(keyed_settings, database=database)
        service.audit.record("state.clean", actor="tester")
        entries = service.audit.read()
        assert entries[-1]["algorithm"] == HMAC_SHA256
        assert service.audit.verify().intact

    def test_without_an_encryption_key_the_chain_is_unkeyed(self, service):
        service.audit.record("state.clean", actor="tester")
        assert service.audit.read()[-1]["algorithm"] == SHA256


class TestCli:
    runner = CliRunner()

    @pytest.fixture
    def audit_log(self, tmp_path: Path, monkeypatch) -> Path:
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("IRONFLOW_HOME", str(tmp_path / ".ironflow"))
        monkeypatch.setenv("COLUMNS", "400")
        # No forced colour: CI sets FORCE_COLOR, and Rich's styling would put
        # escape sequences into the text these tests read.
        for variable in ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE"):
            monkeypatch.delenv(variable, raising=False)
        reset_settings()
        path = get_settings().audit_file
        assert path is not None
        return path

    def invoke(self, *args: str):
        return self.runner.invoke(app, list(args), catch_exceptions=False)

    def test_an_intact_chain_prints_its_head_for_recording_off_host(self, audit_log):
        head = filled(audit_log, 2).last_hash
        result = self.invoke("state", "audit", "--verify")
        assert result.exit_code == 0
        assert "audit chain intact (2 entries, SHA-256, unkeyed)" in result.stdout
        assert f"head: {head}" in result.stdout

    def test_truncation_fails_with_the_reason(self, audit_log):
        filled(audit_log, 2)
        write_entries(audit_log, read_entries(audit_log)[:1])
        result = self.invoke("state", "audit", "--verify")
        assert result.exit_code == EXIT_INVALID_CONFIG
        assert "audit chain broken at entry 1: the log ends after 1 of the 2 entries" in (
            result.stdout
        )

    def test_a_deleted_log_is_no_longer_intact(self, audit_log):
        filled(audit_log, 2)
        audit_log.unlink()
        result = self.invoke("state", "audit", "--verify")
        assert result.exit_code == EXIT_INVALID_CONFIG
        assert "the log is missing" in result.stdout

    def test_expect_head_implies_verify(self, audit_log):
        head = filled(audit_log, 2).last_hash
        assert self.invoke("state", "audit", "--expect-head", head).exit_code == 0
        other = self.invoke("state", "audit", "--expect-head", "ab" * 32)
        assert other.exit_code == EXIT_INVALID_CONFIG
        assert "the expected head is not in the log" in other.stdout

    def test_a_malformed_expected_head_is_a_usage_error(self, audit_log):
        filled(audit_log, 1)
        result = self.invoke("state", "audit", "--verify", "--expect-head", "nope")
        assert result.exit_code == EXIT_INVALID_CONFIG
        assert "64-character" in result.stderr

    def test_json_names_the_problem(self, audit_log):
        filled(audit_log, 2)
        anchor_path(audit_log).unlink()
        result = self.invoke("--json", "state", "audit", "--verify")
        payload = json.loads(result.stdout)
        assert payload["intact"] is False
        assert payload["broken_at"] is None
        assert payload["problem"] == "anchor_missing"
        assert payload["entries"] == 2

    def test_a_keyed_chain_verifies_through_the_cli(self, audit_log, monkeypatch):
        encryption_key = generate_key()
        filled(audit_log, 2, key=derive_audit_key(encryption_key))
        assert self.invoke("state", "audit", "--verify").exit_code == EXIT_INVALID_CONFIG

        monkeypatch.setenv("IRONFLOW_ENCRYPTION_KEY", encryption_key)
        reset_settings()
        result = self.invoke("state", "audit", "--verify")
        assert result.exit_code == 0
        assert "(2 entries, HMAC-SHA256)" in result.stdout
