"""Tests for structured logging, metrics, the audit trail and resource sampling."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from ironflow.core.context import ExecutionContext
from ironflow.observability.audit import GENESIS_HASH, AuditLog, NullAuditLog
from ironflow.observability.logging import (
    ContextFilter,
    JsonFormatter,
    RedactionFilter,
    configure_logging,
)
from ironflow.observability.metrics import METRICS, MetricsRegistry
from ironflow.observability.resources import ResourceMonitor, sample_resources
from ironflow.security.masking import REDACTED


def make_record(message: str = "hello", *, args=None, **extra) -> logging.LogRecord:
    record = logging.LogRecord("test", logging.INFO, "f.py", 1, message, args, None)
    for key, value in extra.items():
        setattr(record, key, value)
    return record


class TestLogging:
    def test_context_filter_stamps_identity(self):
        context = ExecutionContext(pipeline_id="p", task_id="t")
        record = make_record()
        with context.bind():
            ContextFilter().filter(record)
        assert record.pipeline_id == "p"
        assert record.task_id == "t"

    def test_redaction_filter_scrubs_extras(self):
        record = make_record(password="hunter2", username="alice")
        RedactionFilter().filter(record)
        assert record.password == REDACTED
        assert record.username == "alice"

    def test_redaction_filter_scrubs_urls_in_the_message(self):
        record = make_record("connecting to postgresql://u:hunter2@db/prod")
        RedactionFilter().filter(record)
        assert "hunter2" not in record.getMessage()

    def test_a_dsn_passed_as_an_argument_is_scrubbed(self):
        """The commonest way to write it, and the one that used to leak.

        Only the format string was scrubbed, so `log.info("connect %s", dsn)`
        put the password straight on disk.
        """
        record = make_record("connecting to %s", args=("postgresql://u:hunter2@db/prod",))
        RedactionFilter().filter(record)
        assert "hunter2" not in record.getMessage()

    def test_a_placeholder_inside_the_credentials_does_not_destroy_the_record(self):
        """`redact_url` treats everything between ":" and "@" as the password.

        Rewriting the format string therefore deleted the `%s` itself -
        "postgres://u:%s@h" became "postgres://u:***@h" - and the record could
        no longer be interpolated, so logging dropped the line and printed a
        TypeError to stderr instead.
        """
        record = make_record("connecting to postgresql://u:%s@db/prod", args=("hunter2",))
        RedactionFilter().filter(record)
        message = record.getMessage()  # must not raise
        assert "hunter2" not in message
        assert "postgresql://u:***@db/prod" in message

    def test_several_arguments_are_all_considered(self):
        record = make_record("%s -> %s", args=("start", "mysql://u:hunter2@h/db"))
        RedactionFilter().filter(record)
        assert "hunter2" not in record.getMessage()
        assert record.getMessage().startswith("start -> ")

    def test_a_mismatched_format_string_is_left_for_logging_to_report(self):
        """A format string that does not match its args is the caller's bug.

        The filter must not swallow it, or the real error becomes invisible.
        """
        record = make_record("no placeholders here", args=("extra",))
        assert RedactionFilter().filter(record) is True
        assert record.args == ("extra",)

    def test_redaction_filter_handles_nested_mappings(self):
        record = make_record(config={"nested": {"api_key": "abc"}})
        RedactionFilter().filter(record)
        assert record.config["nested"]["api_key"] == REDACTED

    def test_json_formatter_emits_one_object_per_line(self):
        record = make_record("something happened", rows=42)
        payload = json.loads(JsonFormatter(service="ironflow").format(record))
        assert payload["message"] == "something happened"
        assert payload["level"] == "INFO"
        assert payload["extra"]["rows"] == 42
        assert payload["service"] == "ironflow"

    def test_json_formatter_includes_the_exception(self):
        def explode() -> None:
            raise ValueError("boom")

        try:
            explode()
        except ValueError:
            import sys

            record = logging.LogRecord(
                "t", logging.ERROR, "f.py", 1, "failed", None, sys.exc_info()
            )
        payload = json.loads(JsonFormatter().format(record))
        assert payload["exception"]["type"] == "ValueError"
        assert "boom" in payload["exception"]["message"]
        assert "Traceback" in payload["exception"]["stacktrace"]

    def test_json_formatter_survives_unserialisable_extras(self):
        record = make_record(obj=object())
        payload = json.loads(JsonFormatter().format(record))
        assert isinstance(payload["extra"]["obj"], str)

    def test_configure_logging_is_idempotent(self, tmp_path: Path):
        for _ in range(3):
            root = configure_logging(level="INFO", log_file=tmp_path / "log" / "app.log")
        assert len(root.handlers) == 2, "handlers must not accumulate on reconfiguration"

    def test_file_output_is_json_even_in_human_mode(self, tmp_path: Path):
        log_file = tmp_path / "app.log"
        configure_logging(level="INFO", json_output=False, log_file=log_file)
        logging.getLogger("test").info("written to file", extra={"rows": 1})
        for handler in logging.getLogger().handlers:
            handler.flush()
        payload = json.loads(log_file.read_text(encoding="utf-8").strip().splitlines()[-1])
        assert payload["message"] == "written to file"

    def test_secrets_never_reach_the_log_file(self, tmp_path: Path):
        log_file = tmp_path / "app.log"
        configure_logging(level="INFO", log_file=log_file)
        logging.getLogger("test").info(
            "connecting", extra={"password": "hunter2", "dsn": "postgres://u:pw@h/db"}
        )
        for handler in logging.getLogger().handlers:
            handler.flush()
        content = log_file.read_text(encoding="utf-8")
        assert "hunter2" not in content
        assert "pw@h" not in content

    def test_every_way_of_logging_a_dsn_reaches_disk_scrubbed(self, tmp_path: Path):
        """docs/security.md promises this outright, so test it end to end."""
        log_file = tmp_path / "app.log"
        configure_logging(level="INFO", log_file=log_file)
        secret = "hunter2SuperSecret"
        dsn = f"postgresql://appuser:{secret}@db.internal:5432/prod"
        log = logging.getLogger("test")
        log.info("connect postgresql://appuser:%s@db/prod", secret)
        log.info("connect %s", dsn)
        log.info("connect " + dsn)
        log.info("cfg", extra={"password": secret})
        log.info("%s -> %s", "start", dsn)
        for handler in logging.getLogger().handlers:
            handler.flush()

        content = log_file.read_text(encoding="utf-8")
        assert secret not in content
        written = [line for line in content.splitlines() if line.strip()]
        assert len(written) == 5, "a record that fails to format is a record that is lost"

    def test_invalid_level_falls_back_to_info(self):
        assert configure_logging(level="NOT_A_LEVEL").level == logging.INFO


class TestMetrics:
    def test_counter(self, metrics):
        metrics.counter("jobs", 2)
        metrics.counter("jobs")
        assert metrics.get_counter("jobs") == 3

    def test_counters_cannot_decrease(self, metrics):
        with pytest.raises(ValueError, match="cannot decrease"):
            metrics.counter("jobs", -1)

    def test_labels_separate_series(self, metrics):
        metrics.counter("jobs", labels={"pipeline": "a"})
        metrics.counter("jobs", 5, labels={"pipeline": "b"})
        assert metrics.get_counter("jobs", {"pipeline": "a"}) == 1
        assert metrics.get_counter("jobs", {"pipeline": "b"}) == 5

    def test_label_order_does_not_matter(self, metrics):
        metrics.counter("jobs", labels={"a": "1", "b": "2"})
        assert metrics.get_counter("jobs", {"b": "2", "a": "1"}) == 1

    def test_gauge_replaces(self, metrics):
        metrics.gauge("memory", 100)
        metrics.gauge("memory", 50)
        assert metrics.get_gauge("memory") == 50

    def test_histogram_statistics(self, metrics):
        for value in (0.1, 0.2, 0.5, 1.0, 5.0):
            metrics.observe("duration", value)
        stats = metrics.histogram_stats("duration")
        assert stats["count"] == 5
        assert stats["sum"] == pytest.approx(6.8)
        assert stats["mean"] == pytest.approx(1.36)
        assert stats["p95"] >= 5.0

    def test_histogram_of_an_unseen_metric(self, metrics):
        assert metrics.histogram_stats("nothing")["count"] == 0

    def test_timer(self, metrics):
        with metrics.timer("block"):
            pass
        assert metrics.histogram_stats("block")["count"] == 1

    def test_prometheus_exposition_format(self, metrics):
        metrics.counter("rows", 5, labels={"pipeline": "p"}, help="Rows processed.")
        metrics.gauge("memory", 1024)
        metrics.observe("duration", 0.5)
        rendered = metrics.render_prometheus()
        assert "# HELP test_rows Rows processed." in rendered
        assert "# TYPE test_rows counter" in rendered
        assert 'test_rows{pipeline="p"} 5' in rendered
        assert "# TYPE test_duration histogram" in rendered
        assert 'test_duration_bucket{le="+Inf"} 1' in rendered
        assert "test_duration_count 1" in rendered

    def test_label_values_are_escaped(self, metrics):
        metrics.counter("rows", labels={"name": 'has"quote'})
        assert r'name="has\"quote"' in metrics.render_prometheus()

    def test_namespace_prefix_is_not_doubled(self, metrics):
        metrics.counter("test_already_prefixed")
        assert "test_test_already_prefixed" not in metrics.render_prometheus()

    def test_snapshot_and_reset(self, metrics):
        metrics.counter("rows", 3)
        metrics.gauge("memory", 1)
        assert metrics.snapshot()["counters"]["test_rows"]["_"] == 3
        metrics.reset()
        assert metrics.get_counter("rows") == 0

    def test_global_registry_exists(self):
        assert isinstance(METRICS, MetricsRegistry)


class TestAudit:
    def test_entries_are_appended(self, tmp_path: Path):
        audit = AuditLog(tmp_path / "audit.jsonl")
        audit.record("pipeline.run", actor="alice", resource="p")
        audit.record("pipeline.run", actor="bob", resource="q")
        entries = audit.read()
        assert len(entries) == 2
        assert entries[0]["actor"] == "alice"

    def test_hash_chain_links_entries(self, tmp_path: Path):
        audit = AuditLog(tmp_path / "audit.jsonl")
        first = audit.record("a", actor="x")
        second = audit.record("b", actor="x")
        assert first.previous_hash == GENESIS_HASH
        assert second.previous_hash == first.entry_hash

    def test_chain_verifies_when_intact(self, tmp_path: Path):
        audit = AuditLog(tmp_path / "audit.jsonl")
        for index in range(5):
            audit.record("action", actor=f"user{index}")
        assert audit.verify_chain() == (True, None)

    def test_tampering_is_detected(self, tmp_path: Path):
        """The point of the chain: an edited entry must be detectable."""
        path = tmp_path / "audit.jsonl"
        audit = AuditLog(path)
        for index in range(5):
            audit.record("action", actor=f"user{index}")

        lines = path.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[2])
        entry["actor"] = "attacker"
        lines[2] = json.dumps(entry)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        intact, broken_at = AuditLog(path).verify_chain()
        assert not intact
        assert broken_at == 2

    def test_deletion_is_detected(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        audit = AuditLog(path)
        for index in range(5):
            audit.record("action", actor=f"user{index}")
        lines = path.read_text(encoding="utf-8").splitlines()
        del lines[2]
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        assert AuditLog(path).verify_chain()[0] is False

    def test_chain_continues_across_instances(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        AuditLog(path).record("a", actor="x")
        AuditLog(path).record("b", actor="x")
        assert AuditLog(path).verify_chain() == (True, None)

    def test_secrets_are_redacted_before_hashing(self, tmp_path: Path):
        path = tmp_path / "audit.jsonl"
        audit = AuditLog(path)
        audit.record("login", actor="x", password="hunter2")
        assert "hunter2" not in path.read_text(encoding="utf-8")
        assert audit.verify_chain() == (True, None)

    def test_a_write_failure_never_raises(self, tmp_path: Path, caplog, monkeypatch):
        """Auditing must not be able to fail an otherwise healthy job."""
        audit = AuditLog(tmp_path / "audit.jsonl")

        def explode(*args, **kwargs):
            raise OSError("disk full")

        monkeypatch.setattr(Path, "open", explode)
        with caplog.at_level("ERROR"):
            audit.record("action", actor="x")
        assert "failed to persist audit entry" in caplog.text

    def test_sink_failure_is_isolated(self, tmp_path: Path, caplog):
        def broken_sink(entry):
            raise RuntimeError("remote audit down")

        audit = AuditLog(tmp_path / "audit.jsonl", sink=broken_sink)
        with caplog.at_level("ERROR"):
            audit.record("action", actor="x")
        assert "audit sink failed" in caplog.text
        assert len(audit.read()) == 1

    def test_null_audit_writes_nothing(self):
        audit = NullAuditLog()
        audit.record("action", actor="x")
        assert audit.read() == []

    def test_verify_of_a_missing_file_is_intact(self, tmp_path: Path):
        assert AuditLog(tmp_path / "absent.jsonl").verify_chain() == (True, None)


class TestResources:
    def test_sample_returns_a_structure(self):
        sample = sample_resources()
        assert sample.rss_bytes >= 0
        assert "rss_mb" in sample.to_dict()

    def test_open_files_is_off_by_default(self):
        """Enumerating handles is pathologically slow on Windows."""
        assert sample_resources().open_files == 0

    def test_monitor_records_a_peak(self):
        with ResourceMonitor(interval=0.25) as monitor:
            _ = [0] * 100_000
        assert monitor.samples >= 1
        assert "rss_mb" in monitor.to_dict()

    def test_monitor_stop_is_safe_twice(self):
        monitor = ResourceMonitor(interval=0.25)
        monitor.start()
        monitor.stop()
        monitor.stop()
