"""Tests for paths the main suites do not reach.

Retries, timeouts, redirects, OAuth2, CDC overlap windows and SQL tasks: the
code that only runs when something goes wrong, which is exactly the code that
must not be discovered to be broken during an incident.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from ironflow.config.models import ConnectorSpec, NotificationSpec, TaskSpec
from ironflow.connectors.factory import ConnectorFactory
from ironflow.connectors.memory import MemorySink, MemorySource
from ironflow.core.errors import (
    ConfigurationError,
    ExtractionError,
    LoadingError,
    SecurityError,
)
from ironflow.core.errors import ConnectionError as IFConnectionError
from ironflow.core.types import RecordBatch, RunStatus
from ironflow.pipeline.extraction import _apply_overlap
from ironflow.pipeline.task import TaskExecutor
from ironflow.repositories.repositories import WatermarkRepository


def spec(connector_type: str, **options) -> ConnectorSpec:
    return ConnectorSpec.model_validate({"type": connector_type, **options})


def read_all(source, context) -> list[dict]:
    source.open(context)
    try:
        return [record for batch in source.read(context) for record in batch]
    finally:
        source.close()


def stub(factory, connector_spec, handler, *, sink: bool = False):
    connector = (
        factory.create_sink(connector_spec) if sink else factory.create_source(connector_spec)
    )
    transport = httpx.MockTransport(handler)
    original = connector._build_client

    def build():
        client = original()
        client._transport = transport
        for key in list(client._mounts):
            client._mounts[key] = transport
        return client

    connector._build_client = build
    return connector


class TestHttpAuth:
    def test_basic_auth(self, factory, context, monkeypatch):
        monkeypatch.setenv("U", "alice")
        monkeypatch.setenv("P", "hunter2")
        captured = {}

        def handler(request):
            captured["auth"] = request.headers.get("authorization")
            return httpx.Response(200, json=[])

        source = stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/x",
                auth="basic",
                user="env:U",
                password="env:P",
                allow_private_network=True,
            ),
            handler,
        )
        read_all(source, context)
        import base64

        assert captured["auth"] == "Basic " + base64.b64encode(b"alice:hunter2").decode()

    def test_api_key_header(self, factory, context, monkeypatch):
        monkeypatch.setenv("K", "abc123")
        captured = {}

        def handler(request):
            captured["key"] = request.headers.get("x-custom-key")
            return httpx.Response(200, json=[])

        source = stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/x",
                auth="api_key",
                api_key="env:K",
                api_key_header="X-Custom-Key",
                allow_private_network=True,
            ),
            handler,
        )
        read_all(source, context)
        assert captured["key"] == "abc123"

    def test_unsupported_auth_is_rejected(self, factory, context):
        source = factory.create_source(
            spec(
                "rest", url="https://api.example.com/x", auth="kerberos", allow_private_network=True
            )
        )
        with pytest.raises(ConfigurationError, match="unsupported auth type"):
            read_all(source, context)

    def test_missing_token_is_reported(self, factory, context):
        source = factory.create_source(
            spec("rest", url="https://api.example.com/x", auth="bearer", allow_private_network=True)
        )
        with pytest.raises(ConfigurationError, match="requires secret option 'token'"):
            read_all(source, context)

    def test_tls_cannot_be_disabled_in_production(self, factory, context):
        factory.settings.environment = "production"
        source = factory.create_source(
            spec(
                "rest",
                url="https://api.example.com/x",
                verify_tls=False,
                allow_private_network=True,
            )
        )
        with pytest.raises(ConfigurationError, match="TLS verification cannot be disabled"):
            read_all(source, context)


class TestHttpBehaviour:
    def test_retries_5xx_then_succeeds(self, factory, context):
        attempts = {"n": 0}

        def handler(request):
            attempts["n"] += 1
            if attempts["n"] < 3:
                return httpx.Response(503, json={"error": "unavailable"})
            return httpx.Response(200, json=[{"i": 1}])

        source = stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/x",
                allow_private_network=True,
                retry={"max_attempts": 3, "initial_delay": 0, "jitter": False},
            ),
            handler,
        )
        assert read_all(source, context) == [{"i": 1}]
        assert attempts["n"] == 3

    def test_redirects_are_followed_and_revalidated(self, factory, context):
        def handler(request):
            if request.url.path == "/start":
                return httpx.Response(302, headers={"location": "https://api.example.com/final"})
            return httpx.Response(200, json=[{"i": 1}])

        source = stub(
            factory,
            spec("rest", url="https://api.example.com/start", allow_private_network=True),
            handler,
        )
        assert read_all(source, context) == [{"i": 1}]

    def test_redirect_to_an_internal_address_is_blocked(self, factory, context):
        """A 302 must not bypass a check that only ran on the original URL."""

        def handler(request):
            return httpx.Response(
                302, headers={"location": "http://169.254.169.254/latest/meta-data/"}
            )

        source = stub(
            factory,
            spec("rest", url="https://api.example.com/start", allow_private_network=False),
            handler,
        )
        with pytest.raises(SecurityError):
            read_all(source, context)

    def test_redirect_loops_terminate(self, factory, context):
        def handler(request):
            return httpx.Response(302, headers={"location": "https://api.example.com/loop"})

        source = stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/loop",
                allow_private_network=True,
                retry={"max_attempts": 1},
            ),
            handler,
        )
        with pytest.raises(IFConnectionError, match="too many redirects"):
            read_all(source, context)

    def test_cursor_pagination(self, factory, context):
        pages = [
            {"items": [{"i": 1}], "next_cursor": "c2"},
            {"items": [{"i": 2}], "next_cursor": None},
        ]
        calls = {"n": 0}

        def handler(request):
            payload = pages[calls["n"]]
            calls["n"] += 1
            return httpx.Response(200, json=payload)

        source = stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/x",
                data_path="items",
                pagination="cursor",
                allow_private_network=True,
            ),
            handler,
        )
        assert read_all(source, context) == [{"i": 1}, {"i": 2}]

    def test_offset_pagination(self, factory, context):
        def handler(request):
            offset = int(request.url.params.get("offset", 0))
            return httpx.Response(200, json=[{"i": offset}] if offset < 4 else [])

        source = stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/x",
                pagination="offset",
                page_size=1,
                allow_private_network=True,
            ),
            handler,
        )
        assert len(read_all(source, context)) == 4

    def test_max_pages_caps_and_warns(self, factory, context, caplog):
        def handler(request):
            return httpx.Response(200, json=[{"i": 1}, {"i": 2}])

        source = stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/x",
                pagination="page",
                page_size=2,
                max_pages=3,
                allow_private_network=True,
            ),
            handler,
        )
        with caplog.at_level("WARNING"):
            rows = read_all(source, context)
        assert len(rows) == 6
        assert "max_pages" in caplog.text

    def test_non_json_response_is_reported(self, factory, context):
        def handler(request):
            return httpx.Response(200, text="<html>not json</html>")

        source = stub(
            factory,
            spec("rest", url="https://api.example.com/x", allow_private_network=True),
            handler,
        )
        with pytest.raises(ExtractionError, match="not valid JSON"):
            read_all(source, context)

    def test_oversized_response_is_refused(self, factory, context):
        factory.settings.http_max_response_bytes = 10

        def handler(request):
            return httpx.Response(200, json=[{"padding": "x" * 500}])

        source = stub(
            factory,
            spec("rest", url="https://api.example.com/x", allow_private_network=True),
            handler,
        )
        with pytest.raises(ExtractionError, match="size limit"):
            read_all(source, context)

    def test_unsupported_pagination_strategy(self, factory, context):
        def handler(request):
            return httpx.Response(200, json=[{"i": 1}])

        source = stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/x",
                pagination="magic",
                allow_private_network=True,
            ),
            handler,
        )
        with pytest.raises(ConfigurationError, match="unsupported pagination"):
            read_all(source, context)


class TestRestSink:
    def test_posts_a_batch(self, factory, context):
        captured = {}

        def handler(request):
            import json

            captured["body"] = json.loads(request.content)
            return httpx.Response(201, json={"ok": True})

        sink = stub(
            factory,
            spec("rest", url="https://api.example.com/ingest", allow_private_network=True),
            handler,
            sink=True,
        )
        sink.open(context)
        assert sink.write(RecordBatch([{"a": 1}, {"a": 2}]), context) == 2
        sink.close()
        assert captured["body"] == [{"a": 1}, {"a": 2}]

    def test_record_mode_posts_individually(self, factory, context):
        calls = {"n": 0}

        def handler(request):
            calls["n"] += 1
            return httpx.Response(200, json={})

        sink = stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/ingest",
                payload_mode="record",
                allow_private_network=True,
            ),
            handler,
            sink=True,
        )
        sink.open(context)
        sink.write(RecordBatch([{"a": 1}, {"a": 2}]), context)
        sink.close()
        assert calls["n"] == 2

    def test_rollback_is_honest_about_being_impossible(self, factory, context):
        def handler(request):
            return httpx.Response(200, json={})

        sink = stub(
            factory,
            spec("rest", url="https://api.example.com/ingest", allow_private_network=True),
            handler,
            sink=True,
        )
        sink.open(context)
        sink.write(RecordBatch([{"a": 1}]), context)
        with pytest.raises(LoadingError, match="cannot roll back"):
            sink.rollback()
        sink.close()

    def test_is_declared_non_transactional(self, factory):
        sink = factory.create_sink(
            spec("rest", url="https://api.example.com/x", allow_private_network=True)
        )
        assert sink.transactional is False


class TestIncrementalOverlap:
    def test_overlap_rewinds_a_timestamp(self):
        rewound = _apply_overlap("2026-03-01T10:00:05", 5)
        assert rewound == "2026-03-01T10:00:00"

    def test_overlap_rewinds_a_datetime(self):
        moment = datetime(2026, 3, 1, 10, 0, 5, tzinfo=UTC)
        assert _apply_overlap(moment, 5) == moment - timedelta(seconds=5)

    def test_overlap_leaves_a_sequence_number_alone(self):
        """Subtracting seconds from an id would re-read an arbitrary row count."""
        assert _apply_overlap(1000, 5) == 1000

    def test_overlap_leaves_a_non_date_string_alone(self):
        assert _apply_overlap("abc", 5) == "abc"

    def test_no_overlap_is_a_no_op(self):
        assert _apply_overlap("2026-03-01T10:00:05", 0) == "2026-03-01T10:00:05"

    def test_none_watermark(self):
        assert _apply_overlap(None, 5) is None

    def test_cdc_deduplicates_the_overlap_window(self, settings, context, database):
        """The rows re-read by the overlap must be delivered once."""
        MemorySource.register(
            "src",
            [
                {"id": 1, "ts": "2026-01-01"},
                {"id": 1, "ts": "2026-01-01"},
                {"id": 2, "ts": "2026-01-02"},
            ],
        )
        task = TaskSpec.model_validate(
            {
                "name": "t",
                "source": {"type": "memory", "dataset": "src"},
                "destination": {"type": "memory", "buffer": "out", "mode": "overwrite"},
                "strategy": "cdc",
                "incremental": {"column": "ts", "overlap": 5, "key_columns": ["id"]},
            }
        )
        executor = TaskExecutor(
            task, "p", factory=ConnectorFactory(settings), watermarks=WatermarkRepository(database)
        )
        result = executor.execute(context)
        assert result.status is RunStatus.SUCCESS
        assert result.metrics.rows_out == 2
        assert result.metrics.rows_skipped == 1


class TestTaskRetryAndTimeout:
    def test_a_transient_failure_is_retried(self, settings, context):
        MemorySource.register("src", [{"a": 1}])
        task = TaskSpec.model_validate(
            {
                "name": "t",
                "source": {"type": "memory", "dataset": "src"},
                "destination": {"type": "memory", "buffer": "out", "mode": "overwrite"},
                "retry": {"max_attempts": 3, "initial_delay": 0, "jitter": False},
            }
        )
        executor = TaskExecutor(task, "p", factory=ConnectorFactory(settings))
        attempts = {"n": 0}
        original = executor._run_once

        def flaky(ctx, result):
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise IFConnectionError("source unavailable")
            return original(ctx, result)

        executor._run_once = flaky
        result = executor.execute(context)
        assert result.status is RunStatus.SUCCESS
        assert attempts["n"] == 3
        assert result.attempt == 3

    def test_retries_are_exhausted(self, settings, context):
        MemorySource.register("src", [{"a": 1}])
        task = TaskSpec.model_validate(
            {
                "name": "t",
                "source": {"type": "memory", "dataset": "src"},
                "destination": {"type": "memory", "buffer": "out", "mode": "overwrite"},
                "retry": {"max_attempts": 2, "initial_delay": 0, "jitter": False},
            }
        )
        executor = TaskExecutor(task, "p", factory=ConnectorFactory(settings))
        executor._run_once = lambda ctx, result: (_ for _ in ()).throw(
            IFConnectionError("always down")
        )
        assert executor.execute(context).status is RunStatus.FAILED

    def test_timeout_aborts_between_batches(self, settings, context, monkeypatch):
        """Driven by a fake clock so the test is deterministic, not timing-dependent."""
        import ironflow.pipeline.task as task_module

        MemorySource.register("src", [{"a": i} for i in range(50)])
        task = TaskSpec.model_validate(
            {
                "name": "t",
                "source": {"type": "memory", "dataset": "src", "batch_size": 1},
                "destination": {"type": "memory", "buffer": "out", "mode": "overwrite"},
                "timeout": 10.0,
            }
        )

        ticks = iter([0.0] + [100.0] * 1000)  # first call sets the deadline, then jump past it
        monkeypatch.setattr(task_module.time, "monotonic", lambda: next(ticks), raising=True)

        executor = TaskExecutor(task, "p", factory=ConnectorFactory(settings))
        result = executor.execute(context)
        assert result.status is RunStatus.FAILED
        assert "timeout" in str(result.error)
        assert MemorySink.buffer("out") == [], "a timed-out load must roll back"


class TestSqlTask:
    def test_executes_a_statement(self, settings, context, tmp_path: Path):
        database = tmp_path / "w.db"
        seed = ConnectorFactory(settings).create_sink(
            spec("sqlite", database=str(database), table="t", create_table=True, mode="overwrite")
        )
        seed.open(context)
        seed.write(RecordBatch([{"id": 1, "flag": 0}]), context)
        seed.commit()
        seed.close()

        task = TaskSpec.model_validate(
            {
                "name": "mark",
                "type": "sql",
                "sql": "UPDATE t SET flag = 1",
                "destination": {"type": "sqlite", "database": str(database), "table": "t"},
            }
        )
        executor = TaskExecutor(task, "p", factory=ConnectorFactory(settings))
        result = executor.execute(context)
        assert result.status is RunStatus.SUCCESS
        assert result.metrics.rows_out == 1

    def test_dry_run_does_not_execute(self, settings, context, tmp_path: Path):
        context.dry_run = True
        task = TaskSpec.model_validate(
            {
                "name": "mark",
                "type": "sql",
                "sql": "DELETE FROM t",
                "destination": {
                    "type": "sqlite",
                    "database": str(tmp_path / "w.db"),
                    "table": "t",
                },
            }
        )
        executor = TaskExecutor(task, "p", factory=ConnectorFactory(settings))
        assert executor.execute(context).status is RunStatus.SUCCESS

    def test_requires_a_sql_destination(self, settings, context):
        task = TaskSpec.model_validate(
            {
                "name": "mark",
                "type": "sql",
                "sql": "SELECT 1",
                "destination": {"type": "memory", "buffer": "x"},
            }
        )
        executor = TaskExecutor(task, "p", factory=ConnectorFactory(settings))
        result = executor.execute(context)
        assert result.status is RunStatus.FAILED
        assert "SQL destination" in str(result.error)


class TestEmailNotifier:
    def test_refuses_to_send_credentials_unencrypted(self, settings, caplog):
        from ironflow.services.notifications import EmailNotifier

        notifier = EmailNotifier(
            NotificationSpec(
                type="email",
                target="ops@corp.com",
                options={"user": "svc", "password": "pw", "use_tls": False},
            ),
            settings,
        )
        with caplog.at_level("ERROR"):
            assert notifier.notify("s", "b", {}) is False
        assert "unencrypted" in caplog.text

    def test_delivery_failure_is_swallowed(self, settings, caplog, monkeypatch):
        import smtplib

        from ironflow.services.notifications import EmailNotifier

        def explode(*args, **kwargs):
            raise OSError("connection refused")

        monkeypatch.setattr(smtplib, "SMTP", explode)
        notifier = EmailNotifier(NotificationSpec(type="email", target="ops@corp.com"), settings)
        with caplog.at_level("ERROR"):
            assert notifier.notify("s", "b", {}) is False
        assert "email notification failed" in caplog.text

    def test_target_is_required(self, settings):
        from ironflow.services.notifications import EmailNotifier

        notifier = EmailNotifier(NotificationSpec(type="email"), settings)
        with pytest.raises(ConfigurationError, match="requires a 'target'"):
            notifier.target()


class TestInterfaces:
    def test_connectors_satisfy_the_protocols(self, factory):
        from ironflow.core.interfaces import DataSink, DataSource

        source = factory.create_source(spec("memory", records=[{"a": 1}]))
        sink = factory.create_sink(spec("memory", buffer="x"))
        assert isinstance(source, DataSource)
        assert isinstance(sink, DataSink)

    def test_repositories_satisfy_the_state_store_protocol(self, database):
        from ironflow.core.interfaces import StateStore
        from ironflow.repositories.repositories import StateRepository

        assert isinstance(StateRepository(database), StateStore)
