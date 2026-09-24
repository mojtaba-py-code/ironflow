"""Tests for the application services: facade, notifications and reporting."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import yaml

from ironflow.config.models import NotificationSpec, PipelineSpec
from ironflow.core.errors import AuthorizationError, ConfigurationError
from ironflow.core.events import EventBus, EventType
from ironflow.core.types import RunStatus
from ironflow.security.rbac import OPERATOR, VIEWER, Principal
from ironflow.services.notifications import (
    ConsoleNotifier,
    NotificationService,
    SlackNotifier,
    WebhookNotifier,
    build_notifier,
)
from ironflow.services.reporting import (
    build_dashboard_report,
    build_run_report,
    default_report_path,
    render_console_summary,
    write_html,
    write_json,
)


def write_pipeline(directory: Path, name: str, **overrides) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    document = {
        "name": name,
        "tasks": [
            {
                "name": "t",
                "source": {"type": "memory", "records": [{"a": 1}, {"a": 2}]},
                "destination": {"type": "memory", "buffer": f"{name}_out", "mode": "overwrite"},
            }
        ],
        **overrides,
    }
    path = directory / f"{name}.yaml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


class TestPipelineService:
    def test_discovery(self, service, tmp_path):
        write_pipeline(tmp_path / "pipelines", "alpha")
        write_pipeline(tmp_path / "pipelines", "beta")
        assert {s.name for s in service.list_pipelines()} == {"alpha", "beta"}

    def test_get_by_name(self, service, tmp_path):
        write_pipeline(tmp_path / "pipelines", "alpha")
        assert service.get_pipeline("alpha").name == "alpha"

    def test_unknown_pipeline(self, service):
        with pytest.raises(ConfigurationError, match="no pipeline named"):
            service.get_pipeline("ghost")

    def test_load_from_an_explicit_path(self, service, tmp_path):
        path = write_pipeline(tmp_path / "elsewhere", "gamma")
        assert service.load_file(path).name == "gamma"

    def test_validate_reports_structure(self, service, tmp_path):
        write_pipeline(tmp_path / "pipelines", "alpha")
        report = service.validate(service.get_pipeline("alpha"))
        assert report["valid"]
        assert report["structure"]["tasks"] == 1

    def test_validate_warns_about_quarantine_without_a_destination(self, service, tmp_path):
        write_pipeline(
            tmp_path / "pipelines",
            "warned",
            tasks=[
                {
                    "name": "t",
                    "source": {"type": "memory", "records": [{"a": 1}]},
                    "destination": {"type": "memory", "buffer": "x"},
                    "validation": {
                        "on_violation": "quarantine",
                        "rules": [{"type": "not_null", "field": "a"}],
                    },
                }
            ],
        )
        report = service.validate(service.get_pipeline("warned"))
        assert any("reject_destination" in w for w in report["warnings"])

    def test_validate_warns_about_a_scheduled_pipeline_without_notifications(
        self, service, tmp_path
    ):
        write_pipeline(tmp_path / "pipelines", "scheduled", schedule={"cron": "0 2 * * *"})
        report = service.validate(service.get_pipeline("scheduled"))
        assert any("notifications" in w for w in report["warnings"])

    def test_validate_detects_a_cycle(self, service):
        spec = PipelineSpec.model_construct(
            name="cyclic",
            version="1",
            tasks=[],
        )
        # Build a genuinely cyclic graph via the model's task list.
        spec = PipelineSpec.model_validate(
            {
                "name": "cyclic",
                "tasks": [
                    {
                        "name": "a",
                        "source": {"type": "memory"},
                        "destination": {"type": "null"},
                    },
                    {
                        "name": "b",
                        "depends_on": ["a"],
                        "source": {"type": "memory"},
                        "destination": {"type": "null"},
                    },
                ],
            }
        )
        spec.tasks[0].depends_on = ["b"]
        report = service.validate(spec)
        assert not report["valid"]

    def test_run_and_history(self, service, tmp_path):
        write_pipeline(tmp_path / "pipelines", "alpha")
        result = service.run(service.get_pipeline("alpha"), install_signal_handlers=False)
        assert result.status is RunStatus.SUCCESS

        history = service.history(pipeline_name="alpha")
        assert history[0]["execution_id"] == result.execution_id

    def test_status_summary(self, service, tmp_path):
        write_pipeline(tmp_path / "pipelines", "alpha")
        service.run(service.get_pipeline("alpha"), install_signal_handlers=False)
        status = service.status("alpha")
        assert status["last_run"]["status"] == "success"
        assert status["statistics"]["runs_total"] == 1

    def test_retry_without_a_failed_run(self, service, tmp_path):
        write_pipeline(tmp_path / "pipelines", "alpha")
        with pytest.raises(ConfigurationError, match="no failed run"):
            service.retry("alpha")

    def test_resume_without_checkpoints_warns(self, service, tmp_path, caplog):
        write_pipeline(tmp_path / "pipelines", "alpha")
        with caplog.at_level("WARNING"):
            service.resume("alpha", "exec_does_not_exist")
        assert "no checkpoints" in caplog.text

    def test_clean_purges_state(self, service, tmp_path):
        write_pipeline(tmp_path / "pipelines", "alpha")
        service.run(service.get_pipeline("alpha"), install_signal_handlers=False)
        removed = service.clean(history_days=1, checkpoint_days=1)
        assert set(removed) == {
            "runs_purged",
            "checkpoints_purged",
            "watermarks_reset",
            "schemas_reset",
        }

    def test_clean_can_rebaseline_schema_snapshots(self, service, tmp_path):
        write_pipeline(tmp_path / "pipelines", "alpha")
        service.run(service.get_pipeline("alpha"), install_signal_handlers=False)
        # Snapshots are keyed by connector name, so list() rather than get().
        assert service.schemas.list("alpha"), "the run should have stored a snapshot"
        removed = service.clean(reset_schemas="alpha")
        assert removed["schemas_reset"] == 1
        assert service.schemas.list("alpha") == []

    def test_healthcheck(self, service):
        health = service.healthcheck()
        assert health["database"] is True
        assert health["environment"] == "local"

    def test_scheduler_is_wired_to_run_history(self, service, tmp_path):
        write_pipeline(tmp_path / "pipelines", "alpha", schedule={"interval_seconds": 3600})
        scheduler = service.build_scheduler()
        assert [job.name for job in scheduler.jobs()] == ["alpha"]

    def test_authorization_is_enforced_when_enabled(self, service, tmp_path):
        write_pipeline(tmp_path / "pipelines", "alpha")
        service.access.enabled = True
        viewer = Principal("v", roles=(VIEWER,))
        with pytest.raises(AuthorizationError):
            service.run(service.get_pipeline("alpha"), principal=viewer)

        operator = Principal("o", roles=(OPERATOR,))
        assert (
            service.run(
                service.get_pipeline("alpha"), principal=operator, install_signal_handlers=False
            ).status
            is RunStatus.SUCCESS
        )

    def test_audit_entries_are_written(self, service, tmp_path):
        write_pipeline(tmp_path / "pipelines", "alpha")
        service.run(service.get_pipeline("alpha"), install_signal_handlers=False)
        actions = {entry["action"] for entry in service.audit.read()}
        assert "pipeline.run" in actions
        assert "pipeline.finished" in actions
        assert service.audit.verify_chain() == (True, None)


class TestNotifications:
    def test_console_notifier(self, caplog):
        notifier = build_notifier(NotificationSpec(type="console"))
        assert isinstance(notifier, ConsoleNotifier)
        with caplog.at_level("INFO"):
            assert notifier.notify("subject", "body", {})
        assert "subject" in caplog.text

    def test_unknown_channel_is_rejected(self):
        with pytest.raises(ConfigurationError, match="unsupported notification channel"):
            build_notifier(NotificationSpec.model_construct(type="carrier_pigeon"))

    def test_webhook_posts_a_redacted_payload(self, settings, monkeypatch):
        captured = {}

        def handler(request):
            captured["url"] = str(request.url)
            captured["json"] = json.loads(request.content)
            return httpx.Response(200)

        settings.allow_private_network = True
        notifier = WebhookNotifier(
            NotificationSpec(type="webhook", target="https://hooks.example.com/x"), settings
        )
        notifier.http_client = lambda: httpx.Client(transport=httpx.MockTransport(handler))
        assert notifier.notify("subj", "body", {"password": "hunter2", "rows": 5})
        assert captured["url"] == "https://hooks.example.com/x"
        assert "hunter2" not in json.dumps(captured["json"])
        assert captured["json"]["rows"] == 5

    def test_webhook_failure_is_swallowed(self, settings, monkeypatch, caplog):
        def explode(request):
            raise httpx.ConnectError("no route to host")

        settings.allow_private_network = True
        notifier = WebhookNotifier(
            NotificationSpec(type="webhook", target="https://hooks.example.com/x"), settings
        )
        notifier.http_client = lambda: httpx.Client(transport=httpx.MockTransport(explode))
        with caplog.at_level("ERROR"):
            assert notifier.notify("s", "b", {}) is False
        assert "webhook notification failed" in caplog.text

    def test_webhook_rejects_an_internal_target(self, settings, caplog):
        settings.allow_private_network = False
        notifier = WebhookNotifier(
            NotificationSpec(type="webhook", target="http://169.254.169.254/x"), settings
        )
        with caplog.at_level("ERROR"):
            assert notifier.notify("s", "b", {}) is False

    def test_slack_restricts_the_host(self, settings, caplog):
        settings.allow_private_network = False
        notifier = SlackNotifier(
            NotificationSpec(type="slack", target="https://evil.example.com/x"), settings
        )
        with caplog.at_level("ERROR"):
            assert notifier.notify("s", "b", {}) is False

    def test_service_dispatches_on_matching_events(self, settings):
        delivered = []

        class Recording(ConsoleNotifier):
            def notify(self, subject, body, payload):
                delivered.append((subject, payload.get("type")))
                return True

        service = NotificationService([NotificationSpec(type="console", on=["failed"])], settings)
        service._channels = [(service._channels[0][0], Recording(NotificationSpec(type="console")))]

        bus = EventBus()
        service.attach(bus)
        bus.emit(EventType.PIPELINE_SUCCEEDED, pipeline_id="p", execution_id="e", status="success")
        assert delivered == [], "a success must not fire a 'failed' channel"

        bus.emit(EventType.PIPELINE_FAILED, pipeline_id="p", execution_id="e", error="boom")
        assert len(delivered) == 1

    def test_a_failing_channel_does_not_break_the_bus(self, settings, caplog):
        class Broken(ConsoleNotifier):
            def notify(self, subject, body, payload):
                raise RuntimeError("channel exploded")

        service = NotificationService([], settings)
        service._channels = [
            (
                NotificationSpec(type="console", on=["failed"]),
                Broken(NotificationSpec(type="console")),
            )
        ]
        bus = EventBus()
        service.attach(bus)
        with caplog.at_level("ERROR"):
            bus.emit(EventType.PIPELINE_FAILED, pipeline_id="p", execution_id="e")
        assert "raised" in caplog.text

    def test_detach_stops_delivery(self, settings):
        delivered = []

        class Recording(ConsoleNotifier):
            def notify(self, subject, body, payload):
                delivered.append(subject)
                return True

        service = NotificationService([], settings)
        service._channels = [
            (
                NotificationSpec(type="console", on=["failed"]),
                Recording(NotificationSpec(type="console")),
            )
        ]
        bus = EventBus()
        service.attach(bus)
        service.detach()
        bus.emit(EventType.PIPELINE_FAILED, pipeline_id="p", execution_id="e")
        assert delivered == []

    def test_invalid_channels_are_skipped_at_construction(self, settings, caplog):
        with caplog.at_level("ERROR"):
            service = NotificationService(
                [NotificationSpec.model_construct(type="pigeon", on=["failed"], enabled=True)],
                settings,
            )
        assert service.channel_count == 0


class TestReporting:
    @pytest.fixture
    def result(self, service, tmp_path):
        write_pipeline(tmp_path / "pipelines", "alpha")
        return service.run(service.get_pipeline("alpha"), install_signal_handlers=False)

    def test_run_report_structure(self, result):
        report = build_run_report(result)
        assert report["run"]["pipeline"] == "alpha"
        assert "generated_at" in report
        assert isinstance(report["slowest_tasks"], list)

    def test_json_report(self, result, tmp_path):
        path = write_json(build_run_report(result), tmp_path / "r" / "report.json")
        assert path.exists()
        assert json.loads(path.read_text(encoding="utf-8"))["run"]["status"] == "success"

    def test_html_report(self, result, tmp_path):
        path = write_html(build_run_report(result), tmp_path / "report.html")
        content = path.read_text(encoding="utf-8")
        assert "<!DOCTYPE html>" in content
        assert "alpha" in content

    def test_html_report_escapes_content(self, result, tmp_path):
        report = build_run_report(result)
        report["run"]["pipeline"] = "<script>alert(1)</script>"
        content = write_html(report, tmp_path / "x.html").read_text(encoding="utf-8")
        assert "<script>alert(1)</script>" not in content
        assert "&lt;script&gt;" in content

    def test_reports_are_redacted(self, result, tmp_path):
        report = build_run_report(result)
        report["run"]["password"] = "hunter2"
        assert "hunter2" not in write_json(report, tmp_path / "r.json").read_text(encoding="utf-8")

    def test_dashboard_report(self, service):
        report = build_dashboard_report(service.statistics(), service.runs.timeline())
        assert "statistics" in report
        assert "timeline" in report

    def test_console_summary_renders(self, result):
        from rich.console import Console

        console = Console(record=True, width=100)
        console.print(render_console_summary(result))
        assert "alpha" in console.export_text()

    def test_default_report_path_sanitises_the_name(self, tmp_path):
        path = default_report_path(tmp_path, "bad/../name", "exec_123456789", "html")
        assert path.name == Path(path.name).name, "must be a single path component"
        assert "/" not in path.name and ".." not in path.name
        assert path.parent == Path(tmp_path)
        assert path.suffix == ".html"
