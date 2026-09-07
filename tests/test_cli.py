"""CLI tests driven through Typer's runner - no subprocesses."""

from __future__ import annotations

import io
import json
import sys
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from ironflow.cli.context import EXIT_FAILED, EXIT_INVALID_CONFIG, _console, parse_key_values
from ironflow.cli.main import app
from ironflow.cli.main import main as console_entry_point
from ironflow.config.settings import reset_settings

runner = CliRunner()


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch) -> Path:
    """An isolated working directory with settings pointed at it."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IRONFLOW_HOME", str(tmp_path / ".ironflow"))
    monkeypatch.setenv("IRONFLOW_DATA_ROOTS", str(tmp_path))
    monkeypatch.setenv("IRONFLOW_PIPELINES_DIR", str(tmp_path / "pipelines"))
    reset_settings()

    (tmp_path / "pipelines").mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "orders.csv").write_text(
        "id,name,amount\n1,Alice,100\n2,Bob,-5\n3,Carol,250\n", encoding="utf-8"
    )
    (tmp_path / "pipelines" / "demo.yaml").write_text(
        yaml.safe_dump(
            {
                "name": "demo",
                "version": "1",
                "owner": "data-eng",
                "tasks": [
                    {
                        "name": "load",
                        "source": {"type": "csv", "path": str(tmp_path / "data" / "orders.csv")},
                        "transformations": [{"type": "cast", "columns": {"amount": "float"}}],
                        "validation": {
                            "on_violation": "quarantine",
                            "rules": [{"type": "range", "field": "amount", "min": 0}],
                        },
                        "destination": {
                            "type": "csv",
                            "path": str(tmp_path / "out.csv"),
                            "mode": "overwrite",
                        },
                    }
                ],
            },
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return tmp_path


def invoke(*args: str):
    return runner.invoke(app, list(args), catch_exceptions=False)


class TestGlobal:
    def test_help(self):
        result = invoke("--help")
        assert result.exit_code == 0
        assert "pipeline" in result.stdout

    def test_version_lists_extras(self):
        result = invoke("version")
        assert result.exit_code == 0
        assert "IronFlow" in result.stdout
        assert "columnar" in result.stdout

    def test_no_arguments_shows_help(self):
        assert runner.invoke(app, []).exit_code != 0


class TestPipelineCommands:
    def test_list(self, workspace):
        result = invoke("pipeline", "list")
        assert result.exit_code == 0
        assert "demo" in result.stdout

    def test_list_json(self, workspace):
        result = invoke("--json", "pipeline", "list")
        assert result.exit_code == 0
        payload = json.loads(result.stdout)
        assert payload[0]["name"] == "demo"
        assert payload[0]["tasks"] == 1

    def test_list_in_an_empty_directory(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("IRONFLOW_PIPELINES_DIR", str(tmp_path / "nothing"))
        monkeypatch.setenv("IRONFLOW_HOME", str(tmp_path / ".ironflow"))
        reset_settings()
        result = invoke("pipeline", "list")
        assert result.exit_code == 0
        assert "No pipelines" in result.stdout

    def test_show(self, workspace):
        result = invoke("pipeline", "show", "demo")
        assert result.exit_code == 0
        assert "load" in result.stdout

    def test_show_mermaid(self, workspace):
        result = invoke("pipeline", "show", "demo", "--mermaid")
        assert result.exit_code == 0
        assert "graph LR" in result.stdout

    def test_show_unknown_pipeline(self, workspace):
        result = invoke("pipeline", "show", "ghost")
        assert result.exit_code == EXIT_INVALID_CONFIG

    def test_validate(self, workspace):
        result = invoke("pipeline", "validate", "demo")
        assert result.exit_code == 0
        assert "VALID" in result.stdout

    def test_validate_all(self, workspace):
        assert invoke("pipeline", "validate", "--all").exit_code == 0

    def test_validate_reports_problems(self, workspace):
        (workspace / "pipelines" / "broken.yaml").write_text(
            yaml.safe_dump(
                {
                    "name": "broken",
                    "tasks": [
                        {
                            "name": "t",
                            "source": {"type": "no_such_connector"},
                            "destination": {"type": "csv", "path": "out.csv"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = invoke("pipeline", "validate", "broken")
        assert result.exit_code == EXIT_INVALID_CONFIG
        assert "INVALID" in result.stdout

    def test_run(self, workspace):
        result = invoke("pipeline", "run", "demo")
        assert result.exit_code == 0
        assert "SUCCESS" in result.stdout
        assert (workspace / "out.csv").exists()
        content = (workspace / "out.csv").read_text(encoding="utf-8")
        assert "Bob" not in content, "the negative amount must have been quarantined"

    def test_run_with_a_file_path(self, workspace):
        result = invoke("pipeline", "run", "--file", str(workspace / "pipelines" / "demo.yaml"))
        assert result.exit_code == 0

    def test_dry_run_writes_nothing(self, workspace):
        result = invoke("pipeline", "run", "demo", "--dry-run")
        assert result.exit_code == 0
        assert "DRY RUN" in result.stdout
        assert not (workspace / "out.csv").exists()

    def test_run_json_output(self, workspace):
        result = invoke("--json", "pipeline", "run", "demo")
        payload = json.loads(result.stdout)
        assert payload["status"] == "success"
        assert payload["rows"]["read"] == 3

    def test_run_writes_a_report(self, workspace):
        report = workspace / "report.html"
        result = invoke("pipeline", "run", "demo", "--report", str(report))
        assert result.exit_code == 0
        assert report.exists()
        assert "<!DOCTYPE html>" in report.read_text(encoding="utf-8")

    def test_run_with_overrides(self, workspace):
        result = invoke(
            "pipeline",
            "run",
            "--file",
            str(workspace / "pipelines" / "demo.yaml"),
            "--set",
            "defaults.batch_size=1",
        )
        assert result.exit_code == 0

    def test_failing_pipeline_exits_nonzero(self, workspace):
        (workspace / "pipelines" / "failing.yaml").write_text(
            yaml.safe_dump(
                {
                    "name": "failing",
                    "tasks": [
                        {
                            "name": "t",
                            "source": {
                                "type": "csv",
                                "path": str(workspace / "data" / "orders.csv"),
                            },
                            "transformations": [{"type": "cast", "columns": {"amount": "float"}}],
                            "validation": {
                                "on_violation": "fail",
                                "rules": [{"type": "range", "field": "amount", "min": 0}],
                            },
                            "destination": {"type": "csv", "path": str(workspace / "bad.csv")},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = invoke("pipeline", "run", "failing")
        assert result.exit_code == EXIT_FAILED
        assert not (workspace / "bad.csv").exists()

    def test_history_and_status_after_a_run(self, workspace):
        invoke("pipeline", "run", "demo")
        history = invoke("pipeline", "history")
        assert history.exit_code == 0
        assert "demo" in history.stdout

        status = invoke("pipeline", "status", "demo")
        assert status.exit_code == 0
        assert "Success rate" in status.stdout

    def test_history_with_an_unknown_status(self, workspace):
        result = invoke("pipeline", "history", "--status", "sideways")
        assert result.exit_code == EXIT_INVALID_CONFIG

    def test_logs(self, workspace):
        run = invoke("--json", "pipeline", "run", "demo")
        execution_id = json.loads(run.stdout)["execution_id"]
        result = invoke("pipeline", "logs", execution_id)
        assert result.exit_code == 0

    def test_logs_of_an_unknown_run(self, workspace):
        assert invoke("pipeline", "logs", "nope").exit_code == EXIT_INVALID_CONFIG

    def test_retry_without_a_failed_run(self, workspace):
        assert invoke("pipeline", "retry", "demo").exit_code == EXIT_FAILED


class TestConfigCommands:
    def test_init_scaffolds(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("IRONFLOW_HOME", str(tmp_path / ".ironflow"))
        reset_settings()
        result = invoke("config", "init")
        assert result.exit_code == 0
        assert (tmp_path / "pipelines" / "example.yaml").exists()
        assert (tmp_path / ".env.example").exists()

    def test_init_does_not_overwrite_without_force(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("IRONFLOW_HOME", str(tmp_path / ".ironflow"))
        reset_settings()
        invoke("config", "init")
        (tmp_path / "pipelines" / "example.yaml").write_text("custom", encoding="utf-8")
        invoke("config", "init")
        assert (tmp_path / "pipelines" / "example.yaml").read_text(encoding="utf-8") == "custom"

    def test_scaffolded_example_is_valid(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("IRONFLOW_HOME", str(tmp_path / ".ironflow"))
        monkeypatch.setenv("IRONFLOW_PIPELINES_DIR", str(tmp_path / "pipelines"))
        monkeypatch.setenv("IRONFLOW_DATA_ROOTS", str(tmp_path))
        reset_settings()
        invoke("config", "init")
        assert invoke("pipeline", "validate", "example").exit_code == 0

    def test_the_scaffolded_example_actually_runs(self, tmp_path, monkeypatch):
        """Validation passing is not the same as the pipeline working.

        `config init` used to scaffold a pipeline pointing at ./data/raw/orders.csv
        and not the file, so `validate` said VALID and the very next command in
        the README - `pipeline run example` - died with an ExtractionError. The
        four-command quick start is the first thing a reader types; it has to
        finish.
        """
        pytest.importorskip("pyarrow", reason="the example writes Parquet")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("IRONFLOW_HOME", str(tmp_path / ".ironflow"))
        monkeypatch.setenv("IRONFLOW_PIPELINES_DIR", str(tmp_path / "pipelines"))
        monkeypatch.setenv("IRONFLOW_DATA_ROOTS", str(tmp_path))
        reset_settings()

        assert invoke("config", "init").exit_code == 0
        assert (tmp_path / "data" / "raw" / "orders.csv").exists()
        assert invoke("pipeline", "run", "example", "--dry-run").exit_code == 0
        assert invoke("pipeline", "run", "example").exit_code == 0
        assert (tmp_path / "data" / "curated" / "orders.parquet").exists()
        # The two deliberately bad rows land in the reject destination, so the
        # first run a reader performs also shows the quarantine path.
        rejected = (tmp_path / "data" / "curated" / "orders_rejected.csv").read_text(
            encoding="utf-8"
        )
        assert rejected.count("\n") == 3, "one header plus the two rejected rows"

    def test_show_redacts(self, workspace, monkeypatch):
        monkeypatch.setenv("IRONFLOW_JWT_SECRET", "super-secret-value")
        reset_settings()
        result = invoke("config", "show")
        assert result.exit_code == 0
        assert "super-secret-value" not in result.stdout

    def test_check(self, workspace):
        result = invoke("config", "check")
        assert result.exit_code == 0
        assert "database" in result.stdout

    def test_check_fails_on_an_unhardened_production_config(self, workspace, monkeypatch):
        monkeypatch.setenv("IRONFLOW_ENVIRONMENT", "production")
        reset_settings()
        result = invoke("config", "check")
        assert result.exit_code == EXIT_INVALID_CONFIG
        assert "auth_enabled" in result.stdout

    def test_schema(self, workspace, tmp_path):
        target = tmp_path / "schema.json"
        assert invoke("config", "schema", "--output", str(target)).exit_code == 0
        assert "tasks" in json.loads(target.read_text(encoding="utf-8"))["properties"]


class TestSecretsCommands:
    def test_generate_key(self, workspace):
        result = invoke("secrets", "generate-key")
        assert result.exit_code == 0
        assert len(result.stdout.strip().splitlines()[0]) >= 40

    def test_encrypt_and_decrypt(self, workspace, monkeypatch):
        from ironflow.security.crypto import generate_key

        monkeypatch.setenv("IRONFLOW_ENCRYPTION_KEY", generate_key())
        reset_settings()
        encrypted = invoke("secrets", "encrypt", "--value", "hunter2")
        assert encrypted.exit_code == 0
        envelope = encrypted.stdout.strip().splitlines()[0]
        assert envelope.startswith("ironflow:v1:")

        decrypted = invoke("secrets", "decrypt", envelope)
        assert decrypted.exit_code == 0
        assert "hunter2" in decrypted.stdout

    def test_encrypt_without_a_key_is_actionable(self, workspace, monkeypatch):
        monkeypatch.delenv("IRONFLOW_ENCRYPTION_KEY", raising=False)
        reset_settings()
        result = invoke("secrets", "encrypt", "--value", "x")
        assert result.exit_code == EXIT_INVALID_CONFIG


class TestOtherCommands:
    def test_connectors_list(self, workspace):
        result = invoke("connectors", "list")
        assert result.exit_code == 0
        assert "csv" in result.stdout
        assert "mask_pii" in result.stdout

    def test_schedule_list_without_schedules(self, workspace):
        result = invoke("schedule", "list")
        assert result.exit_code == 0
        assert "No pipelines declare a schedule" in result.stdout

    def test_schedule_list_with_a_schedule(self, workspace):
        document = yaml.safe_load(
            (workspace / "pipelines" / "demo.yaml").read_text(encoding="utf-8")
        )
        document["schedule"] = {"cron": "0 2 * * *"}
        (workspace / "pipelines" / "demo.yaml").write_text(
            yaml.safe_dump(document), encoding="utf-8"
        )
        result = invoke("schedule", "list")
        assert result.exit_code == 0
        assert "0 2 * * *" in result.stdout

    def test_schedule_start_once(self, workspace):
        assert invoke("schedule", "start", "--once").exit_code == 0

    def test_state_watermarks_when_empty(self, workspace):
        result = invoke("state", "watermarks")
        assert result.exit_code == 0
        assert "No watermarks" in result.stdout

    def test_state_clean(self, workspace):
        invoke("pipeline", "run", "demo")
        result = invoke("state", "clean")
        assert result.exit_code == 0
        assert "purged" in result.stdout

    def test_state_audit_verify(self, workspace):
        invoke("pipeline", "run", "demo")
        result = invoke("state", "audit", "--verify")
        assert result.exit_code == 0
        assert "intact" in result.stdout

    def test_state_audit_lists_entries(self, workspace):
        invoke("pipeline", "run", "demo")
        result = invoke("state", "audit")
        assert result.exit_code == 0
        assert "pipeline.run" in result.stdout


class TestKeyValueParsing:
    def test_json_values_are_typed(self):
        parsed = parse_key_values(
            ["n=5", "f=1.5", "b=true", "s=hello", 'l=["a","b"]'], option="--param"
        )
        assert parsed == {"n": 5, "f": 1.5, "b": True, "s": "hello", "l": ["a", "b"]}

    def test_missing_equals_is_rejected(self):
        with pytest.raises(Exception, match="key=value"):
            parse_key_values(["novalue"], option="--param")

    def test_empty_key_is_rejected(self):
        with pytest.raises(Exception, match="empty key"):
            parse_key_values(["=value"], option="--param")

    def test_values_may_contain_equals(self):
        assert parse_key_values(["dsn=a=b"], option="--param") == {"dsn": "a=b"}

    def test_none_is_handled(self):
        assert parse_key_values(None, option="--param") == {}


class TestConsoleEncoding:
    """A redirected stdout on Windows uses the ANSI code page, not UTF-8.

    The run summary contains an arrow and a middle dot, neither of which cp1252
    can encode, so rich raised UnicodeEncodeError from inside the render:
    `ironflow pipeline run x > run.log` lost its summary and exited non-zero
    after a load that had actually succeeded. An interactive terminal never
    shows this, which is how it survives to production.
    """

    @staticmethod
    def _legacy_stream() -> io.TextIOWrapper:
        return io.TextIOWrapper(io.BytesIO(), encoding="cp1252", newline="")

    def test_unencodable_characters_do_not_raise(self, monkeypatch):
        stream = self._legacy_stream()
        monkeypatch.setattr(sys, "stdout", stream)
        console = _console()
        console.print("sales_daily · 10 read → 6 written")  # the real summary glyphs
        stream.flush()
        assert stream.buffer.getvalue()  # something was written, nothing raised

    def test_the_stream_keeps_its_own_encoding(self, monkeypatch):
        """Forcing UTF-8 onto a legacy console would trade a crash for mojibake."""
        stream = self._legacy_stream()
        monkeypatch.setattr(sys, "stdout", stream)
        _console()
        assert stream.encoding.lower() == "cp1252"
        assert stream.errors == "replace"

    def test_a_stream_without_reconfigure_is_tolerated(self, monkeypatch):
        """pytest's capture object and a few wrappers do not implement it."""
        monkeypatch.setattr(sys, "stdout", io.StringIO())
        assert _console() is not None


class TestConsoleEntryPoint:
    """``main()`` is the boundary the installed ``ironflow`` script runs.

    ``CliRunner`` drives ``app`` directly, so it never exercises the top-level
    handler - and a rejected *setting* is raised while the settings object is
    built, before Typer's own error handling gets a chance. Without these tests
    an operator with a typo in one environment variable gets a traceback and
    exit code 1, contradicting the documented "2 = invalid configuration".
    """

    def _run(self, monkeypatch, *argv: str) -> int:
        monkeypatch.setattr(sys, "argv", ["ironflow", *argv])
        reset_settings()
        return console_entry_point()

    def test_a_rejected_setting_exits_with_the_config_code(
        self, workspace: Path, monkeypatch, capsys
    ):
        monkeypatch.setenv("IRONFLOW_LOG_LEVEL", "bogus")
        assert self._run(monkeypatch, "config", "show") == EXIT_INVALID_CONFIG
        stderr = capsys.readouterr().err
        assert "invalid configuration" in stderr
        assert "log_level" in stderr
        assert "Traceback" not in stderr

    def test_auth_without_a_signing_secret_exits_with_the_config_code(
        self, workspace: Path, monkeypatch, capsys
    ):
        monkeypatch.setenv("IRONFLOW_AUTH_ENABLED", "true")
        assert self._run(monkeypatch, "config", "show") == EXIT_INVALID_CONFIG
        assert "jwt_secret" in capsys.readouterr().err
