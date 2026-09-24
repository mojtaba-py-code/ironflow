"""Untrusted text must reach the terminal as text, never as markup or escapes.

A pipeline file and the run data derived from it are input, not presentation.
Rich reads ``[...]`` in any string as markup and passes escape sequences through,
so before these tests:

* ``owner: "[/x]"`` crashed ``pipeline list``, ``validate --all`` and
  ``schedule list`` for the *whole directory* with a MarkupError;
* ``version: "[link=...]1[/link]"`` became a live OSC-8 hyperlink;
* ``owner: "\\x1b[7m..."`` wrote raw SGR sequences to the operator's terminal.

Every test drives the real Typer CLI. Assertions are on the literal text, which
does not depend on whether Rich thinks it is talking to a terminal: markup that
is interpreted disappears from the output, markup that is escaped is printed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from rich.console import Console
from typer.testing import CliRunner

from ironflow.cli.context import EXIT_INVALID_CONFIG
from ironflow.cli.main import app
from ironflow.config.settings import get_settings, reset_settings
from ironflow.core.errors import PipelineError
from ironflow.core.types import RunStatus
from ironflow.observability.audit import AuditLog
from ironflow.pipeline.results import PipelineResult, TaskResult
from ironflow.repositories.database import Database
from ironflow.repositories.repositories import RunRepository, WatermarkRepository
from ironflow.services.reporting import plain_text, render_console_summary

runner = CliRunner()

LINK_MARKUP = "[link=https://example.invalid/]1[/link]"
ESCAPES = "\x1b[7mREVERSED\x1b[0m"
#: A raw OSC-8 hyperlink written straight into a value, terminated by BEL.
RAW_HYPERLINK = "\x1b]8;;https://example.invalid/\x07click\x1b]8;;\x07"


def invoke(*args: str):
    return runner.invoke(app, list(args), catch_exceptions=False)


def write_pipeline(directory: Path, name: str, *, destination: str = "csv", **fields) -> None:
    document = {
        "name": name,
        "tasks": [
            {
                "name": "load",
                "source": {"type": "csv", "path": str(directory.parent / "in.csv")},
                "destination": {"type": destination, "path": str(directory.parent / "out.csv")},
            }
        ],
        **fields,
    }
    (directory / f"{name}.yaml").write_text(yaml.safe_dump(document), encoding="utf-8")


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch) -> Path:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("IRONFLOW_HOME", str(tmp_path / ".ironflow"))
    monkeypatch.setenv("IRONFLOW_DATA_ROOTS", str(tmp_path))
    monkeypatch.setenv("IRONFLOW_PIPELINES_DIR", str(tmp_path / "pipelines"))
    # Wide enough that no cell is truncated, and no forced colour: Rich's own
    # styling would otherwise put escape sequences in the output too.
    monkeypatch.setenv("COLUMNS", "400")
    for variable in ("FORCE_COLOR", "TTY_COMPATIBLE", "TTY_INTERACTIVE"):
        monkeypatch.delenv(variable, raising=False)
    reset_settings()

    pipelines = tmp_path / "pipelines"
    pipelines.mkdir()
    (tmp_path / "in.csv").write_text("id\n1\n", encoding="utf-8")
    write_pipeline(
        pipelines,
        "markup",
        destination="[/dest]",
        version=LINK_MARKUP,
        owner="[/x]",
        description="[bold]not bold[/bold]",
        schedule={"cron": "0 2 * * *", "timezone": "[/tz]"},
    )
    write_pipeline(pipelines, "escapes", version="1", owner=f"{ESCAPES} :lock: {RAW_HYPERLINK}")
    return tmp_path


@pytest.fixture
def run_data(workspace: Path):
    """Run history, a watermark and an audit entry whose text is hostile.

    Written straight to the state store, the way a source row or an API
    caller's token subject would get there.
    """
    settings = get_settings()
    database = Database(settings=settings)
    runs = RunRepository(database)
    run_id = runs.start_run(execution_id="exec_hostile", pipeline_name="[/x]")
    runs.record_task(
        run_id=run_id,
        execution_id="exec_hostile",
        task_name="[/task]",
        status=RunStatus.FAILED,
        error=RuntimeError(f"[/boom] {ESCAPES}"),
    )
    runs.finish_run("exec_hostile", status=RunStatus.FAILED, duration_seconds=1.0)
    WatermarkRepository(database).set(
        "[/x]", "[/task]", column="[/column]", value=f"[/value] {ESCAPES}"
    )
    AuditLog(settings.audit_file).record("pipeline.run", actor=f"[/actor] {ESCAPES}")
    database.dispose()


def assert_plain(output: str) -> None:
    """No escape character from a value may reach the terminal."""
    assert "\x1b" not in output
    assert "\x07" not in output


class TestPipelineFileFields:
    def test_list_prints_the_values_instead_of_crashing(self, workspace):
        result = invoke("pipeline", "list")
        assert result.exit_code == 0
        assert "[/x]" in result.stdout
        assert LINK_MARKUP in result.stdout, "the link markup must print, not become a link"
        assert "\\x1b[7mREVERSED\\x1b[0m" in result.stdout
        assert_plain(result.stdout)

    def test_emoji_codes_in_a_value_stay_text(self, workspace):
        result = invoke("pipeline", "list")
        assert ":lock:" in result.stdout
        assert "\N{LOCK}" not in result.stdout

    def test_validate_all_reports_every_pipeline(self, workspace):
        """One crafted value used to abort the whole report."""
        result = invoke("pipeline", "validate", "--all")
        assert result.exit_code == EXIT_INVALID_CONFIG
        assert "unknown sink type '[/dest]'" in result.stdout
        assert "INVALID  markup" in result.stdout
        assert "VALID  escapes" in result.stdout
        assert_plain(result.stdout)

    def test_show_prints_the_version_and_connector_types_literally(self, workspace):
        result = invoke("pipeline", "show", "markup")
        assert result.exit_code == 0
        assert f"markup v{LINK_MARKUP}" in result.stdout
        assert "[/dest]" in result.stdout

    def test_schedule_list_prints_the_timezone_literally(self, workspace):
        result = invoke("schedule", "list")
        assert result.exit_code == 0
        assert "[/tz]" in result.stdout

    def test_json_output_is_unchanged_and_unescaped(self, workspace):
        result = invoke("--json", "pipeline", "list")
        assert result.exit_code == 0
        by_name = {item["name"]: item for item in json.loads(result.stdout)}
        assert by_name["markup"]["owner"] == "[/x]"
        assert by_name["markup"]["version"] == LINK_MARKUP
        # Exactly the value from the file: not escaped, and no emoji substituted.
        assert by_name["escapes"]["owner"] == f"{ESCAPES} :lock: {RAW_HYPERLINK}"

    def test_an_error_message_quoting_a_path_prints_it_literally(self, workspace):
        """``fail`` prints error messages and context, which quote the input."""
        missing = workspace / "x[red]y.yaml"
        result = invoke("pipeline", "show", "--file", str(missing))
        assert result.exit_code == EXIT_INVALID_CONFIG
        assert "x[red]y.yaml" in result.stderr


class TestRunData:
    def test_history(self, run_data):
        result = invoke("pipeline", "history")
        assert result.exit_code == 0
        assert "[/x]" in result.stdout

    def test_logs_prints_the_task_and_its_error_literally(self, run_data):
        result = invoke("pipeline", "logs", "exec_hostile")
        assert result.exit_code == 0
        assert "[/task]" in result.stdout
        assert "[/boom] \\x1b[7mREVERSED" in result.stdout
        assert_plain(result.stdout)

    def test_status(self, run_data):
        result = invoke("pipeline", "status", "[/x]")
        assert result.exit_code == 0
        assert "Status: [/x]" in result.stdout

    def test_watermarks(self, run_data):
        result = invoke("state", "watermarks")
        assert result.exit_code == 0
        assert "[/column]" in result.stdout
        assert "[/value] \\x1b[7mREVERSED" in result.stdout
        assert_plain(result.stdout)

    def test_audit_listing(self, run_data):
        result = invoke("state", "audit")
        assert result.exit_code == 0
        assert "[/actor] \\x1b[7mREVERSED" in result.stdout
        assert_plain(result.stdout)


class TestRunSummary:
    def test_the_summary_escapes_task_names_and_the_error(self):
        result = PipelineResult(pipeline_name="p", execution_id="exec_1")
        result.tasks.append(TaskResult(task_name="[/task]").finish(RunStatus.FAILED))
        result.finish(RunStatus.FAILED, PipelineError(f"[/boom] {ESCAPES}"))

        console = Console(record=True, width=200, emoji=False)
        console.print(render_console_summary(result))  # a MarkupError here is the bug
        text = console.export_text()
        assert "[/task]" in text
        assert "[/boom] \\x1b[7mREVERSED" in text
        assert_plain(text)


class TestPlainText:
    @pytest.mark.parametrize(
        ("value", "shown"),
        [
            ("\x1b[31m", "\\x1b[31m"),
            ("a\rb", "a\\rb"),  # CR would overwrite the start of the line
            ("a\bb", "a\\x08b"),  # so would backspace
            ("line\nforged", "line\\nforged"),
            ("\x7f\x9b", "\\x7f\\x9b"),  # DEL and the 8-bit CSI
            ("plain text", "plain text"),
            ("é ü 漢字", "é ü 漢字"),  # printable Unicode is left alone
        ],
    )
    def test_control_characters_become_visible(self, value, shown):
        console = Console(record=True, width=200)
        console.print(plain_text(value))
        assert console.export_text().rstrip("\n") == shown

    @pytest.mark.parametrize(
        "value", ["[/x]", "[bold]b[/bold]", "\\[/x]", "trailing\\", "[@click]"]
    )
    def test_markup_prints_verbatim_even_inside_our_own_markup(self, value):
        console = Console(record=True, width=200)
        console.print(f"[red]{plain_text(value)}[/red]")
        assert console.export_text().rstrip("\n") == value
