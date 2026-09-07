"""``ironflow pipeline ...`` commands."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Annotated, Any

import typer
from rich.syntax import Syntax
from rich.table import Table

from ironflow.cli.context import (
    EXIT_CANCELLED,
    EXIT_FAILED,
    EXIT_INVALID_CONFIG,
    EXIT_PARTIAL,
    CliContext,
    get_cli,
    parse_key_values,
)
from ironflow.config.models import PipelineSpec
from ironflow.core.errors import IronFlowError
from ironflow.core.types import RunStatus
from ironflow.orchestration.dag import TaskGraph
from ironflow.pipeline.results import PipelineResult
from ironflow.services.reporting import (
    build_run_report,
    default_report_path,
    render_console_summary,
    write_html,
    write_json,
)

logger = logging.getLogger(__name__)

app = typer.Typer(help="Run, inspect and manage pipelines.", no_args_is_help=True)

_STATUS_EXIT = {
    RunStatus.SUCCESS: 0,
    RunStatus.PARTIAL: EXIT_PARTIAL,
    RunStatus.CANCELLED: EXIT_CANCELLED,
}


def _resolve_pipeline(
    cli: CliContext, name: str | None, file: Path | None, overrides: dict | None = None
) -> PipelineSpec:
    """Load a pipeline by name (from the pipelines dir) or by explicit path."""
    if file is not None:
        return cli.service.load_file(file, profile=cli.profile, overrides=overrides)
    if not name:
        raise typer.BadParameter("provide a pipeline NAME or --file PATH")
    spec = cli.service.get_pipeline(name, profile=cli.profile)
    return spec


# --------------------------------------------------------------------------- #
@app.command("list")
def list_pipelines(ctx: typer.Context) -> None:
    """List every pipeline discovered in the pipelines directory."""
    cli = get_cli(ctx)
    try:
        specs = cli.service.list_pipelines(profile=cli.profile)
    except IronFlowError as exc:
        cli.fail(exc, code=EXIT_INVALID_CONFIG)
        return

    payload = [
        {
            "name": spec.name,
            "version": spec.version,
            "tasks": len(spec.tasks),
            "enabled": spec.enabled,
            "schedule": (
                spec.schedule.cron or f"every {spec.schedule.interval_seconds}s"
                if spec.schedule
                else None
            ),
            "owner": spec.owner,
            "file": spec.source_file,
        }
        for spec in specs
    ]

    table = Table(title=f"Pipelines in {cli.service.repository.directory}", expand=True)
    table.add_column("Name", style="bold")
    table.add_column("Ver", justify="right")
    table.add_column("Tasks", justify="right")
    table.add_column("Schedule")
    table.add_column("Owner")
    table.add_column("Enabled", justify="center")
    for item in payload:
        table.add_row(
            str(item["name"]),
            str(item["version"]),
            str(item["tasks"]),
            str(item["schedule"] or "-"),
            str(item["owner"] or "-"),
            "[green]yes[/green]" if item["enabled"] else "[red]no[/red]",
        )
    if not payload:
        cli.info("[yellow]No pipelines found.[/yellow] Try 'ironflow config init'.")
    cli.emit(payload, table if payload else None)


@app.command("show")
def show_pipeline(
    ctx: typer.Context,
    name: Annotated[str | None, typer.Argument(help="Pipeline name.")] = None,
    file: Annotated[Path | None, typer.Option("--file", "-f", help="Pipeline file.")] = None,
    mermaid: Annotated[bool, typer.Option("--mermaid", help="Print the DAG as Mermaid.")] = False,
) -> None:
    """Show a pipeline's structure and task graph."""
    cli = get_cli(ctx)
    try:
        spec = _resolve_pipeline(cli, name, file)
        graph = TaskGraph.from_spec(spec)
    except IronFlowError as exc:
        cli.fail(exc, code=EXIT_INVALID_CONFIG)
        return

    if mermaid:
        cli.console.print(Syntax(graph.to_mermaid(), "mermaid", theme="ansi_dark"))
        return

    tasks: list[dict[str, Any]] = [
        {
            "name": task.name,
            "type": task.type,
            "depends_on": task.depends_on,
            "strategy": task.strategy.value,
            "source": task.source.type if task.source else None,
            "destination": task.destination.type if task.destination else None,
            "transformations": [t.type for t in task.transformations],
            "validation_rules": len(task.validation.rules) if task.validation else 0,
            "condition": task.condition,
        }
        for task in spec.tasks
    ]
    payload: dict[str, Any] = {
        "name": spec.name,
        "version": spec.version,
        "description": spec.description,
        "owner": spec.owner,
        "graph": graph.describe(),
        "tasks": tasks,
    }

    table = Table(title=f"{spec.name} v{spec.version}", expand=True)
    table.add_column("Task", style="bold")
    table.add_column("Depends on")
    table.add_column("Source")
    table.add_column("Destination")
    table.add_column("Strategy")
    table.add_column("Transforms", justify="right")
    table.add_column("Rules", justify="right")
    for task in tasks:
        table.add_row(
            str(task["name"]),
            ", ".join(task["depends_on"]) or "-",
            str(task["source"] or "-"),
            str(task["destination"] or "-"),
            str(task["strategy"]),
            str(len(task["transformations"])),
            str(task["validation_rules"]),
        )
    cli.info(
        f"[dim]levels: {graph.levels}  depth: {graph.depth}  "
        f"max parallelism: {graph.max_width}[/dim]"
    )
    cli.emit(payload, table)


@app.command("validate")
def validate_pipeline(
    ctx: typer.Context,
    name: Annotated[str | None, typer.Argument(help="Pipeline name.")] = None,
    file: Annotated[Path | None, typer.Option("--file", "-f", help="Pipeline file.")] = None,
    all_pipelines: Annotated[
        bool, typer.Option("--all", help="Validate every discovered pipeline.")
    ] = False,
) -> None:
    """Validate a pipeline definition without connecting to anything."""
    cli = get_cli(ctx)
    try:
        specs = (
            cli.service.list_pipelines(profile=cli.profile)
            if all_pipelines
            else [_resolve_pipeline(cli, name, file)]
        )
    except IronFlowError as exc:
        cli.fail(exc, code=EXIT_INVALID_CONFIG)
        return

    reports = [cli.service.validate(spec) for spec in specs]
    payload = {"valid": all(r["valid"] for r in reports), "reports": reports}

    for report in reports:
        marker = "[green]VALID[/green]" if report["valid"] else "[red]INVALID[/red]"
        cli.info(f"{marker}  {report['pipeline']}")
        for problem in report["problems"]:
            cli.info(f"  [red]![/red] {problem}")
        for warning in report["warnings"]:
            cli.info(f"  [yellow]?[/yellow] {warning}")

    if cli.json_output:
        cli.emit(payload)
    if not payload["valid"]:
        raise typer.Exit(EXIT_INVALID_CONFIG)


@app.command("run")
def run_pipeline(
    ctx: typer.Context,
    name: Annotated[str | None, typer.Argument(help="Pipeline name.")] = None,
    file: Annotated[Path | None, typer.Option("--file", "-f", help="Pipeline file.")] = None,
    param: Annotated[
        list[str] | None,
        typer.Option("--param", "-p", help="Runtime parameter, key=value. Repeatable."),
    ] = None,
    set_option: Annotated[
        list[str] | None,
        typer.Option("--set", "-s", help="Override a config key, e.g. defaults.batch_size=500."),
    ] = None,
    var: Annotated[
        list[str] | None, typer.Option("--var", help="Template variable, key=value.")
    ] = None,
    only: Annotated[
        list[str] | None,
        typer.Option("--only", help="Run only these tasks (dependencies are included)."),
    ] = None,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Read and transform, but write nothing.")
    ] = False,
    report: Annotated[
        Path | None, typer.Option("--report", help="Write an HTML/JSON report to this path.")
    ] = None,
) -> None:
    """Execute a pipeline."""
    cli = get_cli(ctx)
    parameters = parse_key_values(param, option="--param")
    overrides = parse_key_values(set_option, option="--set")
    variables = parse_key_values(var, option="--var")

    try:
        if file is not None:
            spec = cli.service.load_file(
                file, profile=cli.profile, overrides=overrides, variables=variables
            )
        else:
            spec = _resolve_pipeline(cli, name, None, overrides)
    except IronFlowError as exc:
        cli.fail(exc, code=EXIT_INVALID_CONFIG)
        return

    if dry_run:
        cli.info("[yellow]DRY RUN[/yellow] - destinations will not be written")

    try:
        result = cli.service.run(
            spec,
            parameters=parameters,
            dry_run=dry_run,
            only=list(only) if only else None,
            principal=cli.principal,
        )
    except IronFlowError as exc:
        cli.fail(exc)
        return

    if report is not None:
        _write_report(cli, result, report)

    cli.emit(result.to_dict(), render_console_summary(result))
    raise typer.Exit(_STATUS_EXIT.get(result.status, EXIT_FAILED))


def _write_report(cli: CliContext, result: PipelineResult, target: Path) -> None:
    payload = build_run_report(result)
    path = target
    if path.is_dir() or not path.suffix:
        path = default_report_path(path, result.pipeline_name, result.execution_id, "html")
    written = write_json(payload, path) if path.suffix == ".json" else write_html(payload, path)
    cli.info(f"[dim]report written to {written}[/dim]")


@app.command("retry")
def retry_pipeline(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Pipeline name.")],
    execution_id: Annotated[
        str | None, typer.Option("--execution-id", help="Specific run to retry.")
    ] = None,
) -> None:
    """Re-run a failed execution from the beginning."""
    cli = get_cli(ctx)
    try:
        result = cli.service.retry(
            name, execution_id=execution_id, principal=cli.principal, profile=cli.profile
        )
    except IronFlowError as exc:
        cli.fail(exc)
        return
    cli.emit(result.to_dict(), render_console_summary(result))
    raise typer.Exit(_STATUS_EXIT.get(result.status, EXIT_FAILED))


@app.command("resume")
def resume_pipeline(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Pipeline name.")],
    execution_id: Annotated[str, typer.Argument(help="Execution id to resume.")],
) -> None:
    """Continue a failed execution, skipping tasks that already succeeded."""
    cli = get_cli(ctx)
    try:
        result = cli.service.resume(
            name, execution_id, principal=cli.principal, profile=cli.profile
        )
    except IronFlowError as exc:
        cli.fail(exc)
        return
    cli.emit(result.to_dict(), render_console_summary(result))
    raise typer.Exit(_STATUS_EXIT.get(result.status, EXIT_FAILED))


@app.command("status")
def pipeline_status(
    ctx: typer.Context,
    name: Annotated[str, typer.Argument(help="Pipeline name.")],
) -> None:
    """Show the current state and 30-day statistics for a pipeline."""
    cli = get_cli(ctx)
    payload = cli.service.status(name)
    stats = payload["statistics"]
    last = payload["last_run"]

    table = Table(title=f"Status: {name}", expand=True, show_header=False)
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Last status", str(last["status"]) if last else "never run")
    table.add_row("Last run", str(last["started_at"]) if last else "-")
    table.add_row("Currently running", str(payload["running"]))
    table.add_row("Runs (30d)", str(stats["runs_total"]))
    table.add_row("Success rate", f"{stats['success_rate'] * 100:.1f}%")
    table.add_row("Avg duration", f"{stats['avg_duration_seconds']:.2f}s")
    table.add_row("p95 duration", f"{stats['p95_duration_seconds']:.2f}s")
    table.add_row("Rows written (30d)", str(stats["rows_written"]))
    table.add_row("Watermarks", str(len(payload["watermarks"])))
    cli.emit(payload, table)


@app.command("history")
def pipeline_history(
    ctx: typer.Context,
    name: Annotated[str | None, typer.Argument(help="Pipeline name.")] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", min=1, max=500)] = 20,
    status: Annotated[str | None, typer.Option("--status", help="Filter by status.")] = None,
) -> None:
    """List recent executions."""
    cli = get_cli(ctx)
    try:
        status_filter = RunStatus(status) if status else None
    except ValueError:
        cli.fail(
            f"unknown status {status!r}; expected one of {', '.join(s.value for s in RunStatus)}",
            code=EXIT_INVALID_CONFIG,
        )
        return

    runs = cli.service.history(
        pipeline_name=name, status=status_filter, limit=limit, principal=cli.principal
    )
    table = Table(title="Execution history", expand=True)
    table.add_column("Started")
    table.add_column("Pipeline", style="bold")
    table.add_column("Status")
    table.add_column("Seconds", justify="right")
    table.add_column("Read", justify="right")
    table.add_column("Written", justify="right")
    table.add_column("Rejected", justify="right")
    table.add_column("Execution")

    colours = {"success": "green", "failed": "red", "partial": "yellow", "running": "blue"}
    for run in runs:
        colour = colours.get(str(run["status"]), "white")
        table.add_row(
            str(run["started_at"] or "-")[:19],
            str(run["pipeline"]),
            f"[{colour}]{run['status']}[/{colour}]",
            f"{run['duration_seconds']:.2f}",
            str(run["rows_read"]),
            str(run["rows_written"]),
            str(run["rows_rejected"]),
            str(run["execution_id"])[:16],
        )
    if not runs:
        cli.info("[yellow]No runs recorded yet.[/yellow]")
    cli.emit(runs, table if runs else None)


@app.command("logs")
def pipeline_logs(
    ctx: typer.Context,
    execution_id: Annotated[str, typer.Argument(help="Execution id.")],
) -> None:
    """Show the per-task breakdown of one execution."""
    cli = get_cli(ctx)
    run = cli.service.run_details(execution_id)
    if run is None:
        cli.fail(f"no run found with execution id {execution_id!r}", code=EXIT_INVALID_CONFIG)
        return

    table = Table(title=f"{run['pipeline']} · {execution_id}", expand=True)
    table.add_column("Task", style="bold")
    table.add_column("Status")
    table.add_column("Attempt", justify="right")
    table.add_column("Seconds", justify="right")
    table.add_column("Read", justify="right")
    table.add_column("Written", justify="right")
    table.add_column("Rejected", justify="right")
    table.add_column("Error")

    for task in run.get("task_runs", []):
        error = task.get("error") or {}
        table.add_row(
            str(task["task"]),
            str(task["status"]),
            str(task["attempt"]),
            f"{task['duration_seconds']:.2f}",
            str(task["rows_read"]),
            str(task["rows_written"]),
            str(task["rows_rejected"]),
            str(error.get("message", ""))[:60],
        )
    cli.emit(run, table)


__all__ = ["app"]
