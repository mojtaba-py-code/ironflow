"""``ironflow config|secrets|connectors|schedule|state`` commands."""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path
from typing import Annotated

import typer
from rich.syntax import Syntax
from rich.table import Table

from ironflow.cli.context import EXIT_INVALID_CONFIG, get_cli
from ironflow.config.models import PipelineSpec
from ironflow.connectors.factory import describe_connectors
from ironflow.core.errors import IronFlowError
from ironflow.security.crypto import CryptoService, generate_key
from ironflow.services.reporting import plain_text
from ironflow.transformation.base import TRANSFORM_REGISTRY
from ironflow.validation.rules import RULE_REGISTRY
from ironflow.version import APP_TITLE

logger = logging.getLogger(__name__)

config_app = typer.Typer(help="Inspect and scaffold configuration.", no_args_is_help=True)
secrets_app = typer.Typer(help="Manage encrypted secrets.", no_args_is_help=True)
connectors_app = typer.Typer(help="Inspect available components.", no_args_is_help=True)
schedule_app = typer.Typer(help="Run and inspect the scheduler.", no_args_is_help=True)
state_app = typer.Typer(help="Maintain platform state.", no_args_is_help=True)


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #
@config_app.command("show")
def config_show(ctx: typer.Context) -> None:
    """Print the effective settings, with secrets redacted."""
    cli = get_cli(ctx)
    payload = cli.settings.redacted()
    table = Table(title=f"{APP_TITLE} settings", expand=True)
    table.add_column("Setting", style="bold")
    table.add_column("Value")
    for key, value in sorted(payload.items()):
        table.add_row(key, plain_text(value))
    cli.emit(payload, table)


@config_app.command("check")
def config_check(ctx: typer.Context) -> None:
    """Health check: database reachability and production hardening."""
    cli = get_cli(ctx)
    health = cli.service.healthcheck()
    problems = health["production_problems"]

    cli.info(f"database: {'[green]ok[/green]' if health['database'] else '[red]unreachable[/red]'}")
    cli.info(
        f"pipelines: {health['pipelines_discovered']} in {plain_text(health['pipelines_dir'])}"
    )
    cli.info(f"environment: {health['environment']}")
    if problems:
        cli.info("[red]production hardening problems:[/red]")
        for problem in problems:
            cli.info(f"  [red]![/red] {problem}")
    elif cli.settings.is_production:
        cli.info("[green]production hardening: ok[/green]")

    cli.emit(health)
    if not health["database"] or problems:
        raise typer.Exit(EXIT_INVALID_CONFIG)


@config_app.command("schema")
def config_schema(
    ctx: typer.Context,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the schema to a file.")
    ] = None,
) -> None:
    """Emit the JSON Schema for a pipeline file (for editor autocompletion)."""
    cli = get_cli(ctx)
    schema = PipelineSpec.json_schema()
    if output is not None:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(schema, indent=2), encoding="utf-8")
        cli.info(f"schema written to {plain_text(output)}")
        return
    cli.emit(schema, Syntax(json.dumps(schema, indent=2), "json", theme="ansi_dark"))


@config_app.command("init")
def config_init(
    ctx: typer.Context,
    directory: Annotated[Path, typer.Option("--dir", "-d", help="Where to scaffold.")] = Path(),
    force: Annotated[bool, typer.Option("--force", help="Overwrite existing files.")] = False,
) -> None:
    """Scaffold a pipelines directory, an example pipeline, its input and a .env.

    The input CSV is scaffolded too, deliberately. Without it the four commands
    the README opens with end in a failed run against a path that was never
    created, and a reader's first impression of the platform is an
    ``ExtractionError``.
    """
    cli = get_cli(ctx)
    root = directory.expanduser().resolve()
    pipelines = root / "pipelines"
    pipelines.mkdir(parents=True, exist_ok=True)

    created: list[str] = []
    for relative, content in (
        ("pipelines/example.yaml", _EXAMPLE_PIPELINE),
        ("data/raw/orders.csv", _EXAMPLE_DATA),
        (".env.example", _ENV_TEMPLATE),
    ):
        target = root / relative
        if target.exists() and not force:
            cli.warn(f"{relative} already exists (use --force to overwrite)")
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        created.append(relative)

    cli.info(f"[green]scaffolded[/green] {len(created)} file(s) in {plain_text(root)}")
    for item in created:
        cli.info(f"  + {item}")
    cli.emit({"root": str(root), "created": created})


# --------------------------------------------------------------------------- #
# secrets
# --------------------------------------------------------------------------- #
@secrets_app.command("generate-key")
def secrets_generate_key(ctx: typer.Context) -> None:
    """Generate an encryption key for IRONFLOW_ENCRYPTION_KEY."""
    cli = get_cli(ctx)
    key = generate_key()
    # ``typer.echo``, not the rich console: rich wraps at the terminal width and
    # may add styling, either of which corrupts a value the user will copy or
    # pipe. Printed to stdout only, never logged - a key in a log is not a secret.
    typer.echo(key)
    cli.error_console.print(
        "[dim]Store this in a secret manager and export it as "
        "IRONFLOW_ENCRYPTION_KEY. It is not saved anywhere by this command.[/dim]"
    )


@secrets_app.command("encrypt")
def secrets_encrypt(
    ctx: typer.Context,
    value: Annotated[
        str | None, typer.Option("--value", help="Value to encrypt (omit to be prompted).")
    ] = None,
) -> None:
    """Encrypt a value into an envelope you can paste into a pipeline file."""
    cli = get_cli(ctx)
    # Prompting by default keeps the plaintext out of the shell history.
    plaintext = value if value is not None else typer.prompt("value", hide_input=True)
    try:
        crypto = (
            CryptoService.from_key(cli.settings.encryption_key)
            if cli.settings.encryption_key
            else CryptoService.from_env()
        )
    except IronFlowError as exc:
        cli.fail(exc, code=EXIT_INVALID_CONFIG)
        return
    # Unwrapped and unstyled - this envelope gets pasted into a pipeline file.
    typer.echo(crypto.encrypt(plaintext))


@secrets_app.command("decrypt")
def secrets_decrypt(
    ctx: typer.Context,
    envelope: Annotated[str, typer.Argument(help="Ciphertext envelope.")],
) -> None:
    """Decrypt an envelope (for verifying a rotation)."""
    cli = get_cli(ctx)
    try:
        crypto = (
            CryptoService.from_key(cli.settings.encryption_key)
            if cli.settings.encryption_key
            else CryptoService.from_env()
        )
        typer.echo(crypto.decrypt(envelope))
    except IronFlowError as exc:
        cli.fail(exc, code=EXIT_INVALID_CONFIG)


# --------------------------------------------------------------------------- #
# connectors / components
# --------------------------------------------------------------------------- #
@connectors_app.command("list")
def connectors_list(ctx: typer.Context) -> None:
    """List every registered connector, transformation and validation rule."""
    cli = get_cli(ctx)
    catalogue = describe_connectors()
    payload = {
        **catalogue,
        "transformations": TRANSFORM_REGISTRY.names(),
        "validation_rules": RULE_REGISTRY.names(),
    }

    for title, entries in (("Sources", catalogue["sources"]), ("Sinks", catalogue["sinks"])):
        table = Table(title=title, expand=True)
        table.add_column("Type(s)", style="bold")
        table.add_column("Class")
        table.add_column("Summary")
        for entry in entries:
            table.add_row(entry["types"], entry["class"], entry["summary"])
        cli.info(table)  # type: ignore[arg-type]

    cli.info(
        f"\n[bold]Transformations[/bold] ({len(TRANSFORM_REGISTRY)}): "
        f"{', '.join(TRANSFORM_REGISTRY.names())}"
    )
    cli.info(
        f"\n[bold]Validation rules[/bold] ({len(RULE_REGISTRY)}): "
        f"{', '.join(RULE_REGISTRY.names())}"
    )
    if cli.json_output:
        cli.emit(payload)


# --------------------------------------------------------------------------- #
# schedule
# --------------------------------------------------------------------------- #
@schedule_app.command("list")
def schedule_list(ctx: typer.Context) -> None:
    """Show the schedule of every pipeline that declares one."""
    cli = get_cli(ctx)
    scheduler = cli.service.build_scheduler()
    jobs = scheduler.describe()

    table = Table(title="Scheduled pipelines", expand=True)
    table.add_column("Pipeline", style="bold")
    table.add_column("Schedule")
    table.add_column("Timezone")
    table.add_column("Next run")
    # The timezone is free text from the pipeline file; it is not validated.
    for job in jobs:
        table.add_row(
            plain_text(job["pipeline"]),
            plain_text(job["schedule"]),
            plain_text(job["timezone"]),
            plain_text(str(job["next_run"])[:19]),
        )
    if not jobs:
        cli.info("[yellow]No pipelines declare a schedule.[/yellow]")
    cli.emit(jobs, table if jobs else None)


@schedule_app.command("start")
def schedule_start(
    ctx: typer.Context,
    poll_interval: Annotated[
        float, typer.Option("--poll", min=1.0, help="Seconds between scheduler ticks.")
    ] = 30.0,
    once: Annotated[bool, typer.Option("--once", help="Evaluate schedules once and exit.")] = False,
) -> None:
    """Run the scheduler in the foreground.

    Run exactly one instance: this scheduler has no distributed lock, so two
    replicas would double-trigger every job.
    """
    cli = get_cli(ctx)
    scheduler = cli.service.build_scheduler(poll_interval=poll_interval)
    if not scheduler.jobs():
        cli.info("[yellow]Nothing to schedule.[/yellow]")
        return

    if once:
        triggered = scheduler.tick()
        cli.emit({"triggered": triggered})
        return

    cli.info(
        f"[green]scheduler running[/green] with {len(scheduler.jobs())} job(s); Ctrl-C to stop"
    )
    scheduler.start()
    try:
        while scheduler.is_running:
            time.sleep(1.0)
    except KeyboardInterrupt:
        cli.info("\nstopping scheduler...")
    finally:
        scheduler.stop()


# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #
@state_app.command("clean")
def state_clean(
    ctx: typer.Context,
    history_days: Annotated[int, typer.Option("--history-days", min=1)] = 90,
    checkpoint_days: Annotated[int, typer.Option("--checkpoint-days", min=1)] = 30,
    reset_watermarks: Annotated[
        str | None,
        typer.Option("--reset-watermarks", help="Pipeline whose watermarks to clear."),
    ] = None,
    reset_schemas: Annotated[
        str | None,
        typer.Option(
            "--reset-schemas",
            help="Pipeline whose schema snapshots to clear. Use after a deliberate "
            "schema change so drift detection re-baselines.",
        ),
    ] = None,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip confirmation.")] = False,
) -> None:
    """Purge old run history, checkpoints, watermarks and schema snapshots."""
    cli = get_cli(ctx)
    if reset_watermarks and not yes:
        # Clearing a watermark makes the next run re-read everything from the
        # source - potentially millions of rows and a duplicate load.
        typer.confirm(
            f"Reset watermarks for {reset_watermarks!r}? The next run will perform a full re-read.",
            abort=True,
        )
    removed = cli.service.clean(
        history_days=history_days,
        checkpoint_days=checkpoint_days,
        reset_watermarks=reset_watermarks,
        reset_schemas=reset_schemas,
        principal=cli.principal,
    )
    cli.info(
        f"purged {removed['runs_purged']} run(s), "
        f"{removed['checkpoints_purged']} checkpoint(s), "
        f"reset {removed['watermarks_reset']} watermark(s), "
        f"{removed['schemas_reset']} schema snapshot(s)"
    )
    cli.emit(removed)


@state_app.command("watermarks")
def state_watermarks(
    ctx: typer.Context,
    pipeline: Annotated[str | None, typer.Argument(help="Pipeline name.")] = None,
) -> None:
    """List incremental-extraction watermarks."""
    cli = get_cli(ctx)
    rows = cli.service.watermarks.list(pipeline)
    table = Table(title="Watermarks", expand=True)
    table.add_column("Pipeline", style="bold")
    table.add_column("Task")
    table.add_column("Column")
    table.add_column("Value")
    table.add_column("Rows", justify="right")
    table.add_column("Updated")
    # A watermark value is the high-water mark read from source data.
    for row in rows:
        table.add_row(
            plain_text(row["pipeline"]),
            plain_text(row["task"]),
            plain_text(row["column"]),
            plain_text(row["value"]),
            str(row["rows_last_run"]),
            plain_text(str(row["updated_at"] or "")[:19]),
        )
    if not rows:
        cli.info("[yellow]No watermarks recorded.[/yellow]")
    cli.emit(rows, table if rows else None)


@state_app.command("audit")
def state_audit(
    ctx: typer.Context,
    limit: Annotated[int, typer.Option("--limit", "-n", min=1, max=1000)] = 25,
    verify: Annotated[bool, typer.Option("--verify", help="Verify the audit hash chain.")] = False,
) -> None:
    """Read the audit trail and optionally verify its integrity."""
    cli = get_cli(ctx)
    audit = cli.service.audit

    if verify:
        intact, broken_at = audit.verify_chain()
        if intact:
            cli.info("[green]audit chain intact[/green]")
        else:
            cli.info(f"[bold red]audit chain broken at entry {broken_at}[/bold red]")
        cli.emit({"intact": intact, "broken_at": broken_at})
        if not intact:
            raise typer.Exit(EXIT_INVALID_CONFIG)
        return

    entries = audit.read(limit=limit)
    table = Table(title="Audit trail", expand=True)
    table.add_column("Timestamp")
    table.add_column("Action", style="bold")
    table.add_column("Actor")
    table.add_column("Outcome")
    table.add_column("Resource")
    # An actor can be an API token's subject, and whoever can write the file
    # controls every field in it.
    for entry in entries:
        table.add_row(
            plain_text(str(entry.get("timestamp", ""))[:19]),
            plain_text(entry.get("action", "")),
            plain_text(entry.get("actor", "")),
            plain_text(entry.get("outcome", "")),
            plain_text(entry.get("resource", "") or "-"),
        )
    if not entries:
        cli.info("[yellow]No audit entries recorded.[/yellow]")
    cli.emit(entries, table if entries else None)


# --------------------------------------------------------------------------- #
#: Input for the scaffolded pipeline. Two rows are deliberately bad - one
#: negative amount and one duplicate order id - so the first run a reader
#: performs also exercises the quarantine path, rather than a clean happy
#: path that says nothing about how failures are handled.
_EXAMPLE_DATA = """\
Order ID,Customer Email,Amount,Order Date
1001,alice@example.com,49.99,2026-01-15
1002,bob@example.com,199.00,2026-01-16
1003,carol@example.com,-12.50,2026-01-17
1004,dave@example.com,25.50,2026-01-18
1005,erin@example.com,310.75,2026-01-19
1002,bob@example.com,199.00,2026-01-16
1006,frank@example.com,88.20,2026-01-20
"""

_EXAMPLE_PIPELINE = """\
# Example IronFlow pipeline.
#   ironflow pipeline validate example
#   ironflow pipeline run example --dry-run
#   ironflow pipeline run example
name: example
version: "1"
description: Load orders from CSV, clean them, and write Parquet.
owner: data-engineering

variables:
  input_dir: ./data/raw
  output_dir: ./data/curated

defaults:
  batch_size: 10000
  retry:
    max_attempts: 3
    initial_delay: 2

tasks:
  - name: load_orders
    description: Clean, validate and curate the daily order export.
    source:
      type: csv
      path: "${var.input_dir}/orders.csv"
      delimiter: ","
      encoding: utf-8

    transformations:
      - type: normalize_columns          # "Order Date" -> order_date
      - type: cast
        columns:
          order_id: integer
          amount: float
          order_date: date
      - type: derive
        column: amount_with_vat
        expression: "round(amount * 1.21, 2)"
      - type: mask_pii                   # never land raw PII downstream
        columns: [customer_email]
        strategy: email
      - type: add_metadata
        include: [execution_id, loaded_at]

    validation:
      on_violation: quarantine           # keep bad rows, do not lose them
      max_error_rate: 0.05               # abort if >5% of rows are rejected
      rules:
        - type: not_null
          field: order_id
        - type: unique
          field: order_id
        - type: range
          field: amount
          min: 0
          message: "order amount cannot be negative"

    destination:
      type: parquet
      path: "${var.output_dir}/orders.parquet"
      mode: overwrite
      compression: snappy

    reject_destination:
      type: csv
      path: "${var.output_dir}/orders_rejected.csv"
      mode: overwrite

# Uncomment to run unattended.
# schedule:
#   cron: "0 2 * * *"
#   timezone: Europe/Amsterdam
#
# notifications:
#   - type: slack
#     target: env:SLACK_WEBHOOK_URL
#     on: [failed, partial]

# Environment-specific overrides: ironflow --profile production pipeline run example
profiles:
  production:
    defaults:
      batch_size: 50000
"""

_ENV_TEMPLATE = """\
# IronFlow environment template. Copy to .env and fill in; never commit .env.
IRONFLOW_ENVIRONMENT=local
IRONFLOW_LOG_LEVEL=INFO
IRONFLOW_LOG_JSON=false

# Where pipeline definitions live.
IRONFLOW_PIPELINES_DIR=./pipelines

# Directories connectors may read and write. Required in production.
IRONFLOW_DATA_ROOTS=./data

# Control-plane database. Use PostgreSQL in production.
# IRONFLOW_STATE_DATABASE_URL=postgresql+psycopg://ironflow:***@db:5432/ironflow

# Secret encryption key: generate with `ironflow secrets generate-key`.
# IRONFLOW_ENCRYPTION_KEY=

# API authentication (required in production).
# IRONFLOW_AUTH_ENABLED=true
# IRONFLOW_JWT_SECRET=

# Data-source credentials, referenced from pipelines as env:PGPASSWORD
# PGPASSWORD=
# SLACK_WEBHOOK_URL=
"""

__all__ = [
    "config_app",
    "connectors_app",
    "schedule_app",
    "secrets_app",
    "state_app",
]
