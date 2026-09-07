"""IronFlow command-line interface.

Structure::

    ironflow pipeline   run | validate | list | show | status | history | retry
                        | resume | logs
    ironflow schedule   list | start
    ironflow state      clean | watermarks | audit
    ironflow config     show | check | schema | init
    ironflow secrets    generate-key | encrypt | decrypt
    ironflow connectors list
    ironflow serve
    ironflow version

Exit codes are meaningful so CI and cron can branch on them: ``0`` success,
``1`` failure, ``2`` invalid configuration, ``3`` partial success, ``130``
cancelled.  A pipeline that half-succeeded should not look identical to one that
worked.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError as SettingsValidationError
from pydantic_settings import SettingsError

from ironflow.cli import pipeline_commands
from ironflow.cli.admin_commands import (
    config_app,
    connectors_app,
    schedule_app,
    secrets_app,
    state_app,
)
from ironflow.cli.context import EXIT_CANCELLED, EXIT_FAILED, EXIT_INVALID_CONFIG, build_context
from ironflow.core.errors import ConfigurationError, IronFlowError
from ironflow.version import APP_TITLE, __version__

logger = logging.getLogger(__name__)

app = typer.Typer(
    name="ironflow",
    help=f"{APP_TITLE} - enterprise ETL data pipeline platform.",
    no_args_is_help=True,
    add_completion=True,
    rich_markup_mode="rich",
    # Operators get a one-line message; the traceback goes to the log at DEBUG.
    # A framed traceback of pydantic internals helps nobody at 03:00.
    pretty_exceptions_enable=False,
)

app.add_typer(pipeline_commands.app, name="pipeline")
app.add_typer(config_app, name="config")
app.add_typer(secrets_app, name="secrets")
app.add_typer(connectors_app, name="connectors")
app.add_typer(schedule_app, name="schedule")
app.add_typer(state_app, name="state")


@app.callback()
def main_callback(
    ctx: typer.Context,
    log_level: Annotated[
        str | None,
        typer.Option("--log-level", "-l", help="DEBUG, INFO, WARNING, ERROR, CRITICAL."),
    ] = None,
    log_json: Annotated[
        bool, typer.Option("--log-json", help="Emit structured JSON logs.")
    ] = False,
    json_output: Annotated[
        bool, typer.Option("--json", help="Print machine-readable results.")
    ] = False,
    profile: Annotated[
        str | None, typer.Option("--profile", help="Pipeline profile overlay to apply.")
    ] = None,
    pipelines_dir: Annotated[
        Path | None, typer.Option("--pipelines-dir", help="Directory of pipeline definitions.")
    ] = None,
    env_file: Annotated[
        Path | None, typer.Option("--env-file", help="Extra .env file to load.")
    ] = None,
) -> None:
    """Global options applied to every command."""
    ctx.obj = build_context(
        log_level=log_level,
        log_json=log_json,
        json_output=json_output,
        profile=profile,
        pipelines_dir=pipelines_dir,
        env_file=env_file,
    )


@app.command("version")
def version_command() -> None:
    """Print the version and the available optional extras."""
    import importlib.util

    extras = {
        "columnar (parquet)": importlib.util.find_spec("pyarrow") is not None,
        "excel": importlib.util.find_spec("openpyxl") is not None,
        "remote (sftp)": importlib.util.find_spec("paramiko") is not None,
        "api": importlib.util.find_spec("fastapi") is not None,
        "postgres": importlib.util.find_spec("psycopg") is not None,
        "mysql": importlib.util.find_spec("pymysql") is not None,
    }
    typer.echo(f"{APP_TITLE} {__version__} (Python {sys.version.split()[0]})")
    for name, available in extras.items():
        typer.echo(f"  {'+' if available else '-'} {name}")


@app.command("serve")
def serve_command(
    ctx: typer.Context,
    host: Annotated[str | None, typer.Option("--host", help="Bind address.")] = None,
    port: Annotated[int | None, typer.Option("--port", help="Bind port.")] = None,
    reload: Annotated[bool, typer.Option("--reload", help="Auto-reload (development).")] = False,
) -> None:
    """Start the REST API and monitoring dashboard."""
    from ironflow.cli.context import get_cli

    cli = get_cli(ctx)
    try:
        import uvicorn
    except ImportError:
        cli.fail(
            "the API requires the 'api' extra: pip install 'ironflow[api]'",
            code=EXIT_INVALID_CONFIG,
        )
        return

    bind_host = host or cli.settings.api_host
    bind_port = port or cli.settings.api_port

    if cli.settings.is_production and not cli.settings.auth_enabled:
        cli.fail(
            "refusing to serve an unauthenticated API in a production environment; "
            "set IRONFLOW_AUTH_ENABLED=true and IRONFLOW_JWT_SECRET",
            code=EXIT_INVALID_CONFIG,
        )
        return
    if bind_host == "0.0.0.0" and not cli.settings.auth_enabled:  # noqa: S104
        cli.warn(
            "binding to all interfaces without authentication; "
            "anyone who can reach this port can trigger pipeline runs"
        )

    cli.info(f"[green]{APP_TITLE} API[/green] on http://{bind_host}:{bind_port}")
    uvicorn.run(
        "ironflow.api.app:create_app",
        factory=True,
        host=bind_host,
        port=bind_port,
        reload=reload,
        log_config=None,  # keep our own logging configuration
    )


def main() -> int:
    """Console-script entry point.

    Catches IronFlow errors at the boundary so an operator sees a one-line
    message instead of a traceback, while ``--log-level DEBUG`` still yields the
    full stack.

    Note on exit codes: Typer runs in standalone mode and calls ``sys.exit``
    itself, so a command that completes - successfully or with ``typer.Exit`` -
    raises :class:`SystemExit` straight through this function and the return
    value below is never reached.  The returned codes cover only the errors that
    escape the Typer machinery entirely, which is why both paths are needed.
    """
    try:
        app()
    except ConfigurationError as exc:
        logger.debug("configuration error", exc_info=True)
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INVALID_CONFIG
    except SettingsError as exc:
        # A malformed environment variable, e.g. IRONFLOW_MAX_PARALLEL_TASKS=lots
        logger.debug("settings error", exc_info=True)
        print(f"error: invalid configuration: {exc}", file=sys.stderr)
        return EXIT_INVALID_CONFIG
    except SettingsValidationError as exc:
        # A setting that parses but is rejected: IRONFLOW_LOG_LEVEL=bogus, or
        # auth enabled without a signing secret. The Settings object is built
        # during bootstrap, before Typer's own error handling, so without this
        # branch the operator gets a pydantic traceback and exit code 1 - which
        # contradicts the documented "2 = invalid configuration" that cron and
        # CI scripts branch on.
        logger.debug("settings validation error", exc_info=True)
        for error in exc.errors():
            location = ".".join(str(part) for part in error["loc"]) or "settings"
            detail = error["msg"].removeprefix("Value error, ")
            print(f"error: invalid configuration: {location}: {detail}", file=sys.stderr)
        return EXIT_INVALID_CONFIG
    except IronFlowError as exc:
        logger.debug("pipeline error", exc_info=True)
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_FAILED
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        return EXIT_CANCELLED
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
