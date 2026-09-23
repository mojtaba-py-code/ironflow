"""Shared CLI wiring: global options, bootstrap and output helpers.

Every command needs the same four things - settings, logging, the service and a
console - so they are built once here and stashed on the Typer context rather
than reconstructed per command.  That also means ``--log-level`` and
``--json`` behave identically everywhere instead of being re-implemented (and
diverging) per command.
"""

from __future__ import annotations

import json
import logging
import sys
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import typer
from rich.console import Console

from ironflow.config.settings import Settings, get_settings
from ironflow.core.errors import IronFlowError
from ironflow.observability.logging import configure_logging
from ironflow.repositories.database import Database
from ironflow.security.rbac import Principal
from ironflow.services.pipeline_service import PipelineService

logger = logging.getLogger(__name__)

#: Exit codes, so shell scripts and CI can branch on the reason.
EXIT_OK = 0
EXIT_FAILED = 1
EXIT_INVALID_CONFIG = 2
EXIT_PARTIAL = 3
EXIT_CANCELLED = 130


@dataclass(slots=True)
class CliContext:
    """State shared by every command."""

    settings: Settings
    console: Console
    error_console: Console
    json_output: bool = False
    profile: str | None = None
    pipelines_dir: Path | None = None
    _service: PipelineService | None = field(default=None, repr=False)

    @property
    def service(self) -> PipelineService:
        """Lazily build the service so ``--help`` never opens a database."""
        if self._service is None:
            database = Database(settings=self.settings)
            self._service = PipelineService(
                self.settings, database=database, pipelines_dir=self.pipelines_dir
            )
        return self._service

    @property
    def principal(self) -> Principal:
        """CLI identity.

        Anyone who can run the binary already has the host's credentials, so a
        second authentication factor here would be theatre.  Real authorisation
        happens at the API boundary; the CLI records *who* ran the command in
        the audit trail via the OS user.
        """
        import getpass

        try:
            user = getpass.getuser()
        except Exception:
            user = "cli"
        return Principal.system(subject=f"cli:{user}")

    # -- output ------------------------------------------------------------ #
    def emit(self, payload: Any, renderable: Any = None) -> None:
        """Print JSON when ``--json`` was given, otherwise the rich form.

        In human mode with no renderable this prints nothing: the command has
        already said what it needed to, and dumping raw JSON underneath it is
        noise.
        """
        if self.json_output:
            self._print_json(json.dumps(payload, default=str, ensure_ascii=False))
        elif renderable is not None:
            self.console.print(renderable)

    def _print_json(self, text: str) -> None:
        """Write machine-readable JSON, with no styling of any kind.

        ``Console.print_json`` syntax-highlights, and Rich emits the colour when
        the stream is a terminal *or* when FORCE_COLOR is set — which CI sets.
        The result is a document wrapped in escape sequences that ``json.loads``
        and ``jq`` both reject, so ``--json`` stopped being machine-readable in
        exactly the environment that parses it. Nothing is styled here, markup
        is off so a brace in a value cannot be read as a tag, and soft wrapping
        keeps Rich from folding a long line to the terminal width.
        """
        self.console.print(text, markup=False, highlight=False, soft_wrap=True)

    def info(self, message: str) -> None:
        if not self.json_output:
            self.console.print(message)

    def warn(self, message: str) -> None:
        self.error_console.print(f"[yellow]warning:[/yellow] {message}")

    def fail(self, error: Exception | str, *, code: int = EXIT_FAILED) -> None:
        """Report an error and exit with ``code``."""
        if isinstance(error, IronFlowError):
            if self.json_output:
                self._print_json(json.dumps(error.to_dict(), default=str))
            else:
                self.error_console.print(f"[bold red]error:[/bold red] {error.message}")
                for key, value in sorted(error.context.items()):
                    self.error_console.print(f"  [dim]{key}:[/dim] {value}")
        else:
            self.error_console.print(f"[bold red]error:[/bold red] {error}")
        raise typer.Exit(code)


def _console(*, stderr: bool = False) -> Console:
    """A console that degrades on an unencodable character instead of crashing.

    On Windows a *redirected* stdout falls back to the ANSI code page (cp1252),
    which has no ``->`` arrow and no middle dot - both of which appear in the run
    summary.  Rich then raises ``UnicodeEncodeError`` from inside the render, so
    ``ironflow pipeline run sales_daily > run.log`` - an ordinary cron
    invocation - loses its summary *and* exits non-zero after a load that
    actually succeeded.  The interactive terminal never shows this, which is
    exactly why it survives to production.

    Switching the stream to ``errors="replace"`` keeps the characters wherever
    the terminal can render them and substitutes ``?`` where it cannot.  The
    encoding itself is left alone: forcing UTF-8 onto a legacy console would
    trade a crash for mojibake.
    """
    stream = sys.stderr if stderr else sys.stdout
    reconfigure = getattr(stream, "reconfigure", None)
    if reconfigure is not None:
        # Absent under pytest's capture and on a closed stream; neither is fatal.
        with suppress(OSError, ValueError):
            reconfigure(errors="replace")
    return Console(stderr=stderr)


def build_context(
    *,
    log_level: str | None,
    log_json: bool,
    json_output: bool,
    profile: str | None,
    pipelines_dir: Path | None,
    env_file: Path | None,
) -> CliContext:
    """Construct the CLI context and configure logging."""
    if env_file is not None:
        from dotenv import load_dotenv

        load_dotenv(env_file, override=False)

    settings = get_settings()
    if pipelines_dir is not None:
        settings = settings.model_copy(update={"pipelines_dir": pipelines_dir})

    configure_logging(
        level=log_level or settings.log_level,
        # Structured output on stderr would interleave with rich tables on
        # stdout, so human mode stays human unless asked otherwise.
        json_output=log_json or settings.log_json,
        log_file=settings.log_file,
        max_bytes=settings.log_max_bytes,
        backup_count=settings.log_backup_count,
        service=settings.service_name,
        environment=settings.environment,
    )

    return CliContext(
        settings=settings,
        console=_console(),
        error_console=_console(stderr=True),
        json_output=json_output,
        profile=profile,
        pipelines_dir=pipelines_dir,
    )


def get_cli(ctx: typer.Context) -> CliContext:
    """Fetch the :class:`CliContext` attached to a Typer context."""
    obj = ctx.obj
    if not isinstance(obj, CliContext):  # pragma: no cover - defensive
        raise typer.Exit(EXIT_INVALID_CONFIG)
    return obj


def parse_key_values(pairs: list[str] | None, *, option: str) -> dict[str, Any]:
    """Parse repeated ``--set key=value`` options into a mapping.

    Values are parsed as JSON when possible so ``--param batch=500`` yields an
    int and ``--param cols='["a","b"]'`` yields a list; anything else stays a
    string.
    """
    result: dict[str, Any] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise typer.BadParameter(f"{option} expects key=value, got {pair!r}")
        key, _, raw = pair.partition("=")
        key = key.strip()
        if not key:
            raise typer.BadParameter(f"{option} has an empty key in {pair!r}")
        try:
            result[key] = json.loads(raw)
        except json.JSONDecodeError:
            result[key] = raw
    return result


__all__ = [
    "EXIT_CANCELLED",
    "EXIT_FAILED",
    "EXIT_INVALID_CONFIG",
    "EXIT_OK",
    "EXIT_PARTIAL",
    "CliContext",
    "build_context",
    "get_cli",
    "parse_key_values",
]
