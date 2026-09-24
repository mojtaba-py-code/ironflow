"""Report generation - run summaries, data-quality reports and dashboards.

Three output formats, one data model:

``dict``/JSON
    Machine consumption and the REST API.
Rich console tables
    What an operator sees in the terminal.
Self-contained HTML
    An artefact that can be attached to a ticket or emailed.  No external CSS or
    JS, because a report that only renders with an internet connection is not an
    artefact.

The HTML writer escapes every interpolated value with :func:`html.escape`.  Run
data contains error messages that contain source data, so a report is an XSS
sink unless every value is escaped - including the ones that "obviously" come
from our own enums.

The terminal is a sink too.  Rich reads ``[...]`` in any string as markup and
passes escape sequences straight through, so a pipeline file or a source row
could restyle the output, plant an OSC-8 hyperlink, or crash a whole listing
with an unbalanced ``[/x]``.  Every such value goes through :func:`plain_text`
before it reaches a console.
"""

from __future__ import annotations

import html
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.markup import escape as escape_markup

from ironflow.core.context import utcnow
from ironflow.core.types import RunStatus
from ironflow.pipeline.results import PipelineResult
from ironflow.security.masking import redact_mapping
from ironflow.version import APP_TITLE, __version__

logger = logging.getLogger(__name__)

_STATUS_COLOURS = {
    "success": "#1a7f37",
    "partial": "#9a6700",
    "failed": "#cf222e",
    "skipped": "#57606a",
    "cancelled": "#8250df",
    "running": "#0969da",
}

#: C0 and C1 control characters and DEL, each mapped to the escape Python itself
#: prints for it. None of them is text: ESC opens an ANSI sequence, CR and BS
#: overwrite what is already on the line, and a newline in a value could forge
#: a line of output. Shown rather than dropped, so an operator can see that a
#: value carried them.
_CONTROL_ESCAPES = {
    code: repr(chr(code))[1:-1] for code in (*range(0x20), 0x7F, *range(0x80, 0xA0))
}


def plain_text(value: object) -> str:
    """Render an untrusted value as literal text for a Rich console.

    Control characters become visible escapes and markup is escaped, so the
    result can sit in a table cell or inside our own markup and still print
    exactly what the value contains. Slice a value *before* passing it here:
    cutting the result could split an escape and expose the markup after it.
    """
    return escape_markup(str(value).translate(_CONTROL_ESCAPES))


def build_run_report(result: PipelineResult) -> dict[str, Any]:
    """Structured report for one run."""
    quality = [
        {
            "task": task.task_name,
            **{k: v for k, v in task.validation.items() if k != "samples"},
        }
        for task in result.tasks
        if task.validation
    ]
    transformations = [
        {"task": task.task_name, "steps": task.transformations}
        for task in result.tasks
        if task.transformations
    ]
    return {
        "generated_at": utcnow().isoformat(),
        "generator": f"{APP_TITLE} {__version__}",
        "run": result.to_dict(),
        "data_quality": quality,
        "transformations": transformations,
        "slowest_tasks": sorted(
            ({"task": t.task_name, "seconds": round(t.duration_seconds, 3)} for t in result.tasks),
            key=lambda item: -float(item["seconds"]),  # type: ignore[arg-type]
        )[:5],
    }


def build_dashboard_report(
    statistics: dict[str, Any],
    timeline: list[dict[str, Any]],
    *,
    pipelines: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Aggregate report across pipelines."""
    return {
        "generated_at": utcnow().isoformat(),
        "generator": f"{APP_TITLE} {__version__}",
        "statistics": statistics,
        "timeline": timeline,
        "pipelines": pipelines or [],
    }


def write_json(report: dict[str, Any], path: str | Path) -> Path:
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(
        json.dumps(redact_mapping(report), indent=2, default=str, ensure_ascii=False),
        encoding="utf-8",
    )
    logger.info("wrote JSON report to %s", target)
    return target


def write_html(report: dict[str, Any], path: str | Path) -> Path:
    """Render a self-contained HTML report."""
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(_render_html(redact_mapping(report)), encoding="utf-8")
    logger.info("wrote HTML report to %s", target)
    return target


def _render_html(report: dict[str, Any]) -> str:
    run = report.get("run", {})
    status = str(run.get("status", "unknown"))
    colour = _STATUS_COLOURS.get(status, "#57606a")
    rows = run.get("rows", {})

    cards = "".join(
        _card(label, value)
        for label, value in (
            ("Rows read", rows.get("read", 0)),
            ("Rows written", rows.get("written", 0)),
            ("Rows rejected", rows.get("rejected", 0)),
            ("Duration (s)", run.get("duration_seconds", 0)),
            ("Throughput (rows/s)", run.get("throughput_rows_per_second", 0)),
        )
    )

    task_rows = "".join(
        f"<tr>"
        f"<td>{html.escape(str(task.get('task', '')))}</td>"
        f"<td><span class='badge' style='background:"
        f"{_STATUS_COLOURS.get(str(task.get('status')), '#57606a')}'>"
        f"{html.escape(str(task.get('status', '')))}</span></td>"
        f"<td class='num'>{html.escape(str(task.get('duration_seconds', 0)))}</td>"
        f"<td class='num'>{html.escape(str(task.get('metrics', {}).get('rows_in', 0)))}</td>"
        f"<td class='num'>{html.escape(str(task.get('metrics', {}).get('rows_out', 0)))}</td>"
        f"<td class='num'>{html.escape(str(task.get('metrics', {}).get('rows_failed', 0)))}</td>"
        f"</tr>"
        for task in run.get("tasks", [])
    )

    quality_rows = "".join(
        f"<tr>"
        f"<td>{html.escape(str(item.get('task', '')))}</td>"
        f"<td class='num'>{html.escape(str(item.get('records_checked', 0)))}</td>"
        f"<td class='num'>{html.escape(str(item.get('records_rejected', 0)))}</td>"
        f"<td class='num'>{html.escape(str(round(float(item.get('pass_rate', 1)) * 100, 2)))}%</td>"
        f"<td>{html.escape(json.dumps(item.get('by_rule', {}))[:200])}</td>"
        f"</tr>"
        for item in report.get("data_quality", [])
    )

    task_body = task_rows or '<tr><td colspan="6">No tasks</td></tr>'
    quality_panel = (
        '<div class="panel"><h2>Data quality</h2><table><thead><tr>'
        "<th>Task</th><th>Checked</th><th>Rejected</th><th>Pass rate</th><th>By rule</th>"
        f"</tr></thead><tbody>{quality_rows}</tbody></table></div>"
        if quality_rows
        else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(str(run.get("pipeline", "pipeline")))} - run report</title>
<style>
 :root {{ color-scheme: light dark; }}
 body {{ font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        margin: 0; padding: 2rem; background: #f6f8fa; color: #1f2328; }}
 @media (prefers-color-scheme: dark) {{ body {{ background:#0d1117; color:#e6edf3; }}
   .panel, .card {{ background:#161b22 !important; border-color:#30363d !important; }}
   th {{ background:#21262d !important; }} }}
 header {{ display:flex; align-items:center; gap:1rem; margin-bottom:1.5rem; flex-wrap:wrap; }}
 h1 {{ font-size:1.4rem; margin:0; }}
 .badge {{ color:#fff; padding:.15rem .6rem; border-radius:2rem; font-size:.75rem;
           text-transform:uppercase; letter-spacing:.03em; }}
 .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr));
           gap:1rem; margin-bottom:1.5rem; }}
 .card {{ background:#fff; border:1px solid #d0d7de; border-radius:8px; padding:1rem; }}
 .card .label {{ font-size:.75rem; text-transform:uppercase; opacity:.7; }}
 .card .value {{ font-size:1.6rem; font-weight:600; margin-top:.25rem; }}
 .panel {{ background:#fff; border:1px solid #d0d7de; border-radius:8px;
           padding:1rem 1.25rem; margin-bottom:1.5rem; overflow-x:auto; }}
 table {{ border-collapse:collapse; width:100%; font-size:.9rem; }}
 th, td {{ text-align:left; padding:.5rem .6rem; border-bottom:1px solid #d0d7de; }}
 th {{ background:#f6f8fa; font-weight:600; }}
 td.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
 footer {{ font-size:.8rem; opacity:.65; margin-top:2rem; }}
</style></head><body>
<header>
  <h1>{html.escape(str(run.get("pipeline", "pipeline")))}</h1>
  <span class="badge" style="background:{colour}">{html.escape(status)}</span>
  <code>{html.escape(str(run.get("execution_id", "")))}</code>
</header>
<div class="cards">{cards}</div>
<div class="panel"><h2>Tasks</h2><table>
  <thead><tr><th>Task</th><th>Status</th><th>Seconds</th><th>In</th><th>Out</th>
  <th>Rejected</th></tr></thead><tbody>{task_body}</tbody>
</table></div>
{quality_panel}
<footer>Generated {html.escape(str(report.get("generated_at", "")))}
 by {html.escape(str(report.get("generator", APP_TITLE)))}</footer>
</body></html>"""


def _card(label: str, value: Any) -> str:
    return (
        f"<div class='card'><div class='label'>{html.escape(label)}</div>"
        f"<div class='value'>{html.escape(str(value))}</div></div>"
    )


def render_console_summary(result: PipelineResult) -> Any:
    """Build a Rich renderable summarising a run."""
    from rich.console import Group
    from rich.panel import Panel
    from rich.table import Table

    style = {
        RunStatus.SUCCESS: "green",
        RunStatus.PARTIAL: "yellow",
        RunStatus.FAILED: "red",
        RunStatus.CANCELLED: "magenta",
    }.get(result.status, "white")

    table = Table(show_header=True, header_style="bold", expand=True)
    table.add_column("Task")
    table.add_column("Status")
    table.add_column("Seconds", justify="right")
    table.add_column("In", justify="right")
    table.add_column("Out", justify="right")
    table.add_column("Rejected", justify="right")

    for task in result.tasks:
        task_style = {
            RunStatus.SUCCESS: "green",
            RunStatus.FAILED: "red",
            RunStatus.SKIPPED: "dim",
        }.get(task.status, "white")
        table.add_row(
            plain_text(task.task_name),
            f"[{task_style}]{task.status.value}[/{task_style}]",
            f"{task.duration_seconds:.2f}",
            str(task.metrics.rows_in),
            str(task.metrics.rows_out),
            str(task.metrics.rows_failed),
        )

    summary = (
        f"[bold {style}]{result.status.value.upper()}[/bold {style}]  "
        f"{result.rows_read} read → {result.rows_written} written  "
        f"({result.rows_rejected} rejected)  in {result.duration_seconds:.2f}s  "
        f"≈ {result.throughput_rows_per_second:.0f} rows/s"
    )
    if result.error is not None:
        # The error quotes source data, so it is the likeliest value to carry markup.
        summary += f"\n[red]{plain_text(html.unescape(str(result.error))[:400])}[/red]"

    return Panel(
        Group(summary, "", table),
        title=f"{plain_text(result.pipeline_name)}  ·  {plain_text(result.execution_id)}",
        border_style=style,
    )


def default_report_path(
    directory: str | Path, pipeline: str, execution_id: str, suffix: str
) -> Path:
    """Build a timestamped report filename from a pipeline name.

    The stem excludes ``.`` as well as separators: the extension is appended
    here, so a dot in the stem serves no purpose and only creates names like
    ``bad_.._name.html`` that read as traversal at a glance.
    """
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")  # noqa: DTZ005 - local filename stamp
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in pipeline)[:80]
    return Path(directory) / f"{safe or 'report'}-{stamp}-{execution_id[:8]}.{suffix}"


__all__ = [
    "build_dashboard_report",
    "build_run_report",
    "default_report_path",
    "plain_text",
    "render_console_summary",
    "write_html",
    "write_json",
]
