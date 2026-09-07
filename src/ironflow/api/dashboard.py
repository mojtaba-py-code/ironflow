"""Server-rendered monitoring dashboard.

Plain HTML with inline CSS and no JavaScript framework.  A monitoring page that
needs a build step is a page that stops working the day the build breaks, and an
operator debugging a 3am failure should not be waiting on a bundle.

Every interpolated value is escaped: run data contains error messages that
contain source data, so the page is an XSS sink otherwise.
"""

from __future__ import annotations

import html
from typing import Any

from ironflow.core.context import utcnow
from ironflow.version import APP_TITLE, __version__

_STATUS_COLOURS = {
    "success": "#1a7f37",
    "partial": "#9a6700",
    "failed": "#cf222e",
    "running": "#0969da",
    "cancelled": "#8250df",
    "skipped": "#57606a",
}


def render_dashboard(
    *,
    statistics: dict[str, Any],
    timeline: list[dict[str, Any]],
    pipelines: list[dict[str, Any]],
) -> str:
    """Render the dashboard page."""
    cards = "".join(
        _card(label, value, suffix)
        for label, value, suffix in (
            ("Runs (30d)", statistics.get("runs_total", 0), ""),
            ("Success rate", round(statistics.get("success_rate", 0) * 100, 1), "%"),
            ("Failures", statistics.get("runs_failed", 0), ""),
            ("Rows written", f"{statistics.get('rows_written', 0):,}", ""),
            ("Rows rejected", f"{statistics.get('rows_rejected', 0):,}", ""),
            ("Avg duration", statistics.get("avg_duration_seconds", 0), "s"),
            ("p95 duration", statistics.get("p95_duration_seconds", 0), "s"),
        )
    )

    pipeline_rows = (
        "".join(
            f"<tr><td><strong>{html.escape(str(p.get('name', '')))}</strong></td>"
            f"<td>{html.escape(str(p.get('version', '')))}</td>"
            f"<td class='num'>{html.escape(str(p.get('tasks', 0)))}</td>"
            f"<td>{html.escape(str(p.get('owner', '') or '-'))}</td></tr>"
            for p in pipelines
        )
        or "<tr><td colspan='4'>No pipelines discovered.</td></tr>"
    )

    max_duration = max((float(r.get("duration_seconds", 0)) for r in timeline), default=1.0) or 1.0
    timeline_rows = (
        "".join(_timeline_row(run, max_duration) for run in timeline)
        or "<tr><td colspan='5'>No runs recorded yet.</td></tr>"
    )

    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="30">
<title>{html.escape(APP_TITLE)} dashboard</title>
<style>
 :root {{ color-scheme: light dark; }}
 * {{ box-sizing: border-box; }}
 body {{ font-family:-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
        margin:0; padding:2rem; background:#f6f8fa; color:#1f2328; }}
 @media (prefers-color-scheme: dark) {{
   body {{ background:#0d1117; color:#e6edf3; }}
   .panel,.card {{ background:#161b22 !important; border-color:#30363d !important; }}
   th {{ background:#21262d !important; }} }}
 header {{ display:flex; justify-content:space-between; align-items:baseline;
           flex-wrap:wrap; gap:1rem; margin-bottom:1.5rem; }}
 h1 {{ font-size:1.35rem; margin:0; }}
 h2 {{ font-size:1rem; margin:0 0 .75rem; text-transform:uppercase;
       letter-spacing:.04em; opacity:.7; }}
 .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
           gap:1rem; margin-bottom:1.5rem; }}
 .card {{ background:#fff; border:1px solid #d0d7de; border-radius:8px; padding:1rem; }}
 .card .label {{ font-size:.72rem; text-transform:uppercase; opacity:.65; }}
 .card .value {{ font-size:1.5rem; font-weight:600; margin-top:.2rem;
                 font-variant-numeric:tabular-nums; }}
 .panel {{ background:#fff; border:1px solid #d0d7de; border-radius:8px;
           padding:1rem 1.25rem; margin-bottom:1.5rem; overflow-x:auto; }}
 table {{ border-collapse:collapse; width:100%; font-size:.88rem; }}
 th,td {{ text-align:left; padding:.45rem .6rem; border-bottom:1px solid #d0d7de;
          white-space:nowrap; }}
 th {{ background:#f6f8fa; font-weight:600; }}
 td.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
 .badge {{ color:#fff; padding:.1rem .5rem; border-radius:2rem; font-size:.7rem;
           text-transform:uppercase; }}
 .bar {{ height:8px; border-radius:4px; background:#0969da; min-width:2px; }}
 footer {{ font-size:.78rem; opacity:.6; }}
</style></head><body>
<header>
  <h1>{html.escape(APP_TITLE)} <span style="opacity:.5;font-weight:400">
    {html.escape(__version__)}</span></h1>
  <span style="font-size:.8rem;opacity:.6">refreshes every 30s ·
    {html.escape(utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))}</span>
</header>

<div class="cards">{cards}</div>

<div class="panel"><h2>Recent runs</h2><table>
  <thead><tr><th>Started</th><th>Pipeline</th><th>Status</th>
  <th>Duration</th><th>Rows</th></tr></thead>
  <tbody>{timeline_rows}</tbody></table></div>

<div class="panel"><h2>Pipelines</h2><table>
  <thead><tr><th>Name</th><th>Version</th><th>Tasks</th><th>Owner</th></tr></thead>
  <tbody>{pipeline_rows}</tbody></table></div>

<footer>{html.escape(APP_TITLE)} · <a href="/health">health</a> ·
 <a href="/metrics">metrics</a> · <a href="/docs">API docs</a></footer>
</body></html>"""


def _card(label: str, value: Any, suffix: str = "") -> str:
    return (
        f"<div class='card'><div class='label'>{html.escape(label)}</div>"
        f"<div class='value'>{html.escape(str(value))}{html.escape(suffix)}</div></div>"
    )


def _timeline_row(run: dict[str, Any], max_duration: float) -> str:
    status = str(run.get("status", "unknown"))
    colour = _STATUS_COLOURS.get(status, "#57606a")
    duration = float(run.get("duration_seconds", 0))
    width = max(2, int(duration / max_duration * 100))
    # Formatted outside the f-string: reusing the outer quote character inside an
    # f-string is only legal on Python 3.12+, and this package supports 3.11.
    rows_written = html.escape(f"{int(run.get('rows_written', 0)):,}")
    started_at = html.escape(str(run.get("started_at", ""))[:19])
    pipeline = html.escape(str(run.get("pipeline", "")))
    return (
        f"<tr><td>{started_at}</td>"
        f"<td><strong>{pipeline}</strong></td>"
        f"<td><span class='badge' style='background:{colour}'>{html.escape(status)}</span></td>"
        f"<td><div style='display:flex;align-items:center;gap:.5rem'>"
        f"<div class='bar' style='width:{width}%;background:{colour}'></div>"
        f"<span>{duration:.2f}s</span></div></td>"
        f"<td class='num'>{rows_written}</td></tr>"
    )


__all__ = ["render_dashboard"]
