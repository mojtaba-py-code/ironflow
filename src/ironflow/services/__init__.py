"""Application services: the facade, notifications and reporting."""

from __future__ import annotations

from ironflow.services.notifications import NotificationService, Notifier, build_notifier
from ironflow.services.pipeline_service import PipelineService
from ironflow.services.reporting import (
    build_dashboard_report,
    build_run_report,
    render_console_summary,
    write_html,
    write_json,
)

__all__ = [
    "NotificationService",
    "Notifier",
    "PipelineService",
    "build_dashboard_report",
    "build_notifier",
    "build_run_report",
    "render_console_summary",
    "write_html",
    "write_json",
]
