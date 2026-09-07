"""Structured logging with correlation ids, rotation and automatic redaction.

Design
------
Built on the standard library rather than a logging framework, because every
library IronFlow depends on already logs through ``logging``; adding a second
framework only means two places to configure and one of them silently dropping
records.

Three pieces are layered onto ``logging``:

``ContextFilter``
    Stamps ``correlation_id``/``execution_id``/``pipeline_id``/``task_id`` onto
    every record from the context vars, so a log line emitted deep inside a
    connector is still attributable to a run.
``RedactionFilter``
    Last line of defence: scrubs secret-looking keys from ``record.__dict__``
    extras and rewrites credentials embedded in URLs inside the message.  Even
    if a developer logs a DSN, the password does not reach disk.
``JsonFormatter``
    One JSON object per line for the log shipper, with the console handler
    keeping a human-readable format.

Log files rotate by size with a bounded backup count so a runaway pipeline
cannot fill the disk and take the host down with it.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import sys
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from ironflow.core.context import current_log_context
from ironflow.security.masking import REDACTED, is_sensitive_key, redact_url

#: Attributes ``logging`` puts on every record; anything else is a user extra.
_RESERVED = frozenset(
    {
        "args",
        "asctime",
        "created",
        "exc_info",
        "exc_text",
        "filename",
        "funcName",
        "levelname",
        "levelno",
        "lineno",
        "module",
        "msecs",
        "message",
        "msg",
        "name",
        "pathname",
        "process",
        "processName",
        "relativeCreated",
        "stack_info",
        "thread",
        "threadName",
        "taskName",
    }
)

CONSOLE_FORMAT = "%(asctime)s %(levelname)-8s [%(correlation_id)s] %(name)s: %(message)s"


class ContextFilter(logging.Filter):
    """Inject run identity into every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in current_log_context().items():
            if not hasattr(record, key):
                setattr(record, key, value)
        return True


class RedactionFilter(logging.Filter):
    """Scrub secrets from record extras and from the formatted message."""

    def filter(self, record: logging.LogRecord) -> bool:
        for key, value in list(record.__dict__.items()):
            if key in _RESERVED:
                continue
            if is_sensitive_key(key):
                record.__dict__[key] = REDACTED
            elif isinstance(value, Mapping):
                record.__dict__[key] = _redact_shallow(value)
            elif isinstance(value, str) and "://" in value:
                record.__dict__[key] = redact_url(value)

        if isinstance(record.msg, str) and "://" in record.msg:
            record.msg = redact_url(record.msg)
        return True


def _redact_shallow(mapping: Mapping[str, Any]) -> dict[str, Any]:
    from ironflow.security.masking import redact_mapping

    return redact_mapping(mapping)


class JsonFormatter(logging.Formatter):
    """Render records as single-line JSON for ingestion."""

    def __init__(self, *, service: str = "ironflow", environment: str = "local") -> None:
        super().__init__()
        self.service = service
        self.environment = environment

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
            + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "service": self.service,
            "environment": self.environment,
            "module": record.module,
            "line": record.lineno,
            "thread": record.threadName,
        }
        for key in ("correlation_id", "execution_id", "pipeline_id", "task_id"):
            value = getattr(record, key, None)
            if value and value != "-":
                payload[key] = value

        extras = {
            k: v for k, v in record.__dict__.items() if k not in _RESERVED and not k.startswith("_")
        }
        for key in ("correlation_id", "execution_id", "pipeline_id", "task_id"):
            extras.pop(key, None)
        if extras:
            payload["extra"] = _json_safe(extras)

        if record.exc_info:
            payload["exception"] = {
                "type": record.exc_info[0].__name__ if record.exc_info[0] else None,
                "message": str(record.exc_info[1]),
                "stacktrace": self.formatException(record.exc_info),
            }
        if record.stack_info:
            payload["stack"] = self.formatStack(record.stack_info)

        return json.dumps(payload, ensure_ascii=False, default=str)


def _json_safe(value: Any) -> Any:
    """Coerce arbitrary extras into something ``json.dumps`` accepts."""
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, Mapping):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_safe(v) for v in value]
    return str(value)


def configure_logging(
    *,
    level: str | int = "INFO",
    json_output: bool = False,
    log_file: str | Path | None = None,
    max_bytes: int = 50 * 1024 * 1024,
    backup_count: int = 5,
    service: str = "ironflow",
    environment: str = "local",
    quiet_libraries: bool = True,
) -> logging.Logger:
    """Configure the root logger.  Idempotent - safe to call from tests."""
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
        handler.close()

    numeric = logging.getLevelName(level) if isinstance(level, str) else level
    if not isinstance(numeric, int):  # pragma: no cover - bad level name
        numeric = logging.INFO
    root.setLevel(numeric)

    context_filter = ContextFilter()
    redaction_filter = RedactionFilter()

    console = logging.StreamHandler(stream=sys.stderr)
    console.setLevel(numeric)
    console.addFilter(context_filter)
    console.addFilter(redaction_filter)
    console.setFormatter(
        JsonFormatter(service=service, environment=environment)
        if json_output
        else logging.Formatter(CONSOLE_FORMAT, datefmt="%Y-%m-%d %H:%M:%S")
    )
    root.addHandler(console)

    if log_file:
        path = Path(log_file).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8"
        )
        file_handler.setLevel(numeric)
        file_handler.addFilter(context_filter)
        file_handler.addFilter(redaction_filter)
        # File output is always JSON: it is machine-consumed by definition.
        file_handler.setFormatter(JsonFormatter(service=service, environment=environment))
        root.addHandler(file_handler)

    if quiet_libraries:
        for noisy in ("urllib3", "httpx", "httpcore", "paramiko", "asyncio", "sqlalchemy.engine"):
            logging.getLogger(noisy).setLevel(max(numeric, logging.WARNING))

    return root


def get_logger(name: str) -> logging.LoggerAdapter[logging.Logger] | logging.Logger:
    """Module-level logger accessor (keeps import sites uniform)."""
    return logging.getLogger(name)


__all__ = [
    "ContextFilter",
    "JsonFormatter",
    "RedactionFilter",
    "configure_logging",
    "get_logger",
]
