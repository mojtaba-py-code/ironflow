"""Framework-free domain core: types, context, errors, retry, events, registry."""

from __future__ import annotations

from ironflow.core.context import CancellationToken, ExecutionContext, new_id, utcnow
from ironflow.core.errors import IronFlowError
from ironflow.core.events import Event, EventBus, EventType
from ironflow.core.registry import ComponentRegistry
from ironflow.core.retry import RetryPolicy, call_with_retry
from ironflow.core.types import (
    DatasetSchema,
    FieldSchema,
    FieldType,
    LoadMode,
    LoadStrategy,
    OnViolation,
    Record,
    RecordBatch,
    RecordStream,
    RunStatus,
    Severity,
    StageMetrics,
    Violation,
    batched,
)

__all__ = [
    "CancellationToken",
    "ComponentRegistry",
    "DatasetSchema",
    "Event",
    "EventBus",
    "EventType",
    "ExecutionContext",
    "FieldSchema",
    "FieldType",
    "IronFlowError",
    "LoadMode",
    "LoadStrategy",
    "OnViolation",
    "Record",
    "RecordBatch",
    "RecordStream",
    "RetryPolicy",
    "RunStatus",
    "Severity",
    "StageMetrics",
    "Violation",
    "batched",
    "call_with_retry",
    "new_id",
    "utcnow",
]
