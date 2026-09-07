"""Declarative pipeline specification.

A pipeline is data, not code.  The whole specification is expressed as Pydantic
models so that:

* a malformed pipeline fails at *load* time with a precise path
  (``tasks.2.destination.mode``) rather than at 03:00 halfway through a load;
* the same model validates YAML, JSON, an API request body and a CLI override;
* the JSON Schema for editor autocompletion is generated, never hand-written.

Component-specific keys (``path``, ``dsn``, ``table`` ...) are captured as
``extra`` fields on :class:`ConnectorSpec` and friends.  This keeps the core
model closed to change while remaining open to new connectors - the connector
itself validates its own options, which is where that knowledge belongs.
"""

from __future__ import annotations

import re
from typing import Any, Literal, cast

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ironflow.core.types import LoadMode, LoadStrategy, OnViolation, Severity

NAME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9_.-]{0,63}$")
CRON_FIELD_RE = re.compile(r"^(\*|\d+|\d+-\d+|\*/\d+|(\d+,)+\d+)$")


class StrictModel(BaseModel):
    """Base for models that must reject unknown keys.

    Rejecting extras turns a typo (``retires: 3``) into a load-time error rather
    than a silently ignored setting - the failure mode that produces the "but I
    configured retries!" incident.
    """

    model_config = ConfigDict(extra="forbid", validate_assignment=True, frozen=False)


class OpenModel(BaseModel):
    """Base for models that carry component-specific options."""

    model_config = ConfigDict(extra="allow", validate_assignment=True)

    @property
    def options(self) -> dict[str, Any]:
        """The extra keys, i.e. everything the component itself interprets."""
        return dict(self.__pydantic_extra__ or {})


# --------------------------------------------------------------------------- #
# Reusable fragments
# --------------------------------------------------------------------------- #
class RetrySpec(StrictModel):
    """Retry behaviour for a task or connector."""

    max_attempts: int = Field(default=3, ge=1, le=20)
    initial_delay: float = Field(default=1.0, ge=0.0, le=600.0)
    max_delay: float = Field(default=60.0, ge=0.0, le=3600.0)
    multiplier: float = Field(default=2.0, ge=1.0, le=10.0)
    jitter: bool = True

    @model_validator(mode="after")
    def _check_delays(self) -> RetrySpec:
        if self.max_delay < self.initial_delay:
            raise ValueError("max_delay must be >= initial_delay")
        return self


class ConnectorSpec(OpenModel):
    """A source or destination declaration."""

    type: str = Field(description="Registered connector type, e.g. 'csv' or 'postgres'.")
    name: str | None = None
    mode: LoadMode = LoadMode.APPEND
    batch_size: int | None = Field(default=None, ge=1, le=1_000_000)
    retry: RetrySpec | None = None

    @field_validator("type")
    @classmethod
    def _normalise_type(cls, value: str) -> str:
        normalised = value.strip().lower().replace("-", "_")
        if not normalised:
            raise ValueError("connector type must not be empty")
        return normalised

    @property
    def label(self) -> str:
        return self.name or self.type


class ValidationRuleSpec(OpenModel):
    """One data-quality rule."""

    type: str
    field: str | None = None
    severity: Severity = Severity.ERROR
    message: str | None = None

    @field_validator("type")
    @classmethod
    def _normalise_type(cls, value: str) -> str:
        return value.strip().lower().replace("-", "_")


class ValidationSpec(StrictModel):
    """The data-quality contract applied to a task."""

    enabled: bool = True
    on_violation: OnViolation = OnViolation.QUARANTINE
    stage: Literal["pre_transform", "post_transform"] = "post_transform"
    """When to validate.

    ``post_transform`` (the default) runs the rules after transformations, so a
    ``type: integer`` rule sees the value produced by the ``cast`` step rather
    than the raw string a CSV reader returned.  ``pre_transform`` validates the
    source as delivered, which is what you want when the contract being enforced
    is with the *upstream system* rather than with the destination.
    """

    rules: list[ValidationRuleSpec] = Field(default_factory=list)
    max_error_rate: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Abort the task when the share of rejected rows exceeds this.",
    )
    max_errors: int | None = Field(
        default=None, ge=0, description="Absolute cap on rejected rows before aborting."
    )
    schema_: dict[str, Any] | None = Field(default=None, alias="schema")
    """Optional declarative column contract: ``{column: {type, nullable, ...}}``."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class TransformSpec(OpenModel):
    """One transformation step."""

    type: str
    name: str | None = None
    enabled: bool = True

    @field_validator("type")
    @classmethod
    def _normalise_type(cls, value: str) -> str:
        return value.strip().lower().replace("-", "_")


class IncrementalSpec(StrictModel):
    """Watermark configuration for incremental / CDC extraction."""

    column: str = Field(description="Monotonic column used as the watermark.")
    initial_value: Any = None
    overlap: float = Field(
        default=0.0,
        ge=0.0,
        description=(
            "Seconds of overlap re-read on each run. Guards against rows committed "
            "with a timestamp slightly earlier than the previous high-water mark."
        ),
    )
    key_columns: list[str] = Field(
        default_factory=list,
        description="Business key used to deduplicate rows re-read due to overlap.",
    )

    @field_validator("column")
    @classmethod
    def _validate_column(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("incremental column must not be empty")
        return value.strip()


class SchemaEvolutionSpec(StrictModel):
    """Policy applied when the observed schema differs from the last run."""

    enabled: bool = True
    mode: Literal["strict", "additive", "permissive"] = "additive"
    """``strict`` fails on any drift, ``additive`` allows new columns only,
    ``permissive`` logs everything and continues."""
    fail_on_removed_columns: bool = True
    fail_on_type_change: bool = True


class TaskSpec(StrictModel):
    """A single unit of work inside a pipeline."""

    name: str
    type: Literal["etl", "sql", "noop"] = "etl"
    description: str = ""
    enabled: bool = True
    depends_on: list[str] = Field(default_factory=list)
    condition: str | None = Field(
        default=None,
        description="Safe boolean expression over params/state gating this task.",
    )
    source: ConnectorSpec | None = None
    destination: ConnectorSpec | None = None
    reject_destination: ConnectorSpec | None = None
    transformations: list[TransformSpec] = Field(default_factory=list)
    validation: ValidationSpec | None = None
    strategy: LoadStrategy = LoadStrategy.FULL
    incremental: IncrementalSpec | None = None
    schema_evolution: SchemaEvolutionSpec = Field(default_factory=SchemaEvolutionSpec)
    batch_size: int | None = Field(default=None, ge=1, le=1_000_000)
    retry: RetrySpec | None = None
    timeout: float | None = Field(default=None, gt=0, le=86_400)
    on_failure: Literal["fail", "continue"] = "fail"
    checkpoint: bool = True
    parallelism: int = Field(default=1, ge=1, le=64)
    sql: str | None = Field(default=None, description="Statement for ``type: sql`` tasks.")
    tags: list[str] = Field(default_factory=list)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if not NAME_RE.match(value):
            raise ValueError(
                "task name must start with a letter and contain only letters, "
                "digits, '_', '.' or '-'"
            )
        return value

    @model_validator(mode="after")
    def _check_shape(self) -> TaskSpec:
        if self.type == "etl":
            if self.source is None:
                raise ValueError("etl tasks require a 'source'")
            if self.destination is None:
                raise ValueError("etl tasks require a 'destination'")
        if self.type == "sql" and not self.sql:
            raise ValueError("sql tasks require a 'sql' statement")
        if self.strategy in (LoadStrategy.INCREMENTAL, LoadStrategy.CDC) and not self.incremental:
            raise ValueError(f"strategy '{self.strategy.value}' requires an 'incremental' block")
        if self.name in self.depends_on:
            raise ValueError("a task cannot depend on itself")
        if len(set(self.depends_on)) != len(self.depends_on):
            raise ValueError("duplicate entries in depends_on")
        return self


class NotificationSpec(StrictModel):
    """Where to send run outcomes."""

    type: Literal["email", "slack", "webhook", "console"]
    on: list[Literal["started", "success", "failed", "partial"]] = Field(
        default_factory=lambda: cast(
            "list[Literal['started', 'success', 'failed', 'partial']]", ["failed"]
        )
    )
    target: str | None = None
    """Webhook URL, ``mailto:`` recipient list, or channel - resolved as a secret."""
    enabled: bool = True
    options: dict[str, Any] = Field(default_factory=dict)


class ScheduleSpec(StrictModel):
    """When a pipeline should run unattended."""

    cron: str | None = None
    interval_seconds: int | None = Field(default=None, ge=1)
    timezone: str = "UTC"
    enabled: bool = True
    catchup: bool = False
    max_concurrent_runs: int = Field(default=1, ge=1, le=16)

    @model_validator(mode="after")
    def _one_of(self) -> ScheduleSpec:
        if bool(self.cron) == bool(self.interval_seconds):
            raise ValueError("specify exactly one of 'cron' or 'interval_seconds'")
        if self.cron:
            validate_cron(self.cron)
        return self


def validate_cron(expression: str) -> str:
    """Validate a 5-field cron expression (minute hour dom month dow)."""
    fields = expression.split()
    if len(fields) != 5:
        raise ValueError("cron expression must have 5 fields: 'm h dom mon dow'")
    for index, field_value in enumerate(fields):
        if not CRON_FIELD_RE.match(field_value):
            raise ValueError(f"invalid cron field {index} ({field_value!r})")
    return expression


class PipelineSpec(StrictModel):
    """The complete, validated definition of a pipeline."""

    name: str
    version: str = "1"
    description: str = ""
    owner: str = ""
    enabled: bool = True
    tasks: list[TaskSpec] = Field(min_length=1)
    schedule: ScheduleSpec | None = None
    notifications: list[NotificationSpec] = Field(default_factory=list)
    variables: dict[str, Any] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)
    defaults: dict[str, Any] = Field(default_factory=dict)
    max_parallel_tasks: int = Field(default=4, ge=1, le=64)
    tags: list[str] = Field(default_factory=list)
    source_file: str | None = Field(default=None, exclude=True)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        if not NAME_RE.match(value):
            raise ValueError(
                "pipeline name must start with a letter and contain only letters, "
                "digits, '_', '.' or '-'"
            )
        return value

    @model_validator(mode="after")
    def _validate_graph(self) -> PipelineSpec:
        names = [t.name for t in self.tasks]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise ValueError(f"duplicate task names: {sorted(duplicates)}")
        known = set(names)
        for task in self.tasks:
            missing = [d for d in task.depends_on if d not in known]
            if missing:
                raise ValueError(f"task {task.name!r} depends on unknown task(s): {missing}")
        return self

    # -- convenience ------------------------------------------------------- #
    def task(self, name: str) -> TaskSpec:
        for candidate in self.tasks:
            if candidate.name == name:
                return candidate
        raise KeyError(name)

    @property
    def enabled_tasks(self) -> list[TaskSpec]:
        return [t for t in self.tasks if t.enabled]

    @property
    def task_names(self) -> list[str]:
        return [t.name for t in self.tasks]

    def with_defaults_applied(self) -> PipelineSpec:
        """Push pipeline-level ``defaults`` into tasks that did not override them.

        Applied once at load time so the runtime never has to look in two places
        for a value.
        """
        if not self.defaults:
            return self
        updated = self.model_copy(deep=True)
        default_batch = updated.defaults.get("batch_size")
        default_retry = updated.defaults.get("retry")
        for task in updated.tasks:
            if task.batch_size is None and default_batch:
                task.batch_size = int(default_batch)
            if task.retry is None and default_retry:
                task.retry = RetrySpec.model_validate(default_retry)
        return updated

    @classmethod
    def json_schema(cls) -> dict[str, Any]:
        """JSON Schema for editor autocompletion and ``ironflow config schema``."""
        return cls.model_json_schema(by_alias=True)


__all__ = [
    "ConnectorSpec",
    "IncrementalSpec",
    "NotificationSpec",
    "PipelineSpec",
    "RetrySpec",
    "ScheduleSpec",
    "SchemaEvolutionSpec",
    "TaskSpec",
    "TransformSpec",
    "ValidationRuleSpec",
    "ValidationSpec",
    "validate_cron",
]
