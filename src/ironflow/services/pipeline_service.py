"""Application service - the single facade the CLI and the API both use.

Everything a caller needs to do with a pipeline goes through here: discover it,
validate it, run it, retry it, inspect its history.  Concentrating that in one
class means the authorisation check, the audit entry and the notification wiring
happen exactly once instead of being duplicated (and eventually forgotten) in
each delivery mechanism.

Composition root: this is where settings, the database, the repositories, the
event bus and the notification channels are assembled.  Nothing below this layer
constructs its own dependencies, which is what keeps the lower layers testable.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from ironflow.config.loader import PipelineRepository, load_pipeline
from ironflow.config.models import PipelineSpec
from ironflow.config.settings import Settings, get_settings
from ironflow.connectors.factory import ConnectorFactory
from ironflow.core.errors import ConfigurationError, IronFlowError
from ironflow.core.events import EventBus
from ironflow.core.types import RunStatus
from ironflow.observability.audit import AuditLog
from ironflow.observability.metrics import METRICS, MetricsRegistry
from ironflow.orchestration.dag import TaskGraph
from ironflow.orchestration.scheduler import Scheduler
from ironflow.pipeline.results import PipelineResult
from ironflow.pipeline.runner import PipelineRunner
from ironflow.repositories.database import Database, get_database
from ironflow.repositories.repositories import (
    CheckpointRepository,
    RunRepository,
    SchemaRepository,
    WatermarkRepository,
)
from ironflow.security.rbac import AccessControl, Permission, Principal
from ironflow.services.notifications import NotificationService

logger = logging.getLogger(__name__)


class PipelineService:
    """High-level operations on pipelines."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        database: Database | None = None,
        events: EventBus | None = None,
        metrics: MetricsRegistry | None = None,
        pipelines_dir: str | Path | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.settings.ensure_directories()

        self.db = database or get_database(self.settings)
        self.events = events or EventBus()
        self.metrics = metrics or METRICS

        self.runs = RunRepository(self.db)
        self.watermarks = WatermarkRepository(self.db)
        self.checkpoints = CheckpointRepository(self.db)
        self.schemas = SchemaRepository(self.db)

        self.audit = AuditLog(self.settings.audit_file, enabled=self.settings.audit_enabled)
        self.access = AccessControl(enabled=self.settings.auth_enabled)
        self.factory = ConnectorFactory(self.settings)
        self.repository = PipelineRepository(
            pipelines_dir or self.settings.pipelines_dir,
            roots=self._config_roots(pipelines_dir),
        )

    def _config_roots(self, pipelines_dir: str | Path | None) -> tuple[Path, ...]:
        """Directories a pipeline file may be loaded from.

        Confining this stops ``--file ../../../etc/shadow`` from being read by a
        server-side API call.  The CLI passes an explicit directory when the
        operator points at a file elsewhere.
        """
        directory = Path(pipelines_dir or self.settings.pipelines_dir).expanduser()
        roots = [directory.resolve()] if directory.exists() else []
        roots.extend(Path(r).expanduser().resolve() for r in self.settings.data_roots)
        return tuple(roots)

    # -- discovery --------------------------------------------------------- #
    def list_pipelines(self, *, profile: str | None = None) -> list[PipelineSpec]:
        return self.repository.load_all(profile=profile)

    def get_pipeline(self, name: str, *, profile: str | None = None) -> PipelineSpec:
        return self.repository.get(name, profile=profile)

    def load_file(
        self,
        path: str | Path,
        *,
        profile: str | None = None,
        overrides: dict[str, Any] | None = None,
        variables: dict[str, Any] | None = None,
    ) -> PipelineSpec:
        """Load a pipeline from an explicit path (CLI ``--file``)."""
        target = Path(path).expanduser().resolve()
        roots = (*self._config_roots(None), target.parent)
        return load_pipeline(
            target, profile=profile, overrides=overrides, variables=variables, roots=roots
        )

    # -- validation -------------------------------------------------------- #
    def validate(self, pipeline: PipelineSpec) -> dict[str, Any]:
        """Static checks that need no credentials for the target systems."""
        problems: list[str] = []
        warnings: list[str] = []

        try:
            graph = TaskGraph.from_spec(pipeline)
            structure = graph.describe()
        except IronFlowError as exc:
            return {
                "pipeline": pipeline.name,
                "valid": False,
                "problems": [str(exc)],
                "warnings": [],
            }

        for task in pipeline.tasks:
            if task.source is not None:
                problems.extend(
                    f"task {task.name!r} source: {p}"
                    for p in self.factory.validate(task.source, kind="source")
                )
            if task.destination is not None:
                problems.extend(
                    f"task {task.name!r} destination: {p}"
                    for p in self.factory.validate(task.destination, kind="sink")
                )
                warnings.extend(self._destination_warnings(task))

            if (
                task.validation
                and task.validation.on_violation.value == "quarantine"
                and task.reject_destination is None
            ):
                warnings.append(
                    f"task {task.name!r} quarantines invalid records but has no "
                    "'reject_destination'; rejected rows will only be counted, not stored"
                )
            for transform in task.transformations:
                try:
                    from ironflow.transformation.base import build_transformation

                    build_transformation(transform)
                except IronFlowError as exc:
                    problems.append(f"task {task.name!r} transformation: {exc}")
            if task.validation:
                try:
                    from ironflow.validation.engine import ValidationEngine

                    ValidationEngine(task.validation, task_name=task.name)
                except IronFlowError as exc:
                    problems.append(f"task {task.name!r} validation: {exc}")

        if pipeline.schedule and not pipeline.notifications:
            warnings.append(
                "this pipeline runs on a schedule but defines no notifications; "
                "a failure at 03:00 will go unnoticed until someone looks"
            )

        return {
            "pipeline": pipeline.name,
            "valid": not problems,
            "problems": problems,
            "warnings": warnings,
            "structure": structure,
        }

    def _destination_warnings(self, task: Any) -> list[str]:
        warnings: list[str] = []
        try:
            sink = self.factory.create_sink(task.destination, context=task.name)
        except IronFlowError:
            return warnings
        if not sink.transactional:
            warnings.append(
                f"task {task.name!r} writes to a non-transactional destination "
                f"({task.destination.type}); a mid-run failure can leave partial data"
            )
        return warnings

    # -- execution --------------------------------------------------------- #
    def run(
        self,
        pipeline: PipelineSpec,
        *,
        parameters: dict[str, Any] | None = None,
        dry_run: bool = False,
        only: list[str] | None = None,
        resume_execution_id: str | None = None,
        principal: Principal | None = None,
        trigger: str = "manual",
        install_signal_handlers: bool = True,
    ) -> PipelineResult:
        """Authorise, wire notifications and execute the pipeline."""
        self.access.authorize(
            principal or Principal.system(), Permission.PIPELINE_RUN, pipeline=pipeline.name
        )

        notifications = NotificationService(pipeline.notifications, self.settings)
        notifications.attach(self.events)
        runner = self._build_runner()
        try:
            return runner.run(
                pipeline,
                parameters=parameters,
                dry_run=dry_run,
                only=only,
                resume_execution_id=resume_execution_id,
                principal=principal,
                trigger=trigger,
                install_signal_handlers=install_signal_handlers,
            )
        finally:
            notifications.detach()

    def _build_runner(self) -> PipelineRunner:
        return PipelineRunner(
            settings=self.settings,
            factory=self.factory,
            runs=self.runs,
            watermarks=self.watermarks,
            checkpoints=self.checkpoints,
            schemas=self.schemas,
            events=self.events,
            metrics=self.metrics,
            audit=self.audit,
        )

    def retry(
        self,
        pipeline_name: str,
        *,
        execution_id: str | None = None,
        principal: Principal | None = None,
        profile: str | None = None,
    ) -> PipelineResult:
        """Re-run a failed execution from the beginning."""
        self.access.authorize(
            principal or Principal.system(), Permission.RUN_RETRY, pipeline=pipeline_name
        )
        run = (
            self.runs.get_run(execution_id)
            if execution_id
            else self.runs.last_failed_run(pipeline_name)
        )
        if run is None:
            raise ConfigurationError(
                "no failed run found to retry", context={"pipeline": pipeline_name}
            )
        pipeline = self.get_pipeline(pipeline_name, profile=profile)
        logger.info("retrying %s (previous execution %s)", pipeline_name, run["execution_id"])
        return self.run(pipeline, principal=principal, trigger="retry")

    def resume(
        self,
        pipeline_name: str,
        execution_id: str,
        *,
        principal: Principal | None = None,
        profile: str | None = None,
    ) -> PipelineResult:
        """Continue a failed execution, skipping tasks that already succeeded."""
        self.access.authorize(
            principal or Principal.system(), Permission.RUN_RETRY, pipeline=pipeline_name
        )
        completed = self.checkpoints.completed_tasks(execution_id)
        if not completed:
            logger.warning(
                "no checkpoints for %s; resume will behave like a full retry", execution_id
            )
        pipeline = self.get_pipeline(pipeline_name, profile=profile)
        return self.run(
            pipeline,
            resume_execution_id=execution_id,
            principal=principal,
            trigger="resume",
        )

    # -- history ----------------------------------------------------------- #
    def history(
        self,
        *,
        pipeline_name: str | None = None,
        status: RunStatus | None = None,
        limit: int = 20,
        principal: Principal | None = None,
    ) -> list[dict[str, Any]]:
        self.access.authorize(
            principal or Principal.system(), Permission.RUN_HISTORY_READ, pipeline=pipeline_name
        )
        return self.runs.list_runs(pipeline_name=pipeline_name, status=status, limit=limit)

    def run_details(self, execution_id: str) -> dict[str, Any] | None:
        return self.runs.get_run(execution_id)

    def status(self, pipeline_name: str) -> dict[str, Any]:
        """Current state of a pipeline: last run plus its 30-day statistics."""
        latest = self.runs.latest_run(pipeline_name)
        return {
            "pipeline": pipeline_name,
            "last_run": latest,
            "running": self.runs.running_count(pipeline_name),
            "statistics": self.runs.statistics(pipeline_name),
            "watermarks": self.watermarks.list(pipeline_name),
        }

    def statistics(self, pipeline_name: str | None = None, *, days: int = 30) -> dict[str, Any]:
        return self.runs.statistics(pipeline_name, days=days)

    # -- maintenance ------------------------------------------------------- #
    def clean(
        self,
        *,
        history_days: int = 90,
        checkpoint_days: int = 30,
        reset_watermarks: str | None = None,
        reset_schemas: str | None = None,
        principal: Principal | None = None,
    ) -> dict[str, int]:
        """Purge old state.  Returns what was removed."""
        self.access.authorize(principal or Principal.system(), Permission.PIPELINE_DELETE)
        removed = {
            "runs_purged": self.runs.purge(older_than_days=history_days),
            "checkpoints_purged": self.checkpoints.purge(older_than_days=checkpoint_days),
            "watermarks_reset": (
                self.watermarks.reset(reset_watermarks) if reset_watermarks else 0
            ),
            "schemas_reset": (self.schemas.reset(reset_schemas) if reset_schemas else 0),
        }
        self.audit.record(
            "state.clean",
            actor=(principal.subject if principal else "system"),
            **{k: str(v) for k, v in removed.items()},
        )
        return removed

    def build_scheduler(self, *, poll_interval: float = 30.0) -> Scheduler:
        """Scheduler wired to this service's run history for overlap checks."""
        scheduler = Scheduler(
            trigger=lambda spec: self.run(spec, trigger="schedule", install_signal_handlers=False),
            poll_interval=poll_interval,
            running_count=self.runs.running_count,
        )
        scheduler.register_all(self.list_pipelines())
        return scheduler

    def healthcheck(self) -> dict[str, Any]:
        """Liveness/readiness summary for the API and ``ironflow config check``."""
        return {
            "database": self.db.healthcheck(),
            "pipelines_dir": str(self.repository.directory),
            "pipelines_discovered": len(self.repository.discover()),
            "environment": self.settings.environment,
            "production_problems": self.settings.validate_production_hardening(),
        }


__all__ = ["PipelineService"]
