"""REST API and monitoring dashboard (optional ``api`` extra).

Security posture
----------------
* **Authentication** is JWT bearer, verified by
  :func:`ironflow.security.rbac.verify_token` (algorithm allow-listed, signature
  compared in constant time, ``exp``/``nbf``/``iss``/``aud`` enforced).  It can
  be disabled for local development but :func:`create_app` refuses to start
  unauthenticated in a production environment.
* **Authorisation** is per-endpoint: reading history needs ``run:read``,
  triggering a run needs ``pipeline:run``, and pipeline-name scoping is applied
  on top - to *every* read, including the ones that do not name a pipeline.
  The run list, a run looked up by id, the statistics and the dashboard all
  used to answer a principal scoped to ``sales_*`` with ``hr_*`` data; they now
  filter through :meth:`PipelineService.visible_pipelines`, and a run outside
  the caller's scope is a 404, not a 403 that would confirm the id exists.
* **The dashboard** is a route like any other: with authentication on it
  needs a token.  It used to render every pipeline and the run timeline to
  anyone who asked.
* **CORS** defaults to no origins, and never runs in credentials mode: the API
  authenticates with a bearer header, which no cross-origin page can attach
  on the operator's behalf, so there is nothing for credentials mode to carry.
* **Run triggering is asynchronous** via a background task, and the response
  returns the execution id.  A synchronous multi-hour ETL run over HTTP would
  hit every proxy timeout in the path.
* **Errors** are mapped to status codes without leaking internals: the client
  gets a code and a message, the stack trace goes to the log.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

from ironflow.config.settings import Settings, get_settings
from ironflow.core.errors import ConfigurationError, IronFlowError, SecurityError
from ironflow.core.types import RunStatus
from ironflow.observability.metrics import METRICS
from ironflow.security.rbac import Permission, Principal, principal_from_claims, verify_token
from ironflow.services.pipeline_service import PipelineService
from ironflow.version import APP_TITLE, __version__

logger = logging.getLogger(__name__)

_bearer = HTTPBearer(auto_error=False)


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class RunRequest(BaseModel):
    """Body of ``POST /api/pipelines/{name}/runs``."""

    parameters: dict[str, Any] = Field(default_factory=dict)
    dry_run: bool = False
    only: list[str] = Field(default_factory=list)
    profile: str | None = None


class RunAccepted(BaseModel):
    execution_id: str
    pipeline: str
    status: str
    dry_run: bool


class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    database: bool
    pipelines: int
    problems: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# Application factory
# --------------------------------------------------------------------------- #
def create_app(settings: Settings | None = None, service: PipelineService | None = None) -> FastAPI:
    """Build the FastAPI application."""
    resolved = settings or get_settings()
    if resolved.is_production:
        # Fail closed: a production deployment must be hardened before it serves.
        resolved.assert_production_hardening()

    api = FastAPI(
        title=f"{APP_TITLE} API",
        version=__version__,
        description="Trigger, monitor and inspect ETL pipelines.",
        docs_url="/docs" if not resolved.is_production else None,
        redoc_url=None,
    )

    if resolved.api_cors_origins:
        api.add_middleware(
            CORSMiddleware,
            allow_origins=list(resolved.api_cors_origins),
            # With credentials on, Starlette reflects any origin a "*" list
            # admits - a wildcard plus credentials is the configuration every
            # CORS guide warns against.  Bearer tokens do not need it.
            allow_credentials=False,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type"],
        )

    app_service = service or PipelineService(resolved)
    api.state.settings = resolved
    api.state.service = app_service

    _register_routes(api)
    _register_error_handlers(api)
    return api


def get_service(request: Request) -> PipelineService:
    return request.app.state.service  # type: ignore[no-any-return]


def get_app_settings(request: Request) -> Settings:
    return request.app.state.settings  # type: ignore[no-any-return]


async def get_principal(
    request: Request,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(_bearer)] = None,
) -> Principal:
    """Resolve the caller's identity from the bearer token."""
    settings: Settings = request.app.state.settings
    if not settings.auth_enabled:
        return Principal.system(subject="anonymous-local")

    if credentials is None or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        claims = verify_token(
            credentials.credentials,
            settings.jwt_secret,
            issuer=settings.jwt_issuer or None,
            audience=settings.jwt_audience or None,
        )
    except SecurityError as exc:
        # Log the reason, tell the client only that it failed.
        logger.warning("token rejected: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        ) from exc
    return principal_from_claims(claims)


def _require(principal: Principal, permission: Permission, pipeline: str | None = None) -> None:
    from ironflow.security.rbac import AccessControl

    try:
        AccessControl(enabled=True).authorize(principal, permission, pipeline=pipeline)
    except SecurityError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc.message)) from exc


def _require_unscoped(principal: Principal, what: str) -> None:
    """For data that spans every pipeline and cannot be filtered per scope."""
    if "*" not in principal.pipeline_scopes:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"{what} covers every pipeline; it needs a principal without a pipeline scope",
        )


# --------------------------------------------------------------------------- #
def _register_routes(api: FastAPI) -> None:
    @api.get("/health", response_model=HealthResponse, tags=["system"])
    async def health(
        service: Annotated[PipelineService, Depends(get_service)],
    ) -> HealthResponse:
        """Liveness and readiness probe."""
        report = service.healthcheck()
        healthy = report["database"] and not report["production_problems"]
        return HealthResponse(
            status="ok" if healthy else "degraded",
            version=__version__,
            environment=str(report["environment"]),
            database=bool(report["database"]),
            pipelines=int(report["pipelines_discovered"]),
            problems=list(report["production_problems"]),
        )

    @api.get("/metrics", response_class=PlainTextResponse, tags=["system"])
    async def metrics(
        principal: Annotated[Principal, Depends(get_principal)],
        settings: Annotated[Settings, Depends(get_app_settings)],
    ) -> str:
        """Prometheus exposition endpoint."""
        if settings.auth_enabled:
            _require(principal, Permission.METRICS_READ)
            # Every series carries a pipeline label, so a scoped principal would
            # read other teams' volumes and failure counts here.
            _require_unscoped(principal, "the metrics endpoint")
        return METRICS.render_prometheus()

    @api.get("/api/pipelines", tags=["pipelines"])
    async def list_pipelines(
        service: Annotated[PipelineService, Depends(get_service)],
        principal: Annotated[Principal, Depends(get_principal)],
        profile: str | None = None,
    ) -> list[dict[str, Any]]:
        _require(principal, Permission.PIPELINE_READ)
        return [
            {
                "name": spec.name,
                "version": spec.version,
                "description": spec.description,
                "owner": spec.owner,
                "enabled": spec.enabled,
                "tasks": len(spec.tasks),
                "tags": spec.tags,
            }
            for spec in service.list_pipelines(profile=profile)
            if principal.can_access_pipeline(spec.name)
        ]

    @api.get("/api/pipelines/{name}", tags=["pipelines"])
    async def get_pipeline(
        name: str,
        service: Annotated[PipelineService, Depends(get_service)],
        principal: Annotated[Principal, Depends(get_principal)],
    ) -> dict[str, Any]:
        _require(principal, Permission.PIPELINE_READ, name)
        spec = service.get_pipeline(name)
        return service.validate(spec)

    @api.post(
        "/api/pipelines/{name}/runs",
        response_model=RunAccepted,
        status_code=status.HTTP_202_ACCEPTED,
        tags=["pipelines"],
    )
    async def trigger_run(
        name: str,
        body: RunRequest,
        background: BackgroundTasks,
        service: Annotated[PipelineService, Depends(get_service)],
        principal: Annotated[Principal, Depends(get_principal)],
    ) -> RunAccepted:
        """Trigger a run.  Returns immediately; poll the run endpoint for status."""
        _require(principal, Permission.PIPELINE_RUN, name)
        spec = service.get_pipeline(name, profile=body.profile)

        from ironflow.core.context import new_id

        execution_id = new_id("exec_")

        def _run() -> None:
            try:
                service.run(
                    spec,
                    parameters=body.parameters,
                    dry_run=body.dry_run,
                    only=body.only or None,
                    principal=principal,
                    trigger="api",
                    # The same id this response already returned, so the client
                    # can actually poll /api/runs/{execution_id} for it.
                    execution_id=execution_id,
                    install_signal_handlers=False,
                )
            except IronFlowError:
                logger.error("API-triggered run of %r failed", name, exc_info=True)

        background.add_task(_run)
        return RunAccepted(
            execution_id=execution_id,
            pipeline=name,
            status=RunStatus.PENDING.value,
            dry_run=body.dry_run,
        )

    @api.get("/api/pipelines/{name}/status", tags=["pipelines"])
    async def pipeline_status(
        name: str,
        service: Annotated[PipelineService, Depends(get_service)],
        principal: Annotated[Principal, Depends(get_principal)],
    ) -> dict[str, Any]:
        _require(principal, Permission.RUN_HISTORY_READ, name)
        return service.status(name)

    @api.get("/api/runs", tags=["runs"])
    async def list_runs(
        service: Annotated[PipelineService, Depends(get_service)],
        principal: Annotated[Principal, Depends(get_principal)],
        pipeline: str | None = None,
        run_status: Annotated[str | None, Query(alias="status")] = None,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> list[dict[str, Any]]:
        _require(principal, Permission.RUN_HISTORY_READ, pipeline)
        try:
            parsed = RunStatus(run_status) if run_status else None
        except ValueError as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="unknown status"
            ) from exc
        visible = None if pipeline else service.visible_pipelines(principal)
        return service.history(
            pipeline_name=pipeline, status=parsed, limit=limit, pipelines=visible
        )

    @api.get("/api/runs/{execution_id}", tags=["runs"])
    async def get_run(
        execution_id: str,
        service: Annotated[PipelineService, Depends(get_service)],
        principal: Annotated[Principal, Depends(get_principal)],
    ) -> dict[str, Any]:
        _require(principal, Permission.RUN_HISTORY_READ)
        run = service.run_details(execution_id)
        # Out of scope reads as absent: a 403 would confirm the id exists.
        if run is None or not principal.can_access_pipeline(str(run.get("pipeline", ""))):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="run not found")
        return run

    @api.get("/api/statistics", tags=["runs"])
    async def statistics(
        service: Annotated[PipelineService, Depends(get_service)],
        principal: Annotated[Principal, Depends(get_principal)],
        pipeline: str | None = None,
        days: Annotated[int, Query(ge=1, le=365)] = 30,
    ) -> dict[str, Any]:
        _require(principal, Permission.METRICS_READ, pipeline)
        visible = None if pipeline else service.visible_pipelines(principal)
        return service.statistics(pipeline, days=days, pipelines=visible)

    @api.get("/", response_class=HTMLResponse, tags=["system"], include_in_schema=False)
    async def dashboard(
        service: Annotated[PipelineService, Depends(get_service)],
        principal: Annotated[Principal, Depends(get_principal)],
    ) -> str:
        """Server-rendered overview.  With auth on, it needs a token like the API.

        A browser does not send a bearer header by itself, so in an
        authenticated deployment the dashboard is reached through a proxy that
        adds one (an SSO gateway) - not by leaving the page open.
        """
        from ironflow.api.dashboard import render_dashboard

        _require(principal, Permission.PIPELINE_READ)
        _require(principal, Permission.RUN_HISTORY_READ)
        visible = service.visible_pipelines(principal)
        return render_dashboard(
            statistics=service.statistics(pipelines=visible),
            timeline=service.runs.timeline(limit=25, pipelines=visible),
            pipelines=[
                {"name": s.name, "version": s.version, "tasks": len(s.tasks), "owner": s.owner}
                for s in service.list_pipelines()
                if principal.can_access_pipeline(s.name)
            ],
        )


def _register_error_handlers(api: FastAPI) -> None:
    from fastapi.responses import JSONResponse

    @api.exception_handler(ConfigurationError)
    async def _config_error(_request: Request, exc: ConfigurationError) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"code": exc.code, "message": exc.message},
        )

    @api.exception_handler(SecurityError)
    async def _security_error(_request: Request, exc: SecurityError) -> JSONResponse:
        logger.warning("security error on API request: %s", exc)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"code": exc.code, "message": "forbidden"},
        )

    @api.exception_handler(IronFlowError)
    async def _generic_error(_request: Request, exc: IronFlowError) -> JSONResponse:
        # The context can hold table names and paths; keep it out of the response.
        logger.error("unhandled platform error", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"code": exc.code, "message": exc.message},
        )


__all__ = ["create_app", "get_principal", "get_service"]
