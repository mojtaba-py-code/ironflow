"""Pipeline scopes hold on every API read, not only the ones that name a pipeline.

A principal scoped to ``sales_*`` was refused ``/api/pipelines/hr_payroll/status``
and then read the same data through the routes that take no pipeline name: the
run list, a run fetched by id, the statistics, the metrics - and the dashboard,
which answered with no token at all.  Each test below is one of those doors.
"""

from __future__ import annotations

from pathlib import Path

import pytest

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from ironflow.api.app import create_app  # noqa: E402
from ironflow.config.settings import Settings  # noqa: E402
from ironflow.core.types import RunStatus  # noqa: E402
from ironflow.repositories.database import Database  # noqa: E402
from ironflow.security.rbac import issue_token  # noqa: E402
from ironflow.services.pipeline_service import PipelineService  # noqa: E402

JWT_SECRET = "an-authorization-test-secret-of-sufficient-length"
SALES_RUN = "exec_sales_0001"
HR_RUN = "exec_hr_0001"


@pytest.fixture
def api(tmp_path: Path) -> TestClient:
    home = tmp_path / ".ironflow"
    (tmp_path / "pipelines").mkdir()
    settings = Settings(
        home=home,
        data_roots=[tmp_path],
        pipelines_dir=tmp_path / "pipelines",
        state_database_url=f"sqlite:///{(home / 'state.db').as_posix()}",
        auth_enabled=True,
        jwt_secret=JWT_SECRET,
    )
    settings.ensure_directories()
    service = PipelineService(
        settings, database=Database(settings=settings), pipelines_dir=tmp_path / "pipelines"
    )
    for execution_id, pipeline, error in (
        (SALES_RUN, "sales_daily", None),
        (HR_RUN, "hr_payroll", RuntimeError("salary table locked: row 7 of payroll_2026")),
    ):
        service.runs.start_run(execution_id=execution_id, pipeline_name=pipeline)
        service.runs.finish_run(
            execution_id,
            status=RunStatus.FAILED if error else RunStatus.SUCCESS,
            duration_seconds=1.0,
            rows_written=10,
            error=error,
        )
    return TestClient(create_app(settings, service))


def token(roles: list[str], pipelines: list[str]) -> dict[str, str]:
    claims = {
        "sub": "tester",
        "roles": roles,
        "pipelines": pipelines,
        "iss": "ironflow",
        "aud": "ironflow-api",
    }
    return {"Authorization": f"Bearer {issue_token(claims, JWT_SECRET)}"}


SALES_VIEWER = token(["viewer"], ["sales_*"])
EVERYTHING_VIEWER = token(["viewer"], ["*"])


class TestRunReadsRespectScopes:
    def test_the_run_list_shows_only_pipelines_in_scope(self, api):
        runs = api.get("/api/runs", headers=SALES_VIEWER).json()
        assert {run["pipeline"] for run in runs} == {"sales_daily"}

    def test_an_unscoped_principal_still_sees_everything(self, api):
        runs = api.get("/api/runs", headers=EVERYTHING_VIEWER).json()
        assert {run["pipeline"] for run in runs} == {"sales_daily", "hr_payroll"}

    def test_asking_for_an_out_of_scope_pipeline_by_name_is_refused(self, api):
        response = api.get("/api/runs", params={"pipeline": "hr_payroll"}, headers=SALES_VIEWER)
        assert response.status_code == 403

    def test_a_run_outside_the_scope_reads_as_absent(self, api):
        """404, not 403: the error must not confirm that the id exists."""
        response = api.get(f"/api/runs/{HR_RUN}", headers=SALES_VIEWER)
        assert response.status_code == 404
        assert "salary" not in response.text
        assert api.get(f"/api/runs/{SALES_RUN}", headers=SALES_VIEWER).status_code == 200

    def test_statistics_count_only_pipelines_in_scope(self, api):
        stats = api.get("/api/statistics", headers=token(["operator"], ["sales_*"])).json()
        assert stats["runs_total"] == 1
        assert stats["runs_failed"] == 0

    def test_metrics_need_an_unscoped_principal(self, api):
        assert api.get("/metrics", headers=token(["operator"], ["sales_*"])).status_code == 403
        assert api.get("/metrics", headers=token(["operator"], ["*"])).status_code == 200


class TestDashboard:
    def test_it_needs_a_token_when_authentication_is_on(self, api):
        response = api.get("/")
        assert response.status_code == 401
        assert "hr_payroll" not in response.text

    def test_it_renders_only_what_the_caller_may_see(self, api):
        page = api.get("/", headers=SALES_VIEWER)
        assert page.status_code == 200
        assert "sales_daily" in page.text
        assert "hr_payroll" not in page.text


class TestCors:
    def test_a_wildcard_origin_is_never_combined_with_credentials(self, tmp_path):
        settings = Settings(home=tmp_path / ".ironflow", api_cors_origins=["*"])
        settings.ensure_directories()
        client = TestClient(create_app(settings))
        response = client.get("/health", headers={"Origin": "https://evil.example"})
        assert response.headers.get("access-control-allow-credentials") != "true"
        assert response.headers.get("access-control-allow-origin") in {"*", None}
