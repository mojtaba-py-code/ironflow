"""REST API tests (requires the ``api`` extra)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

fastapi = pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from ironflow.api.app import create_app  # noqa: E402
from ironflow.config.settings import Settings  # noqa: E402
from ironflow.core.errors import ConfigurationError  # noqa: E402
from ironflow.repositories.database import Database  # noqa: E402
from ironflow.security.rbac import issue_token  # noqa: E402
from ironflow.services.pipeline_service import PipelineService  # noqa: E402

JWT_SECRET = "a-test-secret-that-is-at-least-32-chars"


@pytest.fixture
def api_workspace(tmp_path: Path) -> Path:
    (tmp_path / "pipelines").mkdir()
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "in.csv").write_text("id,v\n1,a\n2,b\n", encoding="utf-8")
    (tmp_path / "pipelines" / "demo.yaml").write_text(
        yaml.safe_dump(
            {
                "name": "demo",
                "tasks": [
                    {
                        "name": "t",
                        "source": {"type": "csv", "path": str(tmp_path / "data" / "in.csv")},
                        "destination": {
                            "type": "csv",
                            "path": str(tmp_path / "out.csv"),
                            "mode": "overwrite",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return tmp_path


def build_client(workspace: Path, **overrides) -> TestClient:
    home = workspace / ".ironflow"
    settings = Settings(
        home=home,
        data_roots=[workspace],
        pipelines_dir=workspace / "pipelines",
        state_database_url=f"sqlite:///{(home / 'state.db').as_posix()}",
        **overrides,
    )
    settings.ensure_directories()
    service = PipelineService(
        settings,
        database=Database(settings=settings),
        pipelines_dir=workspace / "pipelines",
    )
    return TestClient(create_app(settings, service))


def auth(roles: list[str], pipelines: list[str] | None = None) -> dict[str, str]:
    token = issue_token(
        {
            "sub": "tester",
            "roles": roles,
            "pipelines": pipelines or ["*"],
            "iss": "ironflow",
            "aud": "ironflow-api",
        },
        JWT_SECRET,
    )
    return {"Authorization": f"Bearer {token}"}


class TestUnauthenticated:
    """With auth disabled (local development) everything is reachable."""

    @pytest.fixture
    def client(self, api_workspace: Path) -> TestClient:
        return build_client(api_workspace)

    def test_health(self, client):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] in {"ok", "degraded"}

    def test_metrics_is_prometheus_text(self, client):
        response = client.get("/metrics")
        assert response.status_code == 200
        assert "text/plain" in response.headers["content-type"]

    def test_list_pipelines(self, client):
        response = client.get("/api/pipelines")
        assert response.status_code == 200
        assert response.json()[0]["name"] == "demo"

    def test_get_pipeline_returns_its_validation(self, client):
        response = client.get("/api/pipelines/demo")
        assert response.status_code == 200
        assert response.json()["valid"] is True

    def test_unknown_pipeline_is_a_400(self, client):
        response = client.get("/api/pipelines/ghost")
        assert response.status_code == 400
        assert response.json()["code"] == "CONFIG_INVALID"

    def test_trigger_run_is_accepted_and_executes(self, client, api_workspace):
        response = client.post("/api/pipelines/demo/runs", json={})
        assert response.status_code == 202
        assert response.json()["pipeline"] == "demo"
        # TestClient runs background tasks before returning.
        assert (api_workspace / "out.csv").exists()

    def test_dry_run_writes_nothing(self, client, api_workspace):
        response = client.post("/api/pipelines/demo/runs", json={"dry_run": True})
        assert response.status_code == 202
        assert not (api_workspace / "out.csv").exists()

    def test_run_history(self, client):
        client.post("/api/pipelines/demo/runs", json={})
        response = client.get("/api/runs")
        assert response.status_code == 200
        assert response.json()[0]["pipeline"] == "demo"

    def test_run_detail_and_404(self, client):
        client.post("/api/pipelines/demo/runs", json={})
        execution_id = client.get("/api/runs").json()[0]["execution_id"]
        assert client.get(f"/api/runs/{execution_id}").status_code == 200
        assert client.get("/api/runs/nope").status_code == 404

    def test_invalid_status_filter(self, client):
        assert client.get("/api/runs", params={"status": "sideways"}).status_code == 400

    def test_statistics(self, client):
        response = client.get("/api/statistics")
        assert response.status_code == 200
        assert "success_rate" in response.json()

    def test_pipeline_status(self, client):
        response = client.get("/api/pipelines/demo/status")
        assert response.status_code == 200
        assert response.json()["pipeline"] == "demo"

    def test_dashboard_renders(self, client):
        response = client.get("/")
        assert response.status_code == 200
        assert "IronFlow" in response.text
        assert "<!DOCTYPE html>" in response.text

    def test_dashboard_escapes_pipeline_names(self, client, api_workspace):
        """Run data reaches the page; an unescaped value would be an XSS sink."""
        (api_workspace / "pipelines" / "x.yaml").write_text(
            yaml.safe_dump(
                {
                    "name": "xss.test",
                    "owner": "<script>alert(1)</script>",
                    "tasks": [
                        {
                            "name": "t",
                            "source": {"type": "memory"},
                            "destination": {"type": "null"},
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        response = client.get("/")
        assert "<script>alert(1)</script>" not in response.text
        assert "&lt;script&gt;" in response.text


class TestAuthenticated:
    @pytest.fixture
    def client(self, api_workspace: Path) -> TestClient:
        return build_client(api_workspace, auth_enabled=True, jwt_secret=JWT_SECRET)

    def test_health_stays_public(self, client):
        assert client.get("/health").status_code == 200

    def test_missing_token_is_401(self, client):
        response = client.get("/api/pipelines")
        assert response.status_code == 401
        assert "WWW-Authenticate" in response.headers

    def test_invalid_token_is_401(self, client):
        response = client.get("/api/pipelines", headers={"Authorization": "Bearer garbage"})
        assert response.status_code == 401

    def test_token_signed_with_the_wrong_secret_is_401(self, client):
        token = issue_token({"sub": "x", "roles": ["admin"]}, "the-wrong-secret-value-here!!")
        response = client.get("/api/pipelines", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401

    def test_viewer_can_read(self, client):
        assert client.get("/api/pipelines", headers=auth(["viewer"])).status_code == 200

    def test_viewer_cannot_trigger_a_run(self, client):
        response = client.post("/api/pipelines/demo/runs", json={}, headers=auth(["viewer"]))
        assert response.status_code == 403

    def test_operator_can_trigger_a_run(self, client):
        response = client.post("/api/pipelines/demo/runs", json={}, headers=auth(["operator"]))
        assert response.status_code == 202

    def test_pipeline_scoping_is_enforced(self, client):
        headers = auth(["operator"], pipelines=["sales_*"])
        assert client.post("/api/pipelines/demo/runs", json={}, headers=headers).status_code == 403

    def test_scoped_pipelines_are_filtered_from_listings(self, client):
        headers = auth(["viewer"], pipelines=["sales_*"])
        assert client.get("/api/pipelines", headers=headers).json() == []

    def test_metrics_requires_permission(self, client):
        assert client.get("/metrics").status_code == 401
        assert client.get("/metrics", headers=auth(["viewer"])).status_code == 200

    def test_docs_are_available_outside_production(self, client):
        assert client.get("/docs").status_code == 200


class TestProductionGuard:
    def test_unhardened_production_refuses_to_start(self, api_workspace: Path):
        settings = Settings(environment="production", home=api_workspace / ".ironflow")
        with pytest.raises(ConfigurationError, match="production-hardened"):
            create_app(settings)

    def test_hardened_production_hides_the_docs_endpoint(self, api_workspace: Path):
        home = api_workspace / ".ironflow"
        settings = Settings(
            environment="production",
            home=home,
            auth_enabled=True,
            jwt_secret=JWT_SECRET,
            encryption_key="k" * 44,
            allow_literal_secrets=False,
            allow_private_network=False,
            data_roots=[api_workspace],
            # SQLite is flagged by the hardening check, so point at a server URL
            # for the settings check and hand the app a SQLite-backed service.
            state_database_url="postgresql+psycopg://u@h/db",
            pipelines_dir=api_workspace / "pipelines",
        )
        settings.ensure_directories()
        assert settings.validate_production_hardening() == []

        local = settings.model_copy(
            update={"state_database_url": f"sqlite:///{(home / 'state.db').as_posix()}"}
        )
        service = PipelineService(
            local, database=Database(settings=local), pipelines_dir=api_workspace / "pipelines"
        )
        client = TestClient(create_app(settings, service))
        assert client.get("/docs").status_code == 404
        assert client.get("/health").status_code == 200
