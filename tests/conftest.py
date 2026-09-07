"""Shared pytest fixtures.

Every fixture is filesystem- and process-isolated: each test gets its own
``tmp_path`` home, its own SQLite state database and a fresh settings object.
That keeps the suite parallelisable and means a failing test cannot leave state
that makes the next one fail.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from ironflow.config.models import ConnectorSpec, PipelineSpec
from ironflow.config.settings import Settings, reset_settings
from ironflow.connectors.factory import ConnectorFactory
from ironflow.connectors.memory import MemorySink, MemorySource
from ironflow.core.context import ExecutionContext
from ironflow.core.events import EventBus
from ironflow.core.types import RecordBatch
from ironflow.observability.metrics import MetricsRegistry
from ironflow.repositories.database import Database, reset_database
from ironflow.services.pipeline_service import PipelineService


@pytest.fixture(autouse=True)
def _isolate_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """Strip IRONFLOW_* variables so a developer's shell cannot alter results."""
    for key in list(os.environ):
        if key.startswith("IRONFLOW_"):
            monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("IRONFLOW_HOME", str(tmp_path / ".ironflow"))
    reset_settings()
    reset_database()
    MemorySource.clear()
    MemorySink.clear()
    yield
    reset_settings()
    reset_database()


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Settings confined to the test's temporary directory."""
    home = tmp_path / ".ironflow"
    return Settings(
        environment="local",
        home=home,
        data_roots=[tmp_path],
        pipelines_dir=tmp_path / "pipelines",
        state_database_url=f"sqlite:///{(home / 'state.db').as_posix()}",
        default_batch_size=100,
        audit_file=home / "audit.jsonl",
        allow_private_network=True,
    )


@pytest.fixture
def database(settings: Settings) -> Iterator[Database]:
    settings.ensure_directories()
    db = Database(settings=settings)
    yield db
    db.dispose()


@pytest.fixture
def factory(settings: Settings) -> ConnectorFactory:
    return ConnectorFactory(settings)


@pytest.fixture
def metrics() -> MetricsRegistry:
    return MetricsRegistry(namespace="test")


@pytest.fixture
def events() -> EventBus:
    return EventBus()


@pytest.fixture
def context(metrics: MetricsRegistry, events: EventBus) -> ExecutionContext:
    return ExecutionContext(pipeline_id="test_pipeline", metrics=metrics, events=events)


@pytest.fixture
def service(settings: Settings, database: Database, tmp_path: Path) -> PipelineService:
    (tmp_path / "pipelines").mkdir(exist_ok=True)
    return PipelineService(settings, database=database, pipelines_dir=tmp_path / "pipelines")


# --------------------------------------------------------------------------- #
# Data fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def sample_records() -> list[dict[str, Any]]:
    return [
        {"id": 1, "name": "Alice", "email": "alice@corp.com", "amount": 100.5, "region": "EU"},
        {"id": 2, "name": "Bob", "email": "bob@corp.com", "amount": -5.0, "region": "EU"},
        {"id": 3, "name": "Carol", "email": "carol@corp.com", "amount": 250.0, "region": "US"},
        {"id": 4, "name": "Dave", "email": "not-an-email", "amount": 10.0, "region": "US"},
        {"id": 5, "name": "Eve", "email": "eve@corp.com", "amount": None, "region": "EU"},
    ]


@pytest.fixture
def batch(sample_records: list[dict[str, Any]]) -> RecordBatch:
    return RecordBatch(list(sample_records), source="fixture")


@pytest.fixture
def csv_file(tmp_path: Path) -> Path:
    path = tmp_path / "orders.csv"
    path.write_text(
        "id,name,email,amount,region\n"
        "1,Alice,alice@corp.com,100.5,EU\n"
        "2,Bob,bob@corp.com,-5,EU\n"
        "3,Carol,carol@corp.com,250,US\n"
        "4,Dave,not-an-email,10,US\n"
        "5,Eve,eve@corp.com,,EU\n",
        encoding="utf-8",
    )
    return path


@pytest.fixture
def memory_pipeline(sample_records: list[dict[str, Any]]) -> PipelineSpec:
    """A minimal in-memory pipeline: no filesystem, no database."""
    MemorySource.register("orders", sample_records)
    return PipelineSpec.model_validate(
        {
            "name": "memory_pipeline",
            "tasks": [
                {
                    "name": "copy",
                    "source": {"type": "memory", "dataset": "orders"},
                    "destination": {"type": "memory", "buffer": "out", "mode": "overwrite"},
                }
            ],
        }
    )


def connector_spec(connector_type: str, **options: Any) -> ConnectorSpec:
    """Terse ConnectorSpec builder for tests."""
    return ConnectorSpec.model_validate({"type": connector_type, **options})
