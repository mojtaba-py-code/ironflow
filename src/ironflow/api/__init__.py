"""Optional REST API and monitoring dashboard (requires the ``api`` extra)."""

from __future__ import annotations

__all__ = ["create_app"]


def __getattr__(name: str) -> object:
    """Import lazily so ``import ironflow.api`` does not require FastAPI."""
    if name == "create_app":
        from ironflow.api.app import create_app

        return create_app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
