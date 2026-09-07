"""State-database engine and session management.

One :class:`Database` per process wraps a pooled SQLAlchemy engine.  Sessions
are handed out through a context manager that commits on success and rolls back
on any exception - so no call site can leave a transaction open, which is the
usual cause of "the scheduler stopped writing history" incidents.

SQLite is supported for local development and CI and gets two pragmas applied on
every connection:

``journal_mode=WAL``
    Allows a reader (the dashboard) concurrently with a writer (the pipeline).
    Without it, the default rollback journal makes them block each other.
``foreign_keys=ON``
    SQLite ignores foreign keys unless asked, so the ``ON DELETE CASCADE`` on
    ``task_runs`` would silently not happen.

Production is expected to point ``IRONFLOW_STATE_DATABASE_URL`` at PostgreSQL;
:meth:`Settings.validate_production_hardening` flags a SQLite URL there.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, event, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from ironflow.config.settings import Settings, get_settings
from ironflow.core.errors import ConnectionError as IFConnectionError
from ironflow.repositories.models import Base
from ironflow.security.masking import redact_url

logger = logging.getLogger(__name__)


class Database:
    """Owns the state-database engine and session factory."""

    def __init__(
        self,
        url: str | None = None,
        settings: Settings | None = None,
        *,
        create_schema: bool = True,
    ) -> None:
        self.settings = settings or get_settings()
        self.url = url or self.settings.state_database_url
        self._engine = self._create_engine()
        self._session_factory = sessionmaker(
            bind=self._engine, expire_on_commit=False, class_=Session
        )
        if create_schema:
            self.create_schema()

    @property
    def engine(self) -> Engine:
        return self._engine

    @property
    def is_sqlite(self) -> bool:
        return self.url.startswith("sqlite")

    def _create_engine(self) -> Engine:
        kwargs: dict[str, Any] = {"future": True, "echo": self.settings.state_echo}

        if self.is_sqlite:
            self._ensure_sqlite_directory()
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
            if ":memory:" in self.url:
                # An in-memory database lives in its connection; a pool would
                # hand out a different (empty) database to the next caller.
                kwargs["poolclass"] = StaticPool
        else:
            kwargs.update(
                pool_size=self.settings.state_pool_size,
                max_overflow=self.settings.state_max_overflow,
                pool_pre_ping=True,
                pool_recycle=1800,
            )

        try:
            engine = create_engine(self.url, **kwargs)
        except (SQLAlchemyError, ValueError, ModuleNotFoundError) as exc:
            raise IFConnectionError(
                "unable to create the state database engine",
                context={"url": redact_url(self.url)},
                cause=exc,
            ) from exc

        if self.is_sqlite:
            _install_sqlite_pragmas(engine)
        return engine

    def _ensure_sqlite_directory(self) -> None:
        path_part = self.url.split("///", 1)[-1]
        if path_part and ":memory:" not in path_part:
            Path(path_part).expanduser().parent.mkdir(parents=True, exist_ok=True)

    def create_schema(self) -> None:
        """Create any missing tables.  Idempotent."""
        try:
            Base.metadata.create_all(self._engine)
        except SQLAlchemyError as exc:
            raise IFConnectionError(
                "unable to initialise the state database schema",
                context={"url": redact_url(self.url)},
                cause=exc,
            ) from exc
        logger.debug("state schema ready at %s", redact_url(self.url))

    def drop_schema(self) -> None:
        """Drop every control-plane table.  Used by tests and ``ironflow clean``."""
        Base.metadata.drop_all(self._engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Transactional session scope: commit on success, roll back on error."""
        session = self._session_factory()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    def healthcheck(self) -> bool:
        """Cheap liveness probe for the API and ``ironflow config check``."""
        try:
            with self._engine.connect() as connection:
                connection.execute(text("SELECT 1"))
        except SQLAlchemyError:
            logger.warning("state database healthcheck failed", exc_info=True)
            return False
        return True

    def dispose(self) -> None:
        self._engine.dispose()

    def __repr__(self) -> str:
        return f"Database(url={redact_url(self.url)!r})"


def _install_sqlite_pragmas(engine: Engine) -> None:
    """Enable WAL and foreign keys on every SQLite connection."""

    @event.listens_for(engine, "connect")
    def _set_pragmas(dbapi_connection: Any, _record: Any) -> None:  # pragma: no cover - driver hook
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA synchronous=NORMAL")
        finally:
            cursor.close()


_DEFAULT: Database | None = None


def get_database(settings: Settings | None = None) -> Database:
    """Process-wide default :class:`Database`."""
    global _DEFAULT
    if _DEFAULT is None:
        _DEFAULT = Database(settings=settings)
    return _DEFAULT


def reset_database() -> None:
    """Dispose and forget the default database (tests, reconfiguration)."""
    global _DEFAULT
    if _DEFAULT is not None:
        _DEFAULT.dispose()
    _DEFAULT = None


__all__ = ["Database", "get_database", "reset_database"]
