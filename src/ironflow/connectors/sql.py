"""SQL connectors built on SQLAlchemy Core (SQLite, PostgreSQL, MySQL).

SQL injection: how it is prevented
----------------------------------
There are exactly two kinds of value that reach a statement, and each has its
own rule:

*Values* (a watermark, a filter argument, every column of every row) are **always
bound parameters**.  They are never formatted into the SQL string, so the driver
sends them out of band and no quoting bug is possible.

*Identifiers* (table and column names) cannot be bound - no DB-API supports
that - so they are validated against ``^[A-Za-z_][A-Za-z0-9_]*$`` by
:func:`~ironflow.security.guards.validate_identifier` and then quoted for the
dialect.  A name that does not match is rejected before it reaches the database.

The one place a raw fragment is accepted is the optional ``where`` option, which
exists because real pipelines need predicates the model cannot express.  It is
run through :func:`assert_no_sql_injection` (rejecting ``;``, comments, ``UNION``,
DDL/DML verbs), which is defence in depth rather than the primary control - the
primary control is that this option is written by the pipeline author, who is
also the person with database credentials.

Other properties
----------------
* **Server-side cursors** (``stream_results``) so a 50-million-row table is not
  buffered client side.
* **Connection pooling** with ``pool_pre_ping`` so a connection killed by a
  firewall idle timeout is detected and replaced instead of failing the load.
* **A real transaction** around the whole load: ``rollback`` genuinely undoes
  everything, which is what makes ``on_violation: fail`` meaningful.
* **Batched executemany** inserts, which is one round trip per batch instead of
  one per row.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator, Sequence
from typing import Any

from sqlalchemy import MetaData, Table, create_engine, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import SQLAlchemyError

from ironflow.config.models import ConnectorSpec
from ironflow.connectors.base import BaseSink, BaseSource, ConnectorRuntime, sink, source
from ironflow.core.context import ExecutionContext
from ironflow.core.errors import ConfigurationError, ExtractionError, LoadingError
from ironflow.core.errors import ConnectionError as IFConnectionError
from ironflow.core.types import (
    DatasetSchema,
    FieldSchema,
    FieldType,
    LoadMode,
    RecordBatch,
    RecordStream,
)
from ironflow.security.guards import (
    assert_no_sql_injection,
    quote_identifier,
    validate_identifier,
)
from ironflow.security.masking import redact_url

logger = logging.getLogger(__name__)

#: Logical type inference from the DB-API type name.
_TYPE_HINTS: tuple[tuple[tuple[str, ...], FieldType], ...] = (
    (("INT", "SERIAL", "BIGINT", "SMALLINT"), FieldType.INTEGER),
    (("FLOAT", "REAL", "DOUBLE"), FieldType.FLOAT),
    (("NUMERIC", "DECIMAL", "MONEY"), FieldType.DECIMAL),
    (("BOOL",), FieldType.BOOLEAN),
    (("TIMESTAMP", "DATETIME"), FieldType.DATETIME),
    (("DATE",), FieldType.DATE),
    (("JSON",), FieldType.JSON),
    (("CHAR", "TEXT", "STRING", "UUID"), FieldType.STRING),
)


class SqlConnectorMixin:
    """Engine construction shared by the SQL source and sink."""

    def _build_url(self: Any) -> str:
        """Assemble the SQLAlchemy URL from ``dsn`` or discrete parts."""
        dsn = self.secret_option("dsn")
        if dsn:
            return dsn

        driver = self.str_option("driver", _default_driver(self.spec.type))
        host = self.str_option("host", "localhost")
        port = self.option("port")
        database = self.str_option("database", required=True)
        user = self.secret_option("user") or self.secret_option("username")
        password = self.secret_option("password")

        if self.spec.type == "sqlite":
            path = self.runtime.resolve_path(database)
            return f"sqlite:///{path.as_posix()}"

        from urllib.parse import quote_plus

        credentials = ""
        if user:
            credentials = quote_plus(user)
            if password:
                credentials += f":{quote_plus(password)}"
            credentials += "@"
        netloc = f"{credentials}{host}" + (f":{int(port)}" if port else "")
        return f"{driver}://{netloc}/{database}"

    def _create_engine(self: Any) -> Engine:
        url = self._build_url()
        settings = self.runtime.settings
        connect_args: dict[str, Any] = dict(self.option("connect_args", {}) or {})

        is_sqlite = url.startswith("sqlite")
        if not is_sqlite:
            connect_args.setdefault("connect_timeout", int(self.int_option("timeout", 30)))
            # Refuse an unencrypted link to a remote database unless the
            # operator explicitly opted out.
            if self.spec.type == "postgres" and self.bool_option("require_tls", True):
                connect_args.setdefault("sslmode", "require")

        kwargs: dict[str, Any] = {
            "echo": settings.state_echo,
            "future": True,
            "connect_args": connect_args,
            "pool_pre_ping": True,
        }
        if not is_sqlite:
            kwargs.update(
                pool_size=self.int_option("pool_size", settings.state_pool_size, minimum=1),
                max_overflow=self.int_option(
                    "max_overflow", settings.state_max_overflow, minimum=0
                ),
                pool_recycle=self.int_option("pool_recycle", 1800, minimum=60),
            )
        try:
            engine = create_engine(url, **kwargs)
        except (SQLAlchemyError, ValueError, ModuleNotFoundError) as exc:
            raise IFConnectionError(
                "unable to create the database engine",
                context={"url": redact_url(url), "detail": str(exc)[:200]},
                cause=exc,
            ) from exc
        logger.debug("engine created", extra={"url": redact_url(url)})
        return engine

    @property
    def _dialect(self: Any) -> str:
        return {"mysql": "mysql"}.get(self.spec.type, "default")


def _default_driver(connector_type: str) -> str:
    return {
        "postgres": "postgresql+psycopg",
        "postgresql": "postgresql+psycopg",
        "mysql": "mysql+pymysql",
        "sqlite": "sqlite",
    }.get(connector_type, connector_type)


# --------------------------------------------------------------------------- #
# Source
# --------------------------------------------------------------------------- #
@source("sql", "sqlite", "postgres", "postgresql", "mysql")
class SqlSource(SqlConnectorMixin, BaseSource):
    """Read from a table or a custom query.

    Options: ``dsn`` **or** (``host``/``port``/``database``/``user``/``password``),
    plus one of ``table`` or ``query``; ``columns``, ``where``, ``order_by``,
    ``params`` (bound), ``fetch_size``.

    Incremental extraction is driven by the engine, which passes
    ``__watermark__`` as a bound parameter.
    """

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._engine: Engine | None = None
        self._connection: Connection | None = None

    def _on_open(self, context: ExecutionContext) -> None:
        self._engine = self._create_engine()
        try:
            self._connection = self._engine.connect()
        except SQLAlchemyError as exc:
            raise IFConnectionError(
                "unable to connect to the database",
                context={"connector": self.name},
                cause=exc,
            ) from exc

    def _on_close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None

    def build_statement(self) -> tuple[str, dict[str, Any]]:
        """Compose the SELECT and its bound parameters."""
        params: dict[str, Any] = dict(self.option("params", {}) or {})
        custom_query = self.str_option("query")

        if custom_query:
            # A full custom query is the author's responsibility; values still
            # go through ``params`` as bind parameters.
            return custom_query, params

        table_name = self.str_option("table", required=True)
        validate_identifier(table_name, kind="table", qualified=True)
        quoted_table = ".".join(
            quote_identifier(part, dialect=self._dialect) for part in table_name.split(".")
        )

        columns = self.list_option("columns")
        projection = (
            ", ".join(quote_identifier(c, dialect=self._dialect) for c in columns)
            if columns
            else "*"
        )

        clauses: list[str] = []
        where = self.str_option("where")
        if where:
            clauses.append(f"({assert_no_sql_injection(where, field='where')})")

        watermark_column = self.option("__watermark_column__")
        if watermark_column and "__watermark__" in params:
            column = quote_identifier(
                validate_identifier(str(watermark_column), kind="column"),
                dialect=self._dialect,
            )
            clauses.append(f"{column} > :__watermark__")

        sql = f"SELECT {projection} FROM {quoted_table}"  # noqa: S608 - identifiers validated
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)

        order_by = self.list_option("order_by")
        if order_by:
            rendered = []
            for entry in order_by:
                name, _, direction = entry.partition(" ")
                validate_identifier(name, kind="column")
                suffix = " DESC" if direction.strip().upper() == "DESC" else ""
                rendered.append(f"{quote_identifier(name, dialect=self._dialect)}{suffix}")
            sql += " ORDER BY " + ", ".join(rendered)

        limit = self.option("limit")
        if limit is not None:
            sql += " LIMIT :__limit__"
            params["__limit__"] = int(limit)
        return sql, params

    def read(self, context: ExecutionContext) -> RecordStream:
        if self._connection is None:
            self.open(context)
        assert self._connection is not None
        sql, params = self.build_statement()
        fetch_size = self.int_option("fetch_size", self.batch_size, minimum=1)

        logger.info("executing query", extra={"connector": self.name, "sql": sql[:500]})

        def generate() -> Iterator[RecordBatch]:
            assert self._connection is not None
            try:
                # stream_results asks the driver for a server-side cursor.
                result = self._connection.execution_options(
                    stream_results=True, max_row_buffer=fetch_size
                ).execute(text(sql), params)
            except SQLAlchemyError as exc:
                raise ExtractionError(
                    "query execution failed",
                    context={"connector": self.name, "detail": str(exc.__cause__ or exc)[:300]},
                    cause=exc,
                ) from exc

            sequence = 0
            while True:
                context.cancellation.raise_if_cancelled()
                rows = result.fetchmany(fetch_size)
                if not rows:
                    break
                yield RecordBatch(
                    [dict(row) for row in (r._mapping for r in rows)],
                    sequence=sequence,
                    source=self.name,
                )
                sequence += 1
            result.close()

        return generate()

    def describe(self) -> DatasetSchema:
        """Reflect the table's columns when reading a table (not a query)."""
        table_name = self.str_option("table")
        if not table_name or self._engine is None:
            return DatasetSchema()
        try:
            metadata = MetaData()
            schema_name, _, bare = table_name.rpartition(".")
            reflected = Table(
                bare, metadata, autoload_with=self._engine, schema=schema_name or None
            )
        except SQLAlchemyError:
            logger.debug("table reflection failed", exc_info=True)
            return DatasetSchema()

        fields = [
            FieldSchema(
                name=column.name,
                type=_map_sql_type(str(column.type)),
                nullable=bool(column.nullable),
            )
            for column in reflected.columns
        ]
        return DatasetSchema(tuple(fields))

    def count(self) -> int | None:
        table_name = self.str_option("table")
        if not table_name or self._connection is None:
            return None
        validate_identifier(table_name, kind="table", qualified=True)
        quoted = ".".join(quote_identifier(p, dialect=self._dialect) for p in table_name.split("."))
        try:
            result = self._connection.execute(
                text(f"SELECT COUNT(*) FROM {quoted}")  # noqa: S608 - identifier validated
            )
            return int(result.scalar_one())
        except SQLAlchemyError:
            return None


def _map_sql_type(sql_type: str) -> FieldType:
    upper = sql_type.upper()
    for prefixes, field_type in _TYPE_HINTS:
        if any(prefix in upper for prefix in prefixes):
            return field_type
    return FieldType.UNKNOWN


# --------------------------------------------------------------------------- #
# Sink
# --------------------------------------------------------------------------- #
@sink("sql", "sqlite", "postgres", "postgresql", "mysql")
class SqlSink(SqlConnectorMixin, BaseSink):
    """Transactional bulk loader.

    Options: connection options as for :class:`SqlSource`, plus ``table``
    (required), ``columns``, ``key_columns`` (for ``mode: upsert``),
    ``create_table`` and ``chunk_size``.

    ``mode: overwrite`` issues a ``DELETE FROM`` inside the same transaction as
    the inserts, so a failure mid-load leaves the original data intact.
    ``TRUNCATE`` is deliberately not used: it is DDL on several engines and
    implicitly commits, which would break exactly that guarantee.
    """

    transactional = True

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._engine: Engine | None = None
        self._connection: Connection | None = None
        self._transaction: Any = None
        self._columns: list[str] = []
        self._prepared = False

    def _on_open(self, context: ExecutionContext) -> None:
        self._engine = self._create_engine()
        try:
            self._connection = self._engine.connect()
            self._transaction = self._connection.begin()
        except SQLAlchemyError as exc:
            raise IFConnectionError(
                "unable to open a database transaction",
                context={"connector": self.name},
                cause=exc,
            ) from exc
        self.rows_written = 0
        self._prepared = False

    @property
    def table_name(self) -> str:
        name = self.str_option("table", required=True)
        validate_identifier(name, kind="table", qualified=True)
        return name

    @property
    def quoted_table(self) -> str:
        return ".".join(
            quote_identifier(p, dialect=self._dialect) for p in self.table_name.split(".")
        )

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        self._assert_writable()
        if batch.is_empty:
            return 0
        assert self._connection is not None

        if not self._prepared:
            self._prepare(batch)

        rows = [
            {column: _adapt(record.get(column)) for column in self._columns}
            for record in batch.records
        ]
        statement = self._insert_statement()
        chunk_size = self.int_option("chunk_size", 1000, minimum=1)

        try:
            for offset in range(0, len(rows), chunk_size):
                # executemany: one round trip per chunk instead of per row.
                self._connection.execute(text(statement), rows[offset : offset + chunk_size])
        except SQLAlchemyError as exc:
            raise LoadingError(
                "insert failed; the transaction will be rolled back",
                context={
                    "connector": self.name,
                    "table": self.table_name,
                    "detail": str(exc.__cause__ or exc)[:300],
                },
                cause=exc,
            ) from exc

        self.rows_written += len(rows)
        return len(rows)

    def _prepare(self, batch: RecordBatch) -> None:
        assert self._connection is not None
        configured = self.list_option("columns")
        self._columns = configured or list(batch.columns())
        if not self._columns:
            raise LoadingError("cannot determine target columns", context={"sink": self.name})
        for column in self._columns:
            validate_identifier(column, kind="column")

        if self.bool_option("create_table", False):
            self._create_table_if_missing(batch)

        if self.mode is LoadMode.OVERWRITE:
            # DELETE, not TRUNCATE: stays inside the transaction.
            self._connection.execute(
                text(f"DELETE FROM {self.quoted_table}")  # noqa: S608 - identifier validated
            )
            logger.info("cleared %s for overwrite load", self.table_name)
        elif self.mode is LoadMode.ERROR_IF_EXISTS:
            existing = self._connection.execute(
                text(f"SELECT 1 FROM {self.quoted_table} LIMIT 1")  # noqa: S608
            ).first()
            if existing is not None:
                raise LoadingError(
                    "target table is not empty and mode is error_if_exists",
                    context={"table": self.table_name},
                )
        self._prepared = True

    def _create_table_if_missing(self, batch: RecordBatch) -> None:
        """Create a permissive table from the inferred schema.

        Convenience for staging/landing zones only.  Production targets should
        be created by a migration - a pipeline inferring DDL from a sample is
        how a column ends up as TEXT forever.
        """
        assert self._connection is not None
        schema = batch.infer_schema()
        sql_types = {
            FieldType.INTEGER: "BIGINT",
            FieldType.FLOAT: "DOUBLE PRECISION" if self._dialect != "mysql" else "DOUBLE",
            FieldType.BOOLEAN: "BOOLEAN",
            FieldType.DATETIME: "TIMESTAMP",
            FieldType.DATE: "DATE",
            FieldType.DECIMAL: "NUMERIC(38, 9)",
        }
        definitions = []
        for column in self._columns:
            field = schema.get(column)
            column_type = sql_types.get(field.type if field else FieldType.UNKNOWN, "TEXT")
            definitions.append(f"{quote_identifier(column, dialect=self._dialect)} {column_type}")
        statement = f"CREATE TABLE IF NOT EXISTS {self.quoted_table} ({', '.join(definitions)})"
        self._connection.execute(text(statement))
        logger.info("ensured table %s exists", self.table_name)

    def _insert_statement(self) -> str:
        quoted_columns = [quote_identifier(c, dialect=self._dialect) for c in self._columns]
        placeholders = [f":{c}" for c in self._columns]
        base = (
            f"INSERT INTO {self.quoted_table} ({', '.join(quoted_columns)}) "  # noqa: S608
            f"VALUES ({', '.join(placeholders)})"
        )
        if self.mode is not LoadMode.UPSERT:
            return base

        key_columns = self.list_option("key_columns")
        if not key_columns:
            raise ConfigurationError(
                "mode 'upsert' requires 'key_columns'", context={"sink": self.name}
            )
        for column in key_columns:
            validate_identifier(column, kind="column")

        updatable = [c for c in self._columns if c not in key_columns]
        if self._dialect == "mysql":
            quoted = {c: quote_identifier(c, dialect="mysql") for c in updatable}
            assignments = ", ".join(f"{q}=VALUES({q})" for q in quoted.values())
            return f"{base} ON DUPLICATE KEY UPDATE {assignments}" if assignments else base

        conflict = ", ".join(quote_identifier(c) for c in key_columns)
        if not updatable:
            return f"{base} ON CONFLICT ({conflict}) DO NOTHING"
        assignments = ", ".join(
            f"{quote_identifier(c)}=EXCLUDED.{quote_identifier(c)}" for c in updatable
        )
        return f"{base} ON CONFLICT ({conflict}) DO UPDATE SET {assignments}"

    def commit(self) -> None:
        if self._transaction is not None:
            self._transaction.commit()
            self._transaction = None
            logger.info("committed %d rows to %s", self.rows_written, self.str_option("table", "?"))

    def rollback(self) -> None:
        if self._transaction is not None:
            self._transaction.rollback()
            self._transaction = None
            logger.warning("rolled back %d rows for %s", self.rows_written, self.name)
        self.rows_written = 0

    def _on_close(self) -> None:
        if self._transaction is not None:
            # Neither commit nor rollback was called: fail closed.
            self._transaction.rollback()
            self._transaction = None
        if self._connection is not None:
            self._connection.close()
            self._connection = None
        if self._engine is not None:
            self._engine.dispose()
            self._engine = None


def _adapt(value: Any) -> Any:
    """Convert values the DB-API drivers do not accept natively."""
    if isinstance(value, (dict, list)):
        import json

        return json.dumps(value, ensure_ascii=False, default=str)
    if isinstance(value, set):
        return ",".join(sorted(str(v) for v in value))
    return value


def execute_statement(
    engine: Engine, statement: str, params: Sequence[dict[str, Any]] | dict[str, Any] | None = None
) -> int:
    """Run a statement in its own transaction; returns the affected row count.

    Used by ``type: sql`` tasks (post-load ``ANALYZE``, marker table updates).
    """
    with engine.begin() as connection:
        result = connection.execute(text(statement), params or {})
        return int(result.rowcount) if result.rowcount is not None else 0


__all__ = ["SqlSink", "SqlSource", "execute_statement"]
