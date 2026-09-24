"""Final uncovered paths: SQL dialects, columnar edge cases, CLI entry point."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from ironflow.config.models import ConnectorSpec, TransformSpec
from ironflow.core.errors import (
    ConfigurationError,
    LoadingError,
    SecretError,
    SecurityError,
)
from ironflow.core.errors import ConnectionError as IFConnectionError
from ironflow.core.retry import RetryPolicy, retryable
from ironflow.core.types import RecordBatch
from ironflow.security.masking import (
    is_redactable,
    looks_like_pii,
    mask,
    mask_auto,
    redact_value,
)
from ironflow.transformation.base import build_transformation


def spec(connector_type: str, **options) -> ConnectorSpec:
    return ConnectorSpec.model_validate({"type": connector_type, **options})


def read_all(source, context) -> list[dict]:
    source.open(context)
    try:
        return [record for batch in source.read(context) for record in batch]
    finally:
        source.close()


class TestSqlDialects:
    def test_postgres_url_is_assembled_from_parts(self, factory, monkeypatch):
        monkeypatch.setenv("PGUSER", "svc")
        monkeypatch.setenv("PGPASSWORD", "p@ss/word")
        connector = factory.create_source(
            spec(
                "postgres",
                host="db.internal",
                port=5432,
                database="warehouse",
                user="env:PGUSER",
                password="env:PGPASSWORD",
            )
        )
        url = connector._build_url()
        assert url.startswith("postgresql+psycopg://svc:")
        assert "p%40ss%2Fword" in url, "credentials must be percent-encoded"
        assert url.endswith("@db.internal:5432/warehouse")

    def test_mysql_driver_and_quoting(self, factory):
        connector = factory.create_source(
            spec("mysql", host="h", database="d", user="u", password="p", table="t")
        )
        assert connector._build_url().startswith("mysql+pymysql://")
        assert connector._dialect == "mysql"

    def test_dsn_takes_precedence(self, factory, monkeypatch):
        monkeypatch.setenv("DSN", "postgresql+psycopg://u:p@h/db")
        connector = factory.create_source(spec("postgres", dsn="env:DSN", database="ignored"))
        assert connector._build_url() == "postgresql+psycopg://u:p@h/db"

    def test_missing_driver_is_reported_actionably(self, factory):
        """Without psycopg installed the failure must name the cause, not traceback."""
        pytest.importorskip("sqlalchemy")
        connector = factory.create_source(
            spec("postgres", host="h", database="d", user="u", password="p", table="t")
        )
        try:
            engine = connector._create_engine()
        except IFConnectionError as exc:
            assert "psycopg" in str(exc)
            assert "p" not in exc.context["url"].split("@")[0].split(":")[-1], (
                "the password must be redacted in the error context"
            )
        else:
            assert engine.dialect.name == "postgresql"
            engine.dispose()

    def test_upsert_statement_for_postgres(self, factory, tmp_path: Path, context):
        sink = factory.create_sink(
            spec(
                "sqlite",
                database=str(tmp_path / "w.db"),
                table="t",
                mode="upsert",
                key_columns=["id"],
                columns=["id", "v"],
            )
        )
        sink._columns = ["id", "v"]
        statement = sink._insert_statement()
        assert "ON CONFLICT" in statement
        assert "EXCLUDED" in statement

    def test_upsert_with_only_key_columns_does_nothing(self, factory, tmp_path: Path):
        sink = factory.create_sink(
            spec(
                "sqlite",
                database=str(tmp_path / "w.db"),
                table="t",
                mode="upsert",
                key_columns=["id"],
                columns=["id"],
            )
        )
        sink._columns = ["id"]
        assert "DO NOTHING" in sink._insert_statement()

    def test_upsert_statement_for_mysql(self, factory):
        sink = factory.create_sink(
            spec(
                "mysql",
                host="h",
                database="d",
                table="t",
                mode="upsert",
                key_columns=["id"],
                columns=["id", "v"],
            )
        )
        sink._columns = ["id", "v"]
        assert "ON DUPLICATE KEY UPDATE" in sink._insert_statement()

    def test_order_by_and_limit(self, factory, tmp_path: Path, context):
        database = tmp_path / "w.db"
        seed = factory.create_sink(
            spec("sqlite", database=str(database), table="t", create_table=True, mode="overwrite")
        )
        seed.open(context)
        seed.write(RecordBatch([{"id": 3}, {"id": 1}, {"id": 2}]), context)
        seed.commit()
        seed.close()

        source = factory.create_source(
            spec("sqlite", database=str(database), table="t", order_by=["id desc"], limit=2)
        )
        assert [r["id"] for r in read_all(source, context)] == [3, 2]

    def test_invalid_order_by_column_is_blocked(self, factory, tmp_path: Path):
        source = factory.create_source(
            spec(
                "sqlite",
                database=str(tmp_path / "w.db"),
                table="t",
                order_by=["id; DROP TABLE t"],
            )
        )
        with pytest.raises(SecurityError):
            source.build_statement()

    def test_column_projection(self, factory, tmp_path: Path, context):
        database = tmp_path / "w.db"
        seed = factory.create_sink(
            spec("sqlite", database=str(database), table="t", create_table=True, mode="overwrite")
        )
        seed.open(context)
        seed.write(RecordBatch([{"id": 1, "secret": "x"}]), context)
        seed.commit()
        seed.close()

        source = factory.create_source(
            spec("sqlite", database=str(database), table="t", columns=["id"])
        )
        assert read_all(source, context) == [{"id": 1}]

    def test_nested_values_are_json_encoded(self, factory, tmp_path: Path, context):
        database = tmp_path / "w.db"
        sink = factory.create_sink(
            spec("sqlite", database=str(database), table="t", create_table=True, mode="overwrite")
        )
        sink.open(context)
        sink.write(RecordBatch([{"id": 1, "tags": ["a", "b"], "meta": {"k": "v"}}]), context)
        sink.commit()
        sink.close()

        rows = read_all(
            factory.create_source(spec("sqlite", database=str(database), table="t")), context
        )
        assert rows[0]["tags"] == '["a", "b"]'

    def test_error_if_exists_on_a_non_empty_table(self, factory, tmp_path: Path, context):
        database = tmp_path / "w.db"
        seed = factory.create_sink(
            spec("sqlite", database=str(database), table="t", create_table=True, mode="overwrite")
        )
        seed.open(context)
        seed.write(RecordBatch([{"id": 1}]), context)
        seed.commit()
        seed.close()

        sink = factory.create_sink(
            spec("sqlite", database=str(database), table="t", mode="error_if_exists")
        )
        sink.open(context)
        with pytest.raises(LoadingError, match="not empty"):
            sink.write(RecordBatch([{"id": 2}]), context)
        sink.close()

    def test_bad_query_is_reported(self, factory, tmp_path: Path, context):
        source = factory.create_source(
            spec("sqlite", database=str(tmp_path / "w.db"), query="SELECT * FROM missing_table")
        )
        source.open(context)
        with pytest.raises(Exception, match="query execution failed"):
            list(source.read(context))
        source.close()

    def test_describe_of_a_query_source_is_empty(self, factory, tmp_path: Path, context):
        source = factory.create_source(
            spec("sqlite", database=str(tmp_path / "w.db"), query="SELECT 1 AS a")
        )
        source.open(context)
        assert source.describe().fields == ()
        assert source.count() is None
        source.close()

    def test_execute_statement_helper(self, factory, tmp_path: Path, context):
        from ironflow.connectors.sql import execute_statement

        database = tmp_path / "w.db"
        seed = factory.create_sink(
            spec("sqlite", database=str(database), table="t", create_table=True, mode="overwrite")
        )
        seed.open(context)
        seed.write(RecordBatch([{"id": 1}, {"id": 2}]), context)
        seed.commit()
        engine = seed._create_engine()
        seed.close()
        try:
            assert execute_statement(engine, "DELETE FROM t WHERE id = 1") == 1
        finally:
            engine.dispose()


class TestColumnarEdgeCases:
    def test_parquet_schema_evolution_is_reported(self, factory, tmp_path: Path, context):
        pytest.importorskip("pyarrow")
        sink = factory.create_sink(spec("parquet", path=str(tmp_path / "d.parquet")))
        sink.open(context)
        sink.write(RecordBatch([{"a": 1}]), context)
        with pytest.raises(LoadingError, match="incompatible with the file schema"):
            sink.write(RecordBatch([{"a": "text", "b": [1, 2]}]), context)
        sink.rollback()
        sink.close()

    def test_parquet_append_is_refused(self, factory, tmp_path: Path):
        """A Parquet file cannot be appended to; 'append' used to replace it."""
        pytest.importorskip("pyarrow")
        with pytest.raises(ConfigurationError, match="does not support mode 'append'"):
            factory.create_sink(spec("parquet", path=str(tmp_path / "d.parquet"), mode="append"))

    def test_parquet_error_if_exists(self, factory, tmp_path: Path, context):
        pytest.importorskip("pyarrow")
        target = tmp_path / "d.parquet"
        target.write_bytes(b"stub")
        sink = factory.create_sink(spec("parquet", path=str(target), mode="error_if_exists"))
        with pytest.raises(LoadingError, match="already exists"):
            sink.open(context)

    def test_excel_sheet_selection_by_name_and_index(self, factory, tmp_path: Path, context):
        openpyxl = pytest.importorskip("openpyxl")
        path = tmp_path / "wb.xlsx"
        workbook = openpyxl.Workbook()
        workbook.active.title = "First"
        workbook.active.append(["a"])
        workbook.active.append([1])
        second = workbook.create_sheet("Second")
        second.append(["b"])
        second.append([2])
        workbook.save(path)

        assert read_all(
            factory.create_source(spec("excel", path=str(path), sheet="Second")), context
        ) == [{"b": 2}]
        assert read_all(factory.create_source(spec("excel", path=str(path), sheet=1)), context) == [
            {"b": 2}
        ]

    def test_excel_unknown_sheet_lists_the_options(self, factory, tmp_path: Path, context):
        openpyxl = pytest.importorskip("openpyxl")
        path = tmp_path / "wb.xlsx"
        workbook = openpyxl.Workbook()
        workbook.active.append(["a"])
        workbook.save(path)
        source = factory.create_source(spec("excel", path=str(path), sheet="Nope"))
        with pytest.raises(Exception, match="worksheet not found"):
            read_all(source, context)

    def test_excel_sheet_index_out_of_range(self, factory, tmp_path: Path, context):
        openpyxl = pytest.importorskip("openpyxl")
        path = tmp_path / "wb.xlsx"
        openpyxl.Workbook().save(path)
        source = factory.create_source(spec("excel", path=str(path), sheet=99))
        with pytest.raises(Exception, match="out of range"):
            read_all(source, context)

    def test_excel_header_row_and_skip_rows(self, factory, tmp_path: Path, context):
        openpyxl = pytest.importorskip("openpyxl")
        path = tmp_path / "wb.xlsx"
        workbook = openpyxl.Workbook()
        sheet = workbook.active
        sheet.append(["report title"])
        sheet.append(["id", "name"])
        sheet.append([1, "Alice"])
        sheet.append([2, "Bob"])
        workbook.save(path)

        rows = read_all(
            factory.create_source(spec("excel", path=str(path), header_row=2, skip_rows=1)),
            context,
        )
        assert rows == [{"id": 2, "name": "Bob"}]

    def test_excel_error_if_exists(self, factory, tmp_path: Path, context):
        pytest.importorskip("openpyxl")
        target = tmp_path / "d.xlsx"
        target.write_bytes(b"stub")
        sink = factory.create_sink(spec("excel", path=str(target), mode="error_if_exists"))
        with pytest.raises(LoadingError, match="already exists"):
            sink.open(context)


class TestRetryDecorator:
    def test_decorator_retries(self):
        attempts = {"n": 0}

        @retryable(RetryPolicy(max_attempts=3, initial_delay=0, jitter=False))
        def flaky():
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise IFConnectionError("down")
            return "ok"

        assert flaky() == "ok"
        assert attempts["n"] == 3

    def test_disabled_policy_raises_the_original(self):
        with pytest.raises(IFConnectionError):
            from ironflow.core.retry import call_with_retry

            call_with_retry(
                lambda: (_ for _ in ()).throw(IFConnectionError("down")),
                RetryPolicy.disabled(),
            )

    def test_negative_delays_are_rejected(self):
        with pytest.raises(ValueError, match="non-negative"):
            RetryPolicy(initial_delay=-1)


class TestMaskingHelpers:
    @pytest.mark.parametrize(
        ("value", "detected"),
        [
            ("a@b.com", True),
            ("4111111111111111", True),
            ("10.0.0.1", True),
            ("+31 20 123 4567", True),
            ("ordinary text", False),
            ("", False),
        ],
    )
    def test_pii_detection(self, value, detected):
        assert looks_like_pii(value) is detected

    def test_is_redactable_ignores_scalars(self):
        assert not is_redactable(True)
        assert not is_redactable(42)
        assert not is_redactable(None)
        assert is_redactable("value")

    def test_redact_value_leaves_booleans_alone(self):
        """Blanking a policy flag hides information and protects nothing."""
        assert redact_value("allow_literal_secrets", False) is False
        assert redact_value("password", "hunter2") == "***REDACTED***"

    def test_mask_with_a_custom_character(self):
        assert mask("1234567890", keep_end=2, mask_char="#") == "########90"

    def test_mask_of_an_empty_value(self):
        assert mask("") == ""

    def test_mask_auto_falls_back_to_partial(self):
        assert mask_auto("some-long-identifier").endswith("fier")


class TestTransformationBaseHelpers:
    def test_required_option_is_enforced(self):
        with pytest.raises(ConfigurationError, match="requires option 'mapping'"):
            build_transformation(TransformSpec.model_validate({"type": "rename"}))

    def test_list_option_accepts_a_csv_string(self):
        transform = build_transformation(
            TransformSpec.model_validate({"type": "drop", "columns": "a, b, c"})
        )
        assert transform._columns == {"a", "b", "c"}

    def test_dict_option_type_is_checked(self):
        with pytest.raises(ConfigurationError, match="must be a mapping"):
            build_transformation(
                TransformSpec.model_validate({"type": "rename", "mapping": ["not", "a", "map"]})
            )

    def test_int_option_type_is_checked(self):
        with pytest.raises(ConfigurationError, match="must be an integer"):
            build_transformation(
                TransformSpec.model_validate({"type": "flatten", "max_depth": "deep"})
            )

    def test_repr_is_useful(self):
        transform = build_transformation(
            TransformSpec.model_validate({"type": "drop", "name": "strip_pii", "columns": ["a"]})
        )
        assert "strip_pii" in repr(transform)


class TestConnectorBaseHelpers:
    def test_bool_option_parsing(self, factory):
        connector = factory.create_source(spec("csv", path="x.csv", has_header="yes"))
        assert connector.bool_option("has_header", False) is True
        assert connector.bool_option("absent", True) is True

    def test_int_option_bounds(self, factory):
        connector = factory.create_source(spec("csv", path="x.csv", batch=5))
        with pytest.raises(ConfigurationError, match="between"):
            connector.int_option("batch", 5, minimum=10, maximum=20)

    def test_list_option_type_is_checked(self, factory):
        connector = factory.create_source(spec("csv", path="x.csv", columns={"a": 1}))
        with pytest.raises(ConfigurationError, match="must be a list"):
            connector.list_option("columns")

    def test_close_is_idempotent(self, factory, context):
        connector = factory.create_source(spec("memory", records=[]))
        connector.open(context)
        connector.close()
        connector.close()

    def test_open_is_idempotent(self, factory, context):
        connector = factory.create_source(spec("memory", records=[]))
        connector.open(context)
        connector.open(context)
        connector.close()

    def test_repr(self, factory):
        assert "csv" in repr(factory.create_source(spec("csv", path="x.csv")))

    def test_batch_size_falls_back_to_settings(self, factory):
        connector = factory.create_source(spec("csv", path="x.csv"))
        assert connector.batch_size == factory.settings.default_batch_size

    def test_retry_policy_from_the_spec(self, factory):
        connector = factory.create_source(
            spec("csv", path="x.csv", retry={"max_attempts": 7, "jitter": False})
        )
        assert connector.retry_policy.max_attempts == 7

    def test_non_transactional_rollback_warns(self, factory, context, caplog):
        sink = factory.create_sink(
            spec("rest", url="https://api.example.com/x", allow_private_network=True)
        )
        sink.rows_written = 0
        sink.rollback()  # nothing written: silent

    def test_write_before_open_is_rejected(self, factory, context):
        sink = factory.create_sink(spec("memory", buffer="x"))
        with pytest.raises(LoadingError, match="not opened"):
            sink.write(RecordBatch([{"a": 1}]), context)


class TestCliEntryPoint:
    def test_successful_command_exits_zero(self, monkeypatch, capsys):
        """Typer runs standalone and calls sys.exit itself."""
        from ironflow.cli.main import main

        monkeypatch.setattr(sys, "argv", ["ironflow", "version"])
        with pytest.raises(SystemExit) as info:
            main()
        assert info.value.code == 0
        assert "IronFlow" in capsys.readouterr().out

    def test_main_maps_configuration_errors(self, monkeypatch, capsys):
        import ironflow.cli.main as main_module

        def explode():
            raise ConfigurationError("bad config")

        monkeypatch.setattr(main_module, "app", explode)
        assert main_module.main() == 2
        assert "bad config" in capsys.readouterr().err

    def test_main_maps_platform_errors(self, monkeypatch, capsys):
        import ironflow.cli.main as main_module

        def explode():
            raise SecretError("no key")

        monkeypatch.setattr(main_module, "app", explode)
        # SecretError subclasses ConfigurationError, so it maps to exit code 2.
        assert main_module.main() == 2

    def test_main_maps_generic_platform_errors(self, monkeypatch, capsys):
        import ironflow.cli.main as main_module

        def explode():
            raise IFConnectionError("database unreachable")

        monkeypatch.setattr(main_module, "app", explode)
        assert main_module.main() == 1
        assert "database unreachable" in capsys.readouterr().err

    def test_main_handles_keyboard_interrupt(self, monkeypatch, capsys):
        import ironflow.cli.main as main_module

        def explode():
            raise KeyboardInterrupt

        monkeypatch.setattr(main_module, "app", explode)
        assert main_module.main() == 130
        assert "interrupted" in capsys.readouterr().err

    def test_module_entry_point_is_importable(self):
        import ironflow.__main__ as entry

        assert callable(entry.main)
