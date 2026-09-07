"""Connector tests: file formats, SQL, HTTP and the in-memory connectors."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from ironflow.config.models import ConnectorSpec
from ironflow.connectors.base import SINK_REGISTRY, SOURCE_REGISTRY
from ironflow.connectors.factory import describe_connectors
from ironflow.connectors.http import RateLimiter, _parse_link_header
from ironflow.connectors.memory import MemorySink, MemorySource
from ironflow.core.errors import (
    AuthenticationError,
    ConfigurationError,
    ExtractionError,
    LoadingError,
    SecurityError,
)
from ironflow.core.types import FieldType, RecordBatch

pytestmark = pytest.mark.integration


def spec(connector_type: str, **options) -> ConnectorSpec:
    return ConnectorSpec.model_validate({"type": connector_type, **options})


def read_all(source, context) -> list[dict]:
    source.open(context)
    try:
        return [record for batch in source.read(context) for record in batch]
    finally:
        source.close()


def write_all(sink, records, context, *, commit: bool = True) -> None:
    sink.open(context)
    try:
        sink.write(RecordBatch(records), context)
        if commit:
            sink.commit()
        else:
            sink.rollback()
    finally:
        sink.close()


class TestRegistries:
    def test_core_connectors_are_registered(self):
        for name in ("csv", "json", "xml", "sql", "sqlite", "postgres", "rest", "memory"):
            assert name in SOURCE_REGISTRY, f"{name} source missing"
            assert name in SINK_REGISTRY, f"{name} sink missing"

    def test_describe_connectors_groups_aliases(self):
        catalogue = describe_connectors()
        rest = next(e for e in catalogue["sources"] if e["class"] == "RestSource")
        assert "rest" in rest["types"] and "http" in rest["types"]

    def test_unknown_type_is_reported_with_alternatives(self, factory):
        problems = factory.validate(spec("nosuchthing"), kind="source")
        assert problems and "unknown source type" in problems[0]


class TestCsv:
    def test_round_trip(self, factory, context, tmp_path: Path, sample_records):
        target = tmp_path / "out.csv"
        write_all(factory.create_sink(spec("csv", path=str(target))), sample_records, context)
        rows = read_all(factory.create_source(spec("csv", path=str(target))), context)
        assert len(rows) == 5
        assert rows[0]["name"] == "Alice"

    def test_null_tokens_become_none(self, factory, context, csv_file):
        rows = read_all(factory.create_source(spec("csv", path=str(csv_file))), context)
        assert rows[4]["amount"] is None

    def test_custom_delimiter(self, factory, context, tmp_path: Path):
        path = tmp_path / "semi.csv"
        path.write_text("a;b\n1;2\n", encoding="utf-8")
        rows = read_all(factory.create_source(spec("csv", path=str(path), delimiter=";")), context)
        assert rows == [{"a": "1", "b": "2"}]

    def test_multi_character_delimiter_is_rejected(self, factory, context, csv_file):
        source = factory.create_source(spec("csv", path=str(csv_file), delimiter="||"))
        with pytest.raises(ConfigurationError, match="single character"):
            read_all(source, context)

    def test_headerless_files_use_configured_columns(self, factory, context, tmp_path: Path):
        path = tmp_path / "raw.csv"
        path.write_text("1,Alice\n2,Bob\n", encoding="utf-8")
        rows = read_all(
            factory.create_source(
                spec("csv", path=str(path), columns=["id", "name"], has_header=False)
            ),
            context,
        )
        assert rows == [{"id": "1", "name": "Alice"}, {"id": "2", "name": "Bob"}]

    def test_formula_injection_is_neutralised(self, factory, context, tmp_path: Path):
        target = tmp_path / "out.csv"
        write_all(
            factory.create_sink(spec("csv", path=str(target))),
            [{"payload": '=cmd|" /c calc"!A1'}, {"payload": "+1+1"}, {"payload": "@SUM(A1)"}],
            context,
        )
        content = target.read_text(encoding="utf-8")
        for line in content.splitlines()[1:]:
            assert line.startswith(("'", '"')), f"unescaped formula: {line}"

    def test_rollback_publishes_nothing(self, factory, context, tmp_path: Path, sample_records):
        target = tmp_path / "out.csv"
        write_all(
            factory.create_sink(spec("csv", path=str(target))),
            sample_records,
            context,
            commit=False,
        )
        assert not target.exists()
        assert not list(tmp_path.glob("*staging*")), "staging file must be cleaned up"

    def test_overwrite_replaces_atomically(self, factory, context, tmp_path: Path):
        target = tmp_path / "out.csv"
        target.write_text("stale,data\n1,2\n", encoding="utf-8")
        write_all(
            factory.create_sink(spec("csv", path=str(target), mode="overwrite")),
            [{"a": 1}],
            context,
        )
        assert "stale" not in target.read_text(encoding="utf-8")

    def test_append_preserves_existing_rows(self, factory, context, tmp_path: Path):
        target = tmp_path / "out.csv"
        write_all(factory.create_sink(spec("csv", path=str(target))), [{"a": 1}], context)
        write_all(
            factory.create_sink(spec("csv", path=str(target), mode="append")), [{"a": 2}], context
        )
        lines = target.read_text(encoding="utf-8").strip().splitlines()
        assert lines == ["a", "1", "2"], "the header must not be repeated"

    def test_error_if_exists(self, factory, context, tmp_path: Path):
        target = tmp_path / "out.csv"
        target.write_text("x\n", encoding="utf-8")
        sink = factory.create_sink(spec("csv", path=str(target), mode="error_if_exists"))
        with pytest.raises(LoadingError, match="already exists"):
            sink.open(context)

    def test_schema_inference(self, factory, context, csv_file):
        schema = factory.create_source(spec("csv", path=str(csv_file))).describe()
        assert schema.names == ("id", "name", "email", "amount", "region")

    def test_size_limit(self, factory, context, csv_file):
        source = factory.create_source(spec("csv", path=str(csv_file), max_bytes=10))
        with pytest.raises(ExtractionError, match="size limit"):
            read_all(source, context)

    def test_path_traversal_is_blocked(self, factory, context):
        source = factory.create_source(spec("csv", path="../../../../etc/passwd"))
        with pytest.raises(SecurityError):
            read_all(source, context)

    def test_missing_path_option_is_actionable(self, factory, context):
        with pytest.raises(ConfigurationError, match="requires option 'path'"):
            read_all(factory.create_source(spec("csv")), context)


class TestJson:
    def test_jsonl_round_trip(self, factory, context, tmp_path: Path, sample_records):
        target = tmp_path / "d.jsonl"
        write_all(factory.create_sink(spec("json", path=str(target))), sample_records, context)
        assert len(target.read_text(encoding="utf-8").strip().splitlines()) == 5
        assert len(read_all(factory.create_source(spec("json", path=str(target))), context)) == 5

    def test_json_array_round_trip(self, factory, context, tmp_path: Path, sample_records):
        target = tmp_path / "d.json"
        write_all(factory.create_sink(spec("json", path=str(target))), sample_records, context)
        assert json.loads(target.read_text(encoding="utf-8"))[0]["name"] == "Alice"
        assert len(read_all(factory.create_source(spec("json", path=str(target))), context)) == 5

    def test_root_path_extraction(self, factory, context, tmp_path: Path):
        path = tmp_path / "api.json"
        path.write_text(json.dumps({"data": {"items": [{"a": 1}, {"a": 2}]}}), encoding="utf-8")
        rows = read_all(
            factory.create_source(spec("json", path=str(path), root="data.items")), context
        )
        assert rows == [{"a": 1}, {"a": 2}]

    def test_missing_root_is_reported(self, factory, context, tmp_path: Path):
        path = tmp_path / "api.json"
        path.write_text('{"data": []}', encoding="utf-8")
        source = factory.create_source(spec("json", path=str(path), root="nope.here"))
        with pytest.raises(ExtractionError, match="root path not found"):
            read_all(source, context)

    def test_malformed_line_reports_its_number(self, factory, context, tmp_path: Path):
        path = tmp_path / "bad.jsonl"
        path.write_text('{"a": 1}\nnot json\n', encoding="utf-8")
        source = factory.create_source(spec("json", path=str(path), format="lines"))
        with pytest.raises(ExtractionError) as info:
            read_all(source, context)
        assert info.value.context["line"] == 2

    def test_lenient_mode_skips_bad_lines(self, factory, context, tmp_path: Path):
        path = tmp_path / "bad.jsonl"
        path.write_text('{"a": 1}\nnot json\n{"a": 2}\n', encoding="utf-8")
        rows = read_all(
            factory.create_source(spec("json", path=str(path), format="lines", strict=False)),
            context,
        )
        assert rows == [{"a": 1}, {"a": 2}]


class TestXml:
    def test_round_trip(self, factory, context, tmp_path: Path):
        target = tmp_path / "d.xml"
        write_all(
            factory.create_sink(spec("xml", path=str(target), record_tag="row")),
            [{"id": 1, "name": "Alice"}],
            context,
        )
        rows = read_all(
            factory.create_source(spec("xml", path=str(target), record_tag="row")), context
        )
        assert rows == [{"id": "1", "name": "Alice"}]

    def test_attributes_are_captured(self, factory, context, tmp_path: Path):
        path = tmp_path / "d.xml"
        path.write_text('<root><row id="7"><name>Alice</name></row></root>', encoding="utf-8")
        rows = read_all(
            factory.create_source(spec("xml", path=str(path), record_tag="row")), context
        )
        assert rows == [{"@id": "7", "name": "Alice"}]

    def test_repeated_tags_become_a_list(self, factory, context, tmp_path: Path):
        path = tmp_path / "d.xml"
        path.write_text("<root><row><t>a</t><t>b</t></row></root>", encoding="utf-8")
        rows = read_all(
            factory.create_source(spec("xml", path=str(path), record_tag="row")), context
        )
        assert rows == [{"t": ["a", "b"]}]

    def test_billion_laughs_is_blocked(self, factory, context, tmp_path: Path):
        """defusedxml must refuse the classic entity-expansion bomb."""
        path = tmp_path / "bomb.xml"
        path.write_text(
            """<?xml version="1.0"?>
<!DOCTYPE lolz [
 <!ENTITY lol "lol">
 <!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
 <!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">
]>
<root><row><v>&lol2;</v></row></root>""",
            encoding="utf-8",
        )
        source = factory.create_source(spec("xml", path=str(path), record_tag="row"))
        with pytest.raises(Exception) as info:
            read_all(source, context)
        assert "Entit" in type(info.value).__name__ or "entit" in str(info.value).lower()

    def test_external_entity_is_blocked(self, factory, context, tmp_path: Path):
        """XXE: reading a local file through an external entity reference."""
        secret = tmp_path / "secret.txt"
        secret.write_text("TOP SECRET", encoding="utf-8")
        path = tmp_path / "xxe.xml"
        path.write_text(
            f"""<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY xxe SYSTEM "file://{secret.as_posix()}">]>
<root><row><v>&xxe;</v></row></root>""",
            encoding="utf-8",
        )
        source = factory.create_source(spec("xml", path=str(path), record_tag="row"))
        try:
            rows = read_all(source, context)
        except Exception:
            return  # rejecting outright is the ideal outcome
        assert "TOP SECRET" not in json.dumps(rows), "XXE leaked file contents"

    def test_unsafe_column_names_are_sanitised(self, factory, context, tmp_path: Path):
        target = tmp_path / "d.xml"
        write_all(
            factory.create_sink(spec("xml", path=str(target), record_tag="row")),
            [{"<script>": "x", "1bad": "y"}],
            context,
        )
        content = target.read_text(encoding="utf-8")
        assert "<script>" not in content

    def test_values_are_escaped(self, factory, context, tmp_path: Path):
        target = tmp_path / "d.xml"
        write_all(
            factory.create_sink(spec("xml", path=str(target), record_tag="row")),
            [{"v": "<injected/>"}],
            context,
        )
        assert "&lt;injected/&gt;" in target.read_text(encoding="utf-8")


class TestColumnar:
    def test_parquet_round_trip(self, factory, context, tmp_path: Path):
        pytest.importorskip("pyarrow")
        target = tmp_path / "d.parquet"
        records = [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]
        write_all(factory.create_sink(spec("parquet", path=str(target))), records, context)
        source = factory.create_source(spec("parquet", path=str(target)))
        source.open(context)
        try:
            assert source.count() == 2
            assert source.describe().get("id").type is FieldType.INTEGER
        finally:
            source.close()
        assert (
            read_all(factory.create_source(spec("parquet", path=str(target))), context) == records
        )

    def test_parquet_column_projection(self, factory, context, tmp_path: Path):
        pytest.importorskip("pyarrow")
        target = tmp_path / "d.parquet"
        write_all(
            factory.create_sink(spec("parquet", path=str(target))),
            [{"id": 1, "name": "Alice", "secret": "x"}],
            context,
        )
        rows = read_all(
            factory.create_source(spec("parquet", path=str(target), columns=["id"])), context
        )
        assert rows == [{"id": 1}]

    def test_parquet_rollback_publishes_nothing(self, factory, context, tmp_path: Path):
        pytest.importorskip("pyarrow")
        target = tmp_path / "d.parquet"
        write_all(
            factory.create_sink(spec("parquet", path=str(target))),
            [{"a": 1}],
            context,
            commit=False,
        )
        assert not target.exists()

    def test_excel_round_trip(self, factory, context, tmp_path: Path):
        pytest.importorskip("openpyxl")
        target = tmp_path / "d.xlsx"
        records = [{"id": 1, "name": "Alice"}, {"id": 2, "name": None}]
        write_all(factory.create_sink(spec("excel", path=str(target))), records, context)
        rows = read_all(factory.create_source(spec("excel", path=str(target))), context)
        assert len(rows) == 2
        assert rows[0] == {"id": 1, "name": "Alice"}
        assert rows[1]["name"] is None, "short rows must be padded against the header"

    def test_excel_formula_injection_is_neutralised(self, factory, context, tmp_path: Path):
        pytest.importorskip("openpyxl")
        target = tmp_path / "d.xlsx"
        write_all(factory.create_sink(spec("excel", path=str(target))), [{"v": "=1+1"}], context)
        rows = read_all(factory.create_source(spec("excel", path=str(target))), context)
        assert rows[0]["v"] == "'=1+1"


class TestSql:
    def _db(self, tmp_path: Path) -> str:
        return str(tmp_path / "w.db")

    def test_round_trip_with_table_creation(self, factory, context, tmp_path: Path):
        db = self._db(tmp_path)
        records = [{"id": 1, "name": "Alice"}, {"id": 2, "name": "Bob"}]
        write_all(
            factory.create_sink(
                spec("sqlite", database=db, table="orders", create_table=True, mode="overwrite")
            ),
            records,
            context,
        )
        rows = read_all(factory.create_source(spec("sqlite", database=db, table="orders")), context)
        assert rows == records

    def test_rollback_leaves_the_table_untouched(self, factory, context, tmp_path: Path):
        db = self._db(tmp_path)
        write_all(
            factory.create_sink(
                spec("sqlite", database=db, table="t", create_table=True, mode="overwrite")
            ),
            [{"id": 1}],
            context,
        )
        write_all(
            factory.create_sink(spec("sqlite", database=db, table="t")),
            [{"id": 2}],
            context,
            commit=False,
        )
        rows = read_all(factory.create_source(spec("sqlite", database=db, table="t")), context)
        assert rows == [{"id": 1}], "rollback must undo the second write entirely"

    def test_overwrite_clears_inside_the_transaction(self, factory, context, tmp_path: Path):
        db = self._db(tmp_path)
        create = spec("sqlite", database=db, table="t", create_table=True, mode="overwrite")
        write_all(factory.create_sink(create), [{"id": 1}], context)
        write_all(factory.create_sink(create), [{"id": 2}], context)
        rows = read_all(factory.create_source(spec("sqlite", database=db, table="t")), context)
        assert rows == [{"id": 2}]

    def test_failed_overwrite_does_not_destroy_existing_data(
        self, factory, context, tmp_path: Path
    ):
        """The DELETE must roll back with the failed insert, not commit early."""
        db = self._db(tmp_path)
        write_all(
            factory.create_sink(
                spec("sqlite", database=db, table="t", create_table=True, mode="overwrite")
            ),
            [{"id": 1}],
            context,
        )
        sink = factory.create_sink(spec("sqlite", database=db, table="t", mode="overwrite"))
        sink.open(context)
        try:
            sink.write(RecordBatch([{"id": 2}]), context)
            sink.rollback()
        finally:
            sink.close()
        rows = read_all(factory.create_source(spec("sqlite", database=db, table="t")), context)
        assert rows == [{"id": 1}], "a rolled-back overwrite must preserve the original rows"

    def test_custom_query_with_bound_parameters(self, factory, context, tmp_path: Path):
        db = self._db(tmp_path)
        write_all(
            factory.create_sink(
                spec("sqlite", database=db, table="t", create_table=True, mode="overwrite")
            ),
            [{"id": 1, "region": "EU"}, {"id": 2, "region": "US"}],
            context,
        )
        rows = read_all(
            factory.create_source(
                spec(
                    "sqlite",
                    database=db,
                    query="SELECT * FROM t WHERE region = :region",
                    params={"region": "EU"},
                )
            ),
            context,
        )
        assert rows == [{"id": 1, "region": "EU"}]

    def test_upsert_requires_key_columns(self, factory, context, tmp_path: Path):
        sink = factory.create_sink(
            spec("sqlite", database=self._db(tmp_path), table="t", mode="upsert", create_table=True)
        )
        sink.open(context)
        with pytest.raises(ConfigurationError, match="key_columns"):
            sink.write(RecordBatch([{"id": 1}]), context)
        sink.close()

    @pytest.mark.parametrize("table", ["t; DROP TABLE users--", "t' OR '1'='1", "t UNION SELECT 1"])
    def test_injection_in_table_name_is_blocked(self, factory, context, tmp_path: Path, table):
        sink = factory.create_sink(spec("sqlite", database=self._db(tmp_path), table=table))
        sink.open(context)
        with pytest.raises(SecurityError):
            sink.write(RecordBatch([{"id": 1}]), context)
        sink.close()

    def test_injection_in_column_name_is_blocked(self, factory, context, tmp_path: Path):
        sink = factory.create_sink(
            spec("sqlite", database=self._db(tmp_path), table="t", create_table=True)
        )
        sink.open(context)
        with pytest.raises(SecurityError):
            sink.write(RecordBatch([{"id); DROP TABLE t; --": 1}]), context)
        sink.close()

    def test_injection_in_where_clause_is_blocked(self, factory, context, tmp_path: Path):
        source = factory.create_source(
            spec("sqlite", database=self._db(tmp_path), table="t", where="1=1; DROP TABLE t")
        )
        with pytest.raises(SecurityError):
            source.build_statement()

    def test_values_are_bound_not_interpolated(self, factory, context, tmp_path: Path):
        """A malicious *value* must be stored verbatim, never executed."""
        db = self._db(tmp_path)
        payload = "Robert'); DROP TABLE students;--"
        write_all(
            factory.create_sink(
                spec("sqlite", database=db, table="t", create_table=True, mode="overwrite")
            ),
            [{"name": payload}],
            context,
        )
        rows = read_all(factory.create_source(spec("sqlite", database=db, table="t")), context)
        assert rows == [{"name": payload}]

    def test_table_reflection(self, factory, context, tmp_path: Path):
        db = self._db(tmp_path)
        write_all(
            factory.create_sink(
                spec("sqlite", database=db, table="t", create_table=True, mode="overwrite")
            ),
            [{"id": 1, "name": "x"}],
            context,
        )
        source = factory.create_source(spec("sqlite", database=db, table="t"))
        source.open(context)
        try:
            assert source.describe().names == ("id", "name")
            assert source.count() == 1
        finally:
            source.close()


class TestMemoryConnectors:
    def test_inline_records(self, factory, context):
        rows = read_all(factory.create_source(spec("memory", records=[{"a": 1}])), context)
        assert rows == [{"a": 1}]

    def test_registered_dataset(self, factory, context):
        MemorySource.register("ds", [{"a": 1}, {"a": 2}])
        assert len(read_all(factory.create_source(spec("memory", dataset="ds")), context)) == 2

    def test_sink_publishes_only_on_commit(self, factory, context):
        sink = factory.create_sink(spec("memory", buffer="b1"))
        sink.open(context)
        sink.write(RecordBatch([{"a": 1}]), context)
        assert MemorySink.buffer("b1") == [], "rows must not appear before commit"
        sink.commit()
        assert MemorySink.buffer("b1") == [{"a": 1}]
        sink.close()

    def test_sink_rollback_discards(self, factory, context):
        sink = factory.create_sink(spec("memory", buffer="b2"))
        sink.open(context)
        sink.write(RecordBatch([{"a": 1}]), context)
        sink.rollback()
        sink.close()
        assert MemorySink.buffer("b2") == []

    def test_generator_is_reproducible_with_a_seed(self, factory, context):
        first = read_all(factory.create_source(spec("generator", rows=5, seed=42)), context)
        second = read_all(factory.create_source(spec("generator", rows=5, seed=42)), context)
        assert first == second

    def test_null_sink_counts_without_storing(self, factory, context):
        sink = factory.create_sink(spec("null"))
        sink.open(context)
        sink.write(RecordBatch([{"a": 1}, {"a": 2}]), context)
        sink.commit()
        sink.close()
        assert sink.rows_written == 2


class TestHttp:
    """HTTP behaviour is exercised against a transport stub, never the network."""

    def _stub(self, factory, connector_spec, handler):
        connector = factory.create_source(connector_spec)
        transport = httpx.MockTransport(handler)
        original = connector._build_client

        def build():
            client = original()
            client._transport = transport
            for key in list(client._mounts):
                client._mounts[key] = transport
            return client

        connector._build_client = build
        return connector

    def test_reads_a_json_array(self, factory, context):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json=[{"id": 1}, {"id": 2}])

        source = self._stub(
            factory,
            spec("rest", url="https://api.example.com/items", allow_private_network=True),
            handler,
        )
        assert read_all(source, context) == [{"id": 1}, {"id": 2}]

    def test_data_path_extraction(self, factory, context):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"result": {"records": [{"id": 1}]}})

        source = self._stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/x",
                data_path="result.records",
                allow_private_network=True,
            ),
            handler,
        )
        assert read_all(source, context) == [{"id": 1}]

    def test_page_pagination_stops_on_a_short_page(self, factory, context):
        pages = {0: [{"i": 1}, {"i": 2}], 1: [{"i": 3}]}
        seen = []

        def handler(request: httpx.Request) -> httpx.Response:
            page = int(request.url.params.get("page", 1)) - 1
            seen.append(page)
            return httpx.Response(200, json=pages.get(page, []))

        source = self._stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/x",
                pagination="page",
                page_size=2,
                allow_private_network=True,
            ),
            handler,
        )
        assert len(read_all(source, context)) == 3
        assert seen == [0, 1]

    def test_bearer_auth_header_is_sent(self, factory, context, monkeypatch):
        monkeypatch.setenv("API_TOKEN", "tok-123")
        captured = {}

        def handler(request: httpx.Request) -> httpx.Response:
            captured["auth"] = request.headers.get("authorization")
            return httpx.Response(200, json=[])

        source = self._stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/x",
                auth="bearer",
                token="env:API_TOKEN",
                allow_private_network=True,
            ),
            handler,
        )
        read_all(source, context)
        assert captured["auth"] == "Bearer tok-123"

    def test_401_becomes_an_authentication_error(self, factory, context):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(401, json={"error": "nope"})

        source = self._stub(
            factory,
            spec("rest", url="https://api.example.com/x", allow_private_network=True),
            handler,
        )
        with pytest.raises(AuthenticationError):
            read_all(source, context)

    def test_4xx_is_not_retried(self, factory, context):
        calls = []

        def handler(request: httpx.Request) -> httpx.Response:
            calls.append(1)
            return httpx.Response(422, json={"error": "bad"})

        source = self._stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/x",
                allow_private_network=True,
                retry={"max_attempts": 3, "initial_delay": 0},
            ),
            handler,
        )
        with pytest.raises(ExtractionError):
            read_all(source, context)
        assert len(calls) == 1, "a deterministic 4xx must not be retried"

    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",  # cloud metadata service
            "http://127.0.0.1:8080/admin",
            "http://10.0.0.1/internal",
        ],
    )
    def test_ssrf_guard_blocks_internal_urls(self, factory, context, url):
        # allow_private_network is set explicitly: the test fixture enables it
        # globally so other tests can use a local stub, and inheriting that here
        # would silently neuter the very guard under test.
        source = factory.create_source(spec("rest", url=url, allow_private_network=False))
        with pytest.raises(SecurityError, match="non-public"):
            read_all(source, context)

    def test_pagination_links_are_revalidated(self, factory, context):
        """A 'next' link pointing inside the network must not be followed."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"items": [{"i": 1}], "next": "http://169.254.169.254/latest/meta-data/"},
            )

        source = self._stub(
            factory,
            spec(
                "rest",
                url="https://api.example.com/x",
                data_path="items",
                pagination="link",
                allow_private_network=False,
            ),
            handler,
        )
        with pytest.raises(SecurityError):
            read_all(source, context)

    def test_graphql_errors_are_surfaced(self, factory, context):
        """GraphQL returns HTTP 200 with an errors array; that must not pass."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"errors": [{"message": "field not found"}]})

        source = self._stub(
            factory,
            spec(
                "graphql",
                url="https://api.example.com/graphql",
                query="{ x }",
                allow_private_network=True,
            ),
            handler,
        )
        with pytest.raises(ExtractionError, match="GraphQL"):
            read_all(source, context)

    def test_graphql_unwraps_relay_nodes(self, factory, context):
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200, json={"data": {"items": [{"node": {"id": 1}}, {"node": {"id": 2}}]}}
            )

        source = self._stub(
            factory,
            spec(
                "graphql",
                url="https://api.example.com/graphql",
                query="{ items { node { id } } }",
                data_path="items",
                allow_private_network=True,
            ),
            handler,
        )
        assert read_all(source, context) == [{"id": 1}, {"id": 2}]


class TestRateLimiter:
    def test_allows_a_burst_then_throttles(self):
        limiter = RateLimiter(requests_per_second=100, burst=3)
        assert all(limiter.acquire() == 0.0 for _ in range(3))
        assert limiter.acquire() > 0

    def test_zero_rate_is_unlimited(self):
        limiter = RateLimiter(requests_per_second=0)
        assert all(limiter.acquire() == 0.0 for _ in range(100))


class TestLinkHeader:
    def test_extracts_next(self):
        header = '<https://api/x?page=2>; rel="next", <https://api/x?page=9>; rel="last"'
        assert _parse_link_header(header) == "https://api/x?page=2"

    def test_returns_none_without_next(self):
        assert _parse_link_header('<https://api/x>; rel="last"') is None
        assert _parse_link_header("") is None
