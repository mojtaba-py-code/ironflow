"""Transformation tests: streaming operations, blocking operations, the engine."""

from __future__ import annotations

import pytest

from ironflow.config.models import TransformSpec
from ironflow.core.errors import ConfigurationError, TransformationError
from ironflow.core.types import RecordBatch, batched
from ironflow.security.crypto import CryptoService, generate_key
from ironflow.transformation.base import TRANSFORM_REGISTRY, build_transformation
from ironflow.transformation.engine import TransformationPipeline


def build(transform_type: str, **options):
    return build_transformation(TransformSpec.model_validate({"type": transform_type, **options}))


def apply(transform, records, context) -> list[dict]:
    return transform.apply(RecordBatch(list(records)), context).records


def apply_stream(transform, records, context, batch_size: int = 2) -> list[dict]:
    stream = batched(list(records), batch_size)
    return [r for batch in transform.apply_stream(stream, context) for r in batch]


class TestRegistry:
    def test_expected_transformations_are_registered(self):
        for name in (
            "rename",
            "drop",
            "select",
            "cast",
            "derive",
            "filter",
            "mask_pii",
            "hash_columns",
            "encrypt_columns",
            "sort",
            "aggregate",
            "join",
            "deduplicate",
        ):
            assert name in TRANSFORM_REGISTRY, f"{name} not registered"

    def test_unknown_transformation_is_rejected(self):
        with pytest.raises(Exception, match="unknown transformation type"):
            build("does_not_exist")


class TestColumnShape:
    def test_rename(self, context):
        result = apply(build("rename", mapping={"a": "b"}), [{"a": 1, "c": 2}], context)
        assert result == [{"b": 1, "c": 2}]

    def test_strict_rename_fails_on_a_missing_column(self, context):
        transform = build("rename", mapping={"missing": "x"}, strict=True)
        with pytest.raises(TransformationError, match="not present"):
            apply(transform, [{"a": 1}], context)

    def test_drop(self, context):
        assert apply(build("drop", columns=["b"]), [{"a": 1, "b": 2}], context) == [{"a": 1}]

    def test_select_pins_column_order_and_fills(self, context):
        result = apply(
            build("select", columns=["b", "a", "z"]), [{"a": 1, "b": 2, "c": 3}], context
        )
        assert list(result[0]) == ["b", "a", "z"]
        assert result[0]["z"] is None

    def test_select_without_fill_omits_missing(self, context):
        result = apply(build("select", columns=["a", "z"], fill_missing=False), [{"a": 1}], context)
        assert result == [{"a": 1}]

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("Order Date", "order_date"),
            ("OrderDate", "order_date"),
            ("  Customer   E-Mail ", "customer_e_mail"),
            ("Montréal", "montreal"),
            ("123", "123"),
            ("!!!", "column"),
        ],
    )
    def test_normalize_column_names(self, context, raw, expected):
        assert list(apply(build("normalize_columns"), [{raw: 1}], context)[0]) == [expected]


class TestValues:
    def test_add_column_with_templating(self, context):
        result = apply(
            build("add_column", column="run", value="${execution_id}"), [{"a": 1}], context
        )
        assert result[0]["run"] == context.execution_id

    def test_add_column_respects_overwrite_false(self, context):
        transform = build("add_column", column="a", value="new", overwrite=False)
        assert apply(transform, [{"a": "existing"}], context)[0]["a"] == "existing"

    def test_derive_computes_from_an_expression(self, context):
        transform = build("derive", column="total", expression="round(price * qty, 2)")
        assert apply(transform, [{"price": 2.5, "qty": 4}], context)[0]["total"] == 10.0

    def test_derive_nulls_on_error_by_default(self, context):
        transform = build("derive", column="x", expression="price * qty")
        assert apply(transform, [{"price": "abc", "qty": 2}], context)[0]["x"] is None

    def test_derive_can_fail_hard(self, context):
        transform = build("derive", column="x", expression="price * qty", on_error="fail")
        with pytest.raises(TransformationError):
            apply(transform, [{"price": "abc", "qty": 2}], context)

    def test_derive_can_read_parameters(self, context):
        context.parameters["rate"] = 2
        transform = build("derive", column="x", expression="amount * params.rate")
        assert apply(transform, [{"amount": 5}], context)[0]["x"] == 10

    @pytest.mark.parametrize(
        ("value", "target", "expected"),
        [
            ("42", "integer", 42),
            ("1,234", "integer", 1234),
            ("3.5", "float", 3.5),
            ("true", "boolean", True),
            ("NO", "boolean", False),
            (1, "string", "1"),
            ("2026-01-15T10:30:00", "date", "2026-01-15"),
        ],
    )
    def test_cast(self, context, value, target, expected):
        transform = build("cast", columns={"v": target})
        assert apply(transform, [{"v": value}], context)[0]["v"] == expected

    def test_cast_nulls_unconvertible_values(self, context):
        transform = build("cast", columns={"v": "integer"})
        assert apply(transform, [{"v": "not a number"}], context)[0]["v"] is None

    def test_cast_can_fail_hard(self, context):
        transform = build("cast", columns={"v": "integer"}, on_error="fail")
        with pytest.raises(TransformationError, match="conversion failed"):
            apply(transform, [{"v": "x"}], context)

    def test_cast_rejects_unknown_target_types(self):
        with pytest.raises(ConfigurationError, match="unknown target type"):
            build("cast", columns={"v": "quaternion"})

    def test_cast_leaves_nulls_alone(self, context):
        assert (
            apply(build("cast", columns={"v": "integer"}), [{"v": None}], context)[0]["v"] is None
        )

    def test_fill_null_with_per_column_defaults(self, context):
        transform = build("fill_null", columns={"a": 0, "b": "unknown"})
        assert apply(transform, [{"a": None, "b": "  "}], context) == [{"a": 0, "b": "unknown"}]

    def test_map_values(self, context):
        transform = build("map_values", column="c", mapping={"1": "EUR"}, default="OTHER")
        result = apply(transform, [{"c": 1}, {"c": 9}], context)
        assert [r["c"] for r in result] == ["EUR", "OTHER"]

    def test_string_ops(self, context):
        transform = build(
            "string_ops", columns=["v"], operations=["trim", "collapse_spaces", "upper"]
        )
        assert apply(transform, [{"v": "  a   b  "}], context)[0]["v"] == "A B"

    def test_string_ops_rejects_unknown_operations(self):
        with pytest.raises(ConfigurationError, match="unknown string operation"):
            build("string_ops", columns=["v"], operations=["frobnicate"])

    def test_split_and_concat(self, context):
        split = build("split_column", column="full", separator=" ", into=["first", "last"])
        assert apply(split, [{"full": "Ada Lovelace"}], context) == [
            {"first": "Ada", "last": "Lovelace"}
        ]
        concat = build("concat_columns", columns=["a", "b"], target="j", separator="-")
        assert apply(concat, [{"a": "x", "b": "y"}], context)[0]["j"] == "x-y"

    def test_flatten(self, context):
        transform = build("flatten")
        result = apply(transform, [{"a": {"b": {"c": 1}}, "d": 2}], context)
        assert result == [{"a.b.c": 1, "d": 2}]

    def test_flatten_depth_is_capped(self, context):
        deep = {"l1": {"l2": {"l3": {"l4": {"l5": {"l6": 1}}}}}}
        result = apply(build("flatten", max_depth=2), [deep], context)
        assert any(isinstance(v, dict) for v in result[0].values())


class TestDatesAndCurrency:
    def test_parse_date_normalises_formats(self, context):
        transform = build("parse_date", columns=["d"])
        assert apply(transform, [{"d": "15/03/2026"}], context)[0]["d"].startswith("2026-03-15")

    def test_parse_date_with_explicit_format(self, context):
        transform = build("parse_date", columns=["d"], format="%d.%m.%Y", output_format="%Y-%m-%d")
        assert apply(transform, [{"d": "15.03.2026"}], context)[0]["d"] == "2026-03-15"

    def test_unparseable_date_becomes_null(self, context):
        assert (
            apply(build("parse_date", columns=["d"]), [{"d": "garbage"}], context)[0]["d"] is None
        )

    def test_timezone_conversion(self, context):
        transform = build("convert_timezone", columns=["t"], **{"from": "+02:00", "to": "UTC"})
        assert apply(transform, [{"t": "2026-01-01T12:00:00"}], context)[0]["t"].startswith(
            "2026-01-01T10:00:00"
        )

    def test_unknown_timezone_is_rejected(self):
        with pytest.raises(ConfigurationError, match="unknown timezone"):
            build("convert_timezone", columns=["t"], to="Mars/Olympus_Mons")

    def test_currency_conversion_uses_decimal_arithmetic(self, context):
        transform = build(
            "convert_currency", columns=["amount"], rates={"USD": "0.9"}, currency_column="cur"
        )
        result = apply(transform, [{"amount": "10.10", "cur": "USD"}], context)
        assert result[0]["amount"] == 9.09

    def test_unknown_currency_leaves_the_row_alone(self, context):
        transform = build(
            "convert_currency", columns=["amount"], rates={"USD": 0.9}, currency_column="cur"
        )
        assert apply(transform, [{"amount": 10, "cur": "XYZ"}], context)[0]["amount"] == 10

    def test_currency_requires_a_source(self):
        with pytest.raises(ConfigurationError, match="currency_column"):
            build("convert_currency", columns=["a"], rates={"USD": 1})


class TestFilteringAndMetadata:
    def test_filter_keeps_matching_records(self, context):
        transform = build("filter", expression="amount > 0")
        result = apply(transform, [{"amount": 5}, {"amount": -1}, {"amount": 10}], context)
        assert [r["amount"] for r in result] == [5, 10]
        assert transform.dropped == 1

    def test_filter_invert(self, context):
        transform = build("filter", expression="amount > 0", invert=True)
        assert apply(transform, [{"amount": 5}, {"amount": -1}], context) == [{"amount": -1}]

    def test_add_metadata(self, context):
        transform = build(
            "add_metadata", include=["execution_id", "pipeline_id", "loaded_at", "row_number"]
        )
        result = apply(transform, [{"a": 1}, {"a": 2}], context)
        assert result[0]["_execution_id"] == context.execution_id
        assert result[0]["_pipeline_id"] == context.pipeline_id
        assert result[0]["_loaded_at"]
        assert [r["_row_number"] for r in result] == [1, 2]

    def test_dedupe_batch(self, context):
        transform = build("dedupe_batch", columns=["id"])
        result = apply(transform, [{"id": 1}, {"id": 1}, {"id": 2}], context)
        assert [r["id"] for r in result] == [1, 2]
        assert transform.dropped == 1


class TestPrivacy:
    def test_mask_pii_email(self, context):
        transform = build("mask_pii", columns=["email"], strategy="email")
        assert (
            apply(transform, [{"email": "alice@corp.com"}], context)[0]["email"] == "a****@corp.com"
        )

    def test_mask_pii_auto_detects(self, context):
        transform = build("mask_pii", columns=["v"])
        assert "@" in apply(transform, [{"v": "a@b.com"}], context)[0]["v"]

    def test_mask_pii_full(self, context):
        transform = build("mask_pii", columns=["v"], strategy="full")
        assert apply(transform, [{"v": "secret"}], context)[0]["v"] == "******"

    def test_hash_columns_is_deterministic_and_irreversible(self, context, monkeypatch):
        monkeypatch.setenv("HASH_KEY", "pepper")
        transform = build("hash_columns", columns=["email"], key="env:HASH_KEY")
        first = apply(transform, [{"email": "a@b.com"}], context)[0]["email"]
        second = apply(transform, [{"email": "a@b.com"}], context)[0]["email"]
        assert first == second, "joins downstream depend on determinism"
        assert "a@b.com" not in first
        assert len(first) == 64

    def test_hash_without_a_key_warns_once(self, context, caplog):
        transform = build("hash_columns", columns=["email"])
        with caplog.at_level("WARNING"):
            apply(transform, [{"email": "a@b.com"}, {"email": "c@d.com"}], context)
        assert caplog.text.count("without a key") == 1

    def test_a_weak_digest_is_rejected_when_the_transformation_is_built(self):
        """Built, not applied - so `ironflow pipeline validate` catches it.

        The algorithm is static configuration. Checking it only inside
        `transform_record` meant `validate` said VALID and the run then died on
        the first record, which is the opposite of what a pre-flight check is
        for.
        """
        with pytest.raises(ConfigurationError, match="not allowed"):
            build("hash_columns", columns=["email"], algorithm="md5")

    def test_a_strong_digest_is_accepted(self, context):
        transform = build("hash_columns", columns=["email"], algorithm="sha512")
        assert len(apply(transform, [{"email": "a@b.com"}], context)[0]["email"]) == 128

    def test_hash_can_keep_the_original(self, context):
        transform = build("hash_columns", columns=["email"], keep_original=True)
        result = apply(transform, [{"email": "a@b.com"}], context)[0]
        assert result["email"] == "a@b.com"
        assert len(result["email_hash"]) == 64

    def test_encrypt_columns_round_trips(self, context, monkeypatch):
        key = generate_key()
        monkeypatch.setenv("ENC_KEY", key)
        transform = build("encrypt_columns", columns=["ssn"], key="env:ENC_KEY")
        encrypted = apply(transform, [{"ssn": "123-45-6789"}], context)[0]["ssn"]
        assert "123-45-6789" not in encrypted
        assert CryptoService.from_key(key).decrypt(encrypted) == "123-45-6789"

    def test_encrypt_leaves_nulls_alone(self, context, monkeypatch):
        monkeypatch.setenv("ENC_KEY", generate_key())
        transform = build("encrypt_columns", columns=["ssn"], key="env:ENC_KEY")
        assert apply(transform, [{"ssn": None}], context)[0]["ssn"] is None


class TestBlocking:
    def test_sort_ascending_and_descending(self, context):
        records = [{"n": 3}, {"n": 1}, {"n": 2}]
        assert [r["n"] for r in apply_stream(build("sort", columns=["n"]), records, context)] == [
            1,
            2,
            3,
        ]
        assert [
            r["n"] for r in apply_stream(build("sort", columns=["n desc"]), records, context)
        ] == [3, 2, 1]

    def test_sort_handles_nulls_and_mixed_types(self, context):
        records = [{"n": 3}, {"n": None}, {"n": "a"}, {"n": 1}]
        result = apply_stream(build("sort", columns=["n"]), records, context)
        assert result[-1]["n"] is None, "nulls last by default"

    def test_multi_key_sort_with_mixed_directions(self, context):
        records = [
            {"g": "b", "n": 1},
            {"g": "a", "n": 2},
            {"g": "a", "n": 1},
            {"g": "b", "n": 2},
        ]
        result = apply_stream(build("sort", columns=["g", "n desc"]), records, context)
        assert [(r["g"], r["n"]) for r in result] == [("a", 2), ("a", 1), ("b", 2), ("b", 1)]

    def test_sort_row_cap(self, context):
        transform = build("sort", columns=["n"], max_rows=2)
        with pytest.raises(TransformationError, match="max_rows"):
            apply_stream(transform, [{"n": i} for i in range(10)], context)

    def test_deduplicate_keep_first_streams(self, context):
        transform = build("deduplicate", columns=["id"])
        result = apply_stream(transform, [{"id": 1, "v": "a"}, {"id": 1, "v": "b"}], context)
        assert result == [{"id": 1, "v": "a"}]
        assert transform.dropped == 1

    def test_deduplicate_keep_last(self, context):
        transform = build("deduplicate", columns=["id"], keep="last")
        result = apply_stream(transform, [{"id": 1, "v": "a"}, {"id": 1, "v": "b"}], context)
        assert result == [{"id": 1, "v": "b"}]

    def test_deduplicate_rejects_a_bad_keep_value(self):
        with pytest.raises(ConfigurationError, match="'first' or 'last'"):
            build("deduplicate", keep="middle")

    def test_aggregate_groups(self, context):
        records = [
            {"g": "a", "v": 1},
            {"g": "a", "v": 3},
            {"g": "b", "v": 10},
            {"g": "b", "v": None},
        ]
        transform = build(
            "aggregate",
            group_by=["g"],
            aggregations={
                "total": {"column": "v", "function": "sum"},
                "n": {"column": "v", "function": "count"},
                "mean": {"column": "v", "function": "avg"},
                "biggest": {"column": "v", "function": "max"},
            },
        )
        result = {r["g"]: r for r in apply_stream(transform, records, context)}
        assert result["a"]["total"] == 4
        assert result["a"]["mean"] == 2
        assert result["b"]["n"] == 1, "nulls are not counted"
        assert result["b"]["biggest"] == 10

    def test_aggregate_without_group_by_yields_one_row(self, context):
        transform = build("aggregate", aggregations={"total": {"column": "v", "function": "sum"}})
        result = apply_stream(transform, [{"v": 1}, {"v": 2}], context)
        assert result == [{"total": 3}]

    def test_aggregate_count_distinct(self, context):
        transform = build(
            "aggregate", aggregations={"d": {"column": "v", "function": "count_distinct"}}
        )
        assert apply_stream(transform, [{"v": 1}, {"v": 1}, {"v": 2}], context)[0]["d"] == 2

    def test_aggregate_rejects_unknown_functions(self):
        with pytest.raises(ConfigurationError, match="unknown aggregate function"):
            build("aggregate", aggregations={"x": {"column": "v", "function": "median"}})

    def test_aggregate_group_cardinality_cap(self, context):
        transform = build(
            "aggregate",
            group_by=["g"],
            aggregations={"n": {"column": "g", "function": "count"}},
            max_groups=2,
        )
        with pytest.raises(TransformationError, match="max_groups"):
            apply_stream(transform, [{"g": i} for i in range(10)], context)

    def test_join_enriches_from_a_lookup(self, context, tmp_path, settings, monkeypatch):
        lookup = tmp_path / "dim.csv"
        lookup.write_text("code,label\nEU,Europe\nUS,Americas\n", encoding="utf-8")
        monkeypatch.setenv("IRONFLOW_DATA_ROOTS", str(tmp_path))

        transform = build(
            "join",
            source={"type": "csv", "path": str(lookup)},
            left_on=["code"],
            how="left",
        )
        result = apply_stream(transform, [{"code": "EU"}, {"code": "XX"}], context)
        assert result[0]["label"] == "Europe"
        assert "label" not in result[1]
        assert transform.matched == 1 and transform.unmatched == 1

    def test_inner_join_drops_unmatched(self, context, tmp_path, monkeypatch):
        lookup = tmp_path / "dim.csv"
        lookup.write_text("code,label\nEU,Europe\n", encoding="utf-8")
        monkeypatch.setenv("IRONFLOW_DATA_ROOTS", str(tmp_path))
        transform = build(
            "join", source={"type": "csv", "path": str(lookup)}, left_on=["code"], how="inner"
        )
        result = apply_stream(transform, [{"code": "EU"}, {"code": "XX"}], context)
        assert [r["code"] for r in result] == ["EU"]

    def test_join_key_arity_is_checked(self):
        with pytest.raises(ConfigurationError, match="same number of columns"):
            build("join", source={"type": "memory"}, left_on=["a"], right_on=["a", "b"])

    def test_limit_short_circuits(self, context):
        transform = build("limit", count=3)
        assert len(apply_stream(transform, [{"i": i} for i in range(100)], context)) == 3


class TestPipelineEngine:
    def test_empty_pipeline_passes_records_through(self, context):
        pipeline = TransformationPipeline.from_specs([])
        assert pipeline.is_empty
        result = [r for b in pipeline.apply(batched([{"a": 1}], 10), context) for r in b]
        assert result == [{"a": 1}]

    def test_steps_apply_in_order(self, context):
        pipeline = TransformationPipeline.from_specs(
            [
                TransformSpec.model_validate({"type": "rename", "mapping": {"a": "b"}}),
                TransformSpec.model_validate(
                    {"type": "derive", "column": "c", "expression": "b * 2"}
                ),
            ]
        )
        result = [r for batch in pipeline.apply(batched([{"a": 5}], 10), context) for r in batch]
        assert result == [{"b": 5, "c": 10}]

    def test_disabled_steps_are_skipped(self, context):
        pipeline = TransformationPipeline.from_specs(
            [TransformSpec.model_validate({"type": "drop", "columns": ["a"], "enabled": False})]
        )
        assert pipeline.is_empty

    def test_blocking_steps_are_detected(self, context):
        pipeline = TransformationPipeline.from_specs(
            [TransformSpec.model_validate({"type": "sort", "columns": ["a"]})]
        )
        assert pipeline.has_blocking_steps

    def test_batch_and_stream_steps_compose(self, context):
        pipeline = TransformationPipeline.from_specs(
            [
                TransformSpec.model_validate({"type": "filter", "expression": "n > 1"}),
                TransformSpec.model_validate({"type": "sort", "columns": ["n desc"]}),
                TransformSpec.model_validate(
                    {"type": "derive", "column": "double", "expression": "n * 2"}
                ),
            ]
        )
        records = [{"n": i} for i in range(5)]
        result = [r for batch in pipeline.apply(batched(records, 2), context) for r in batch]
        assert [r["n"] for r in result] == [4, 3, 2]
        assert result[0]["double"] == 8

    def test_statistics_are_collected(self, context):
        pipeline = TransformationPipeline.from_specs(
            [TransformSpec.model_validate({"type": "filter", "expression": "n > 2"})]
        )
        list(pipeline.apply(batched([{"n": i} for i in range(5)], 5), context))
        report = pipeline.report()
        assert report[0]["rows_in"] == 5
        assert report[0]["rows_out"] == 2
        assert report[0]["rows_dropped"] == 3

    def test_failure_names_the_step(self, context):
        pipeline = TransformationPipeline.from_specs(
            [
                TransformSpec.model_validate(
                    {
                        "type": "cast",
                        "name": "strict_cast",
                        "columns": {"v": "integer"},
                        "on_error": "fail",
                    }
                )
            ],
            task_name="t1",
        )
        with pytest.raises(TransformationError) as info:
            list(pipeline.apply(batched([{"v": "abc"}], 10), context))
        assert info.value.context["step"] == "strict_cast"
        assert info.value.context["task"] == "t1"

    def test_streaming_is_lazy(self, context):
        """Building the chain must not consume the source."""
        consumed = []

        def source():
            for i in range(3):
                consumed.append(i)
                yield RecordBatch([{"n": i}])

        pipeline = TransformationPipeline.from_specs(
            [TransformSpec.model_validate({"type": "derive", "column": "d", "expression": "n + 1"})]
        )
        stream = pipeline.apply(source(), context)
        assert consumed == [], "no batch should be pulled before iteration"
        next(iter(stream))
        assert consumed == [0]
