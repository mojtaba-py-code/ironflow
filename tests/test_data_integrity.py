"""Data-integrity guarantees: what a failed run publishes, and what hostile input costs.

Each class pins one fix from the hardening pass.  Its docstring names the failure
the tests catch if the fix regresses - most of them were reproduced against the
code before the fix, so they fail on it rather than merely passing after it.
"""

from __future__ import annotations

import csv
import gc
import json
import os
import sys
import weakref
from pathlib import Path
from typing import Any

import pytest

from ironflow.config.models import ConnectorSpec, PipelineSpec, TaskSpec
from ironflow.connectors import files as files_module
from ironflow.connectors.factory import ConnectorFactory
from ironflow.connectors.memory import MemorySink, MemorySource
from ironflow.core.errors import (
    ConfigurationError,
    ExtractionError,
    PipelineError,
    SecurityError,
)
from ironflow.core.types import RecordBatch, RunStatus
from ironflow.pipeline.loading import LoadEngine
from ironflow.pipeline.results import TaskResult
from ironflow.pipeline.task import TaskExecutor
from ironflow.repositories.repositories import WatermarkRepository

pytestmark = pytest.mark.integration

REPLACEMENT = "\N{REPLACEMENT CHARACTER}"
QUARANTINE_NEGATIVE_IDS = {
    "on_violation": "quarantine",
    "rules": [{"type": "range", "field": "id", "min": 0}],
}


def spec(connector_type: str, **options: Any) -> ConnectorSpec:
    return ConnectorSpec.model_validate({"type": connector_type, **options})


def read_all(source, context) -> list[dict]:
    source.open(context)
    try:
        return [record for batch in source.read(context) for record in batch]
    finally:
        source.close()


def read_batches(source, context) -> list[RecordBatch]:
    source.open(context)
    try:
        return list(source.read(context))
    finally:
        source.close()


def write_all(sink, records, context) -> None:
    sink.open(context)
    try:
        sink.write(RecordBatch(records), context)
        sink.commit()
    finally:
        sink.close()


def run_task(settings, context, **task: Any) -> TaskResult:
    spec_ = TaskSpec.model_validate({"name": "t", **task})
    return TaskExecutor(spec_, "p", factory=ConnectorFactory(settings)).execute(context)


def parse_xml(path: Path) -> Any:
    from defusedxml.ElementTree import parse

    return parse(str(path)).getroot()


# --------------------------------------------------------------------------- #
# Finding 1: a failed run must not publish the main destination
# --------------------------------------------------------------------------- #
class TestAFailedRunPublishesNothing:
    """The main sink used to be published first; a reject publish failing after it
    left the main file replaced or appended to while the run reported failure, so
    the re-run loaded the same rows a second time."""

    def _quarantining_task(self, main: Path, rejects: Path, **overrides: Any) -> dict:
        return {
            "source": {"type": "memory", "dataset": "feed"},
            "destination": {"type": "csv", "path": str(main)},
            "reject_destination": {"type": "csv", "path": str(rejects)},
            "validation": QUARANTINE_NEGATIVE_IDS,
            **overrides,
        }

    def test_rejects_are_published_before_the_main_data(self, factory, context):
        order: list[str] = []
        main = factory.create_sink(spec("memory", buffer="main"))
        rejects = factory.create_sink(spec("memory", buffer="rejects"))
        for label, sink in (("main", main), ("rejects", rejects)):
            sink.prepare = lambda label=label: order.append(f"prepare {label}")
            sink.commit = lambda label=label: order.append(f"publish {label}")
        engine = LoadEngine(main, reject_sink=rejects, task_name="t")

        def stream():
            engine.write_rejects([{"id": -1}], context)
            yield RecordBatch([{"id": 1}])

        engine.load(stream(), context)
        assert order == ["prepare rejects", "prepare main", "publish rejects", "publish main"]

    @pytest.mark.parametrize("mode", ["append", "overwrite"])
    def test_a_reject_path_taken_by_a_directory(self, settings, context, tmp_path, mode):
        MemorySource.register("feed", [{"id": 1}, {"id": -1}])
        main = tmp_path / "main.csv"
        main.write_text("id\n0\n", encoding="utf-8")
        rejects = tmp_path / "rejects.csv"
        rejects.mkdir()

        task = self._quarantining_task(main, rejects)
        task["destination"]["mode"] = mode
        result = run_task(settings, context, **task)

        assert result.status is RunStatus.FAILED
        assert main.read_text(encoding="utf-8") == "id\n0\n"
        assert not list(tmp_path.glob(".*.staging")), "staging files must be cleaned up"

    @pytest.mark.parametrize("mode", ["append", "overwrite"])
    def test_a_reject_file_that_cannot_be_replaced(
        self, settings, context, tmp_path, monkeypatch, mode
    ):
        """What an analyst with rejects.csv open in Excel does to os.replace on Windows."""
        MemorySource.register("feed", [{"id": 1}, {"id": -1}])
        main = tmp_path / "main.csv"
        main.write_text("id\n0\n", encoding="utf-8")
        rejects = tmp_path / "rejects.csv"
        rejects.write_text("previous\n", encoding="utf-8")

        replace = Path.replace

        def locked(self: Path, target: Any) -> Path:
            if Path(target).name == rejects.name:
                raise PermissionError(13, "file is in use by another process", str(target))
            return replace(self, target)

        monkeypatch.setattr(Path, "replace", locked)
        task = self._quarantining_task(main, rejects)
        task["destination"]["mode"] = mode
        task["reject_destination"]["mode"] = "overwrite"
        result = run_task(settings, context, **task)

        assert result.status is RunStatus.FAILED
        assert main.read_text(encoding="utf-8") == "id\n0\n"
        assert rejects.read_text(encoding="utf-8") == "previous\n"

    def test_a_main_path_taken_by_a_directory_fails_before_the_rejects_go_out(
        self, settings, context, tmp_path
    ):
        """The main target is checked in prepare: a replaced reject file cannot be undone."""
        MemorySource.register("feed", [{"id": 1}, {"id": -1}])
        main = tmp_path / "main.csv"
        main.mkdir()
        rejects = tmp_path / "rejects.csv"
        rejects.write_text("previous\n", encoding="utf-8")

        task = self._quarantining_task(main, rejects)
        task["destination"]["mode"] = "overwrite"
        task["reject_destination"]["mode"] = "overwrite"
        result = run_task(settings, context, **task)

        assert result.status is RunStatus.FAILED
        assert rejects.read_text(encoding="utf-8") == "previous\n"

    def test_a_failed_main_publish_withdraws_the_appended_rejects(
        self, settings, context, tmp_path, monkeypatch
    ):
        """Otherwise the retry appends the same rejects a second time."""
        MemorySource.register("feed", [{"id": 1}, {"id": -1}])
        rejects = tmp_path / "rejects.csv"
        rejects.write_text("id\n", encoding="utf-8")
        publish = MemorySink.commit
        attempts = {"n": 0}

        def flaky(self: MemorySink) -> None:
            attempts["n"] += 1
            if attempts["n"] == 1:
                raise OSError("destination briefly unavailable")
            publish(self)

        monkeypatch.setattr(MemorySink, "commit", flaky)
        result = run_task(
            settings,
            context,
            source={"type": "memory", "dataset": "feed"},
            destination={"type": "memory", "buffer": "main"},
            reject_destination={"type": "csv", "path": str(rejects)},
            validation=QUARANTINE_NEGATIVE_IDS,
            retry={"max_attempts": 2, "initial_delay": 0, "jitter": False},
        )

        assert result.status is RunStatus.SUCCESS
        assert result.attempt == 2
        assert MemorySink.buffer("main") == [{"id": 1}]
        lines = rejects.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2, f"the first attempt's rejects were not withdrawn: {lines}"

    def test_a_reject_that_cannot_be_written_fails_the_run(self, settings, context, tmp_path):
        """It used to be logged and dropped: the run succeeded without its quarantine."""
        MemorySource.register("feed", [{"id": 1}, {"id": -1}])
        main = tmp_path / "main.csv"
        rejects = tmp_path / "rejects.csv"
        rejects.write_text("taken\n", encoding="utf-8")

        result = run_task(
            settings,
            context,
            **self._quarantining_task(
                main,
                rejects,
                reject_destination={
                    "type": "csv",
                    "name": "quarantine_file",
                    "path": str(rejects),
                    "mode": "error_if_exists",
                },
            ),
        )

        assert result.status is RunStatus.FAILED
        assert result.error.context["quarantine"] == "quarantine_file"
        assert not main.exists(), "the main destination must not be published"

    def test_a_watermark_that_cannot_be_saved_does_not_fail_a_committed_load(
        self, settings, context, database, monkeypatch
    ):
        """Failing after the commit reported a failed run that had changed the
        destination, and the retry loaded the rows again."""
        MemorySource.register("feed", [{"id": 1, "ts": "2026-01-01"}])
        watermarks = WatermarkRepository(database)

        def unavailable(*args: Any, **kwargs: Any) -> None:
            raise OSError("state database is locked")

        monkeypatch.setattr(watermarks, "set", unavailable)
        task = TaskSpec.model_validate(
            {
                "name": "t",
                "source": {"type": "memory", "dataset": "feed"},
                "destination": {"type": "memory", "buffer": "main"},
                "strategy": "incremental",
                "incremental": {"column": "ts"},
                "retry": {"max_attempts": 3, "initial_delay": 0, "jitter": False},
            }
        )
        executor = TaskExecutor(
            task, "p", factory=ConnectorFactory(settings), watermarks=watermarks
        )

        result = executor.execute(context)
        assert result.status is RunStatus.SUCCESS
        assert MemorySink.buffer("main") == [{"id": 1, "ts": "2026-01-01"}]

    def test_a_source_that_fails_to_close_does_not_fail_a_committed_load(
        self, settings, context, monkeypatch
    ):
        MemorySource.register("feed", [{"id": 1}])

        def broken(self: MemorySource) -> None:
            raise RuntimeError("handle already gone")

        monkeypatch.setattr(MemorySource, "_on_close", broken, raising=False)
        result = run_task(
            settings,
            context,
            source={"type": "memory", "dataset": "feed"},
            destination={"type": "memory", "buffer": "main"},
        )
        assert result.status is RunStatus.SUCCESS
        assert MemorySink.buffer("main") == [{"id": 1}]

    def test_append_preserves_line_breaks_inside_values(self, factory, context, tmp_path):
        """The appended text was re-read with universal newlines: CRLF became LF."""
        target = tmp_path / "out.csv"
        write_all(factory.create_sink(spec("csv", path=str(target))), [{"v": "first"}], context)
        write_all(factory.create_sink(spec("csv", path=str(target))), [{"v": "a\r\nb"}], context)
        rows = read_all(
            factory.create_source(spec("csv", path=str(target), strip_whitespace=False)), context
        )
        assert [row["v"] for row in rows] == ["first", "a\r\nb"]


# --------------------------------------------------------------------------- #
# Finding 2: header cells are neutralised like values
# --------------------------------------------------------------------------- #
class TestFormulaNeutralisationCoversHeaders:
    """Column names come from the data (a CSV header, JSON keys); a header "=1+1"
    was written raw to CSV and became a live formula cell in XLSX."""

    @pytest.mark.parametrize("name", ["=1+1", "+1", "-1", "@SUM(A1)", "\tx", "\rx"])
    def test_csv_header(self, factory, context, tmp_path, name):
        target = tmp_path / "out.csv"
        write_all(
            factory.create_sink(spec("csv", path=str(target))), [{name: "v", "ok": "w"}], context
        )
        with target.open(encoding="utf-8", newline="") as handle:
            assert next(csv.reader(handle)) == ["'" + name, "ok"]

    def test_reject_csv_header(self, settings, context, tmp_path):
        feed = tmp_path / "feed.jsonl"
        feed.write_text('{"id": -1, "=1+1": "x"}\n', encoding="utf-8")
        rejects = tmp_path / "rejects.csv"
        result = run_task(
            settings,
            context,
            source={"type": "json", "path": str(feed)},
            destination={"type": "memory", "buffer": "main"},
            reject_destination={"type": "csv", "path": str(rejects)},
            validation=QUARANTINE_NEGATIVE_IDS,
        )
        assert result.status is RunStatus.SUCCESS
        with rejects.open(encoding="utf-8", newline="") as handle:
            header = next(csv.reader(handle))
        assert "'=1+1" in header
        assert "=1+1" not in header

    def test_excel_header_is_not_a_formula(self, factory, context, tmp_path):
        openpyxl = pytest.importorskip("openpyxl")
        target = tmp_path / "out.xlsx"
        write_all(factory.create_sink(spec("excel", path=str(target))), [{"=1+1": 1}], context)
        cell = openpyxl.load_workbook(target).active["A1"]
        assert cell.data_type != "f"
        assert cell.value == "'=1+1"


# --------------------------------------------------------------------------- #
# Finding 3: memory follows batch_size, not the input's shape or size
# --------------------------------------------------------------------------- #
class TestMemoryIsBoundedByBatchSize:
    def test_a_stray_cell_in_the_last_excel_column_does_not_widen_records(
        self, factory, context, tmp_path
    ):
        """openpyxl pads rows to the widest used column: 16,384 keys per record."""
        openpyxl = pytest.importorskip("openpyxl")
        path = tmp_path / "stray.xlsx"
        workbook = openpyxl.Workbook()
        sheet = workbook.active
        sheet.append(["id", "name"])
        sheet.append([1, "a"])
        sheet.append([2, "b"])
        sheet["XFD3"] = "stray"
        workbook.save(path)

        rows = read_all(factory.create_source(spec("excel", path=str(path))), context)
        assert rows == [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]

    def test_an_empty_excel_header_above_data_is_refused(self, factory, context, tmp_path):
        """Without names there is no width to bound the rows by."""
        openpyxl = pytest.importorskip("openpyxl")
        path = tmp_path / "headerless.xlsx"
        workbook = openpyxl.Workbook()
        workbook.active["A2"] = 1
        workbook.save(path)
        with pytest.raises(ExtractionError, match="header row is empty"):
            read_all(factory.create_source(spec("excel", path=str(path))), context)

    def test_a_wide_csv_header_shortens_batches_instead_of_inflating_them(
        self, factory, context, tmp_path
    ):
        """Short rows are padded to the header: 1,024 columns x 10 rows in one batch."""
        path = tmp_path / "wide.csv"
        path.write_text(
            ",".join(f"c{i}" for i in range(1024)) + "\n" + "x\n" * 10, encoding="utf-8"
        )
        batches = read_batches(
            factory.create_source(spec("csv", path=str(path), batch_size=10)), context
        )
        assert sum(len(batch) for batch in batches) == 10
        budget = 10 * files_module._CELLS_PER_BATCH_ROW
        for batch in batches:
            assert len(batch) * len(batch.records[0]) <= budget

    def test_a_csv_header_wider_than_max_columns_is_refused(self, factory, context, tmp_path):
        path = tmp_path / "wider.csv"
        path.write_text(",".join(f"c{i}" for i in range(5000)) + "\n1\n", encoding="utf-8")
        with pytest.raises(ExtractionError, match="max_columns"):
            read_all(factory.create_source(spec("csv", path=str(path))), context)

        rows = read_all(
            factory.create_source(spec("csv", path=str(path), max_columns=5000)), context
        )
        assert len(rows) == 1
        assert len(rows[0]) == 5000

    def test_xml_records_are_released_as_they_are_read(
        self, factory, context, tmp_path, monkeypatch
    ):
        """clear() alone left every record attached to the root until the end."""
        path = tmp_path / "feed.xml"
        path.write_text(
            "<root>" + "".join(f"<row><id>{i}</id></row>" for i in range(50)) + "</root>",
            encoding="utf-8",
        )
        converted: list[weakref.ref[Any]] = []
        convert = files_module._element_to_record

        def spy(element: Any, **kwargs: Any) -> dict:
            converted.append(weakref.ref(element))
            return convert(element, **kwargs)

        monkeypatch.setattr(files_module, "_element_to_record", spy)
        source = factory.create_source(spec("xml", path=str(path), record_tag="row", batch_size=10))
        source.open(context)
        try:
            stream = source.read(context)
            for _ in range(3):
                next(stream)
            gc.collect()
            alive = sum(ref() is not None for ref in converted)
        finally:
            source.close()
        assert len(converted) == 30
        assert alive <= 1, f"{alive} converted records are still held by the document"

    def test_xml_sources_are_size_capped(self, factory, context, tmp_path):
        path = tmp_path / "feed.xml"
        path.write_text("<root><row><v>1</v></row></root>", encoding="utf-8")
        source = factory.create_source(spec("xml", path=str(path), record_tag="row", max_bytes=10))
        with pytest.raises(ExtractionError, match="size limit"):
            read_all(source, context)

    def test_a_json_document_has_a_lower_default_cap_than_json_lines(
        self, factory, context, tmp_path
    ):
        """A JSON array is parsed whole; the 5 GiB streaming default was an OOM switch."""
        path = tmp_path / "export.json"
        path.write_bytes(b"[]")
        os.truncate(path, 100 * 1024**2 + 1)  # sparse where the filesystem allows
        with pytest.raises(ExtractionError, match="JSON Lines") as info:
            read_all(factory.create_source(spec("json", path=str(path))), context)
        assert info.value.context["limit"] == 100 * 1024**2


# --------------------------------------------------------------------------- #
# Findings 3 and 7: Parquet directories are streamed, and confined file by file
# --------------------------------------------------------------------------- #
@pytest.fixture
def parquet_dataset(tmp_path: Path) -> Path:
    pa = pytest.importorskip("pyarrow")
    pq = pytest.importorskip("pyarrow.parquet")
    root = tmp_path / "root" / "dataset"
    for year, ids in ((2024, [1, 2]), (2025, [3])):
        partition = root / f"year={year}"
        partition.mkdir(parents=True)
        pq.write_table(pa.table({"id": ids}), partition / "part-0.parquet")
    (root / "_SUCCESS").write_bytes(b"")
    return root


def link_directory(link: Path, target: Path, request: pytest.FixtureRequest) -> None:
    """A directory symlink, or a junction where Windows refuses symlinks."""
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        if sys.platform != "win32":
            pytest.skip("cannot create a directory link on this platform")
        import _winapi

        try:
            _winapi.CreateJunction(str(target), str(link))
        except OSError:
            pytest.skip("cannot create a directory junction")
    # Removed before tmp_path cleanup, so the cleanup never walks through it; on
    # Windows both kinds of directory link are removed like an empty directory.
    request.addfinalizer(link.rmdir if sys.platform == "win32" else link.unlink)


class TestParquetDirectories:
    """``pq.read_table`` loaded the whole directory, and only the directory itself
    was confined: a link inside it read files outside the data roots."""

    def test_a_directory_is_streamed_not_loaded_whole(
        self, factory, context, parquet_dataset, monkeypatch
    ):
        pq = pytest.importorskip("pyarrow.parquet")

        def refuse(*args: Any, **kwargs: Any) -> None:
            raise AssertionError("read_table materialises the whole directory")

        monkeypatch.setattr(pq, "read_table", refuse)
        batches = read_batches(
            factory.create_source(spec("parquet", path=str(parquet_dataset), batch_size=1)),
            context,
        )
        assert [len(batch) for batch in batches] == [1, 1, 1]
        assert [record for batch in batches for record in batch] == [
            {"id": 1, "year": 2024},
            {"id": 2, "year": 2024},
            {"id": 3, "year": 2025},
        ]

    def test_a_directory_source_runs_through_a_pipeline(self, settings, context, parquet_dataset):
        """describe() - called for schema drift - handed the directory to read_schema."""
        result = run_task(
            settings,
            context,
            source={"type": "parquet", "path": str(parquet_dataset)},
            destination={"type": "memory", "buffer": "main"},
        )
        assert result.status is RunStatus.SUCCESS, result.error
        assert len(MemorySink.buffer("main")) == 3

    def test_a_link_out_of_the_data_roots_is_refused(
        self, settings, context, tmp_path, parquet_dataset, request
    ):
        pa = pytest.importorskip("pyarrow")
        pq = pytest.importorskip("pyarrow.parquet")
        outside = tmp_path / "outside"
        outside.mkdir()
        pq.write_table(pa.table({"id": [666]}), outside / "secret.parquet")
        link_directory(parquet_dataset / "escape", outside, request)

        factory = ConnectorFactory(settings.model_copy(update={"data_roots": [tmp_path / "root"]}))
        source = factory.create_source(spec("parquet", path=str(parquet_dataset)))
        with pytest.raises(SecurityError):
            read_all(source, context)

    def test_a_file_link_out_of_the_data_roots_is_refused(
        self, settings, context, tmp_path, parquet_dataset
    ):
        pa = pytest.importorskip("pyarrow")
        pq = pytest.importorskip("pyarrow.parquet")
        outside = tmp_path / "outside.parquet"
        pq.write_table(pa.table({"id": [666]}), outside)
        try:
            (parquet_dataset / "year=2025" / "part-1.parquet").symlink_to(outside)
        except OSError:
            pytest.skip("symlinks require privileges on this platform")

        factory = ConnectorFactory(settings.model_copy(update={"data_roots": [tmp_path / "root"]}))
        source = factory.create_source(spec("parquet", path=str(parquet_dataset)))
        with pytest.raises(SecurityError):
            read_all(source, context)

    def test_a_link_back_into_the_dataset_does_not_loop(
        self, factory, context, parquet_dataset, request
    ):
        link_directory(parquet_dataset / "year=2025" / "loop", parquet_dataset, request)
        rows = read_all(factory.create_source(spec("parquet", path=str(parquet_dataset))), context)
        assert sorted(row["id"] for row in rows) == [1, 2, 3]


# --------------------------------------------------------------------------- #
# Finding 4: a lone surrogate cannot block a feed or empty the quarantine
# --------------------------------------------------------------------------- #
class TestLoneSurrogates:
    """``"\\ud83d"`` is legal JSON that no UTF-8 encoder accepts: it failed every
    retry at the main sink, and at the reject sink it silently lost the batch."""

    def test_json_sources_replace_them(self, factory, context, tmp_path):
        lines = tmp_path / "feed.jsonl"
        lines.write_text(
            '{"name": "a\\ud83db", "\\udc00": 1, "pair": "\\ud83d\\ude00"}\n', encoding="utf-8"
        )
        document = tmp_path / "feed.json"
        document.write_text('[{"name": ["a\\ud83db"]}]', encoding="utf-8")

        assert read_all(factory.create_source(spec("json", path=str(lines))), context) == [
            {"name": f"a{REPLACEMENT}b", REPLACEMENT: 1, "pair": "\N{GRINNING FACE}"}
        ]
        assert read_all(factory.create_source(spec("json", path=str(document))), context) == [
            {"name": [f"a{REPLACEMENT}b"]}
        ]

    def test_http_sources_replace_them(self, factory, context):
        import httpx

        source = factory.create_source(
            spec("rest", url="https://api.example.com/items", allow_private_network=True)
        )
        original = source._build_client

        def build() -> httpx.Client:
            client = original()
            client._transport = httpx.MockTransport(
                lambda request: httpx.Response(
                    200, content=b'[{"name": "a\\ud83db", "pair": "\\ud83d\\ude00"}]'
                )
            )
            return client

        source._build_client = build
        assert read_all(source, context) == [
            {"name": f"a{REPLACEMENT}b", "pair": "\N{GRINNING FACE}"}
        ]

    @pytest.mark.parametrize(
        ("destination", "suffix"),
        [({"type": "csv"}, "csv"), ({"type": "parquet"}, "parquet")],
    )
    def test_one_does_not_block_the_feed(self, settings, context, tmp_path, destination, suffix):
        if suffix == "parquet":
            pytest.importorskip("pyarrow")
        feed = tmp_path / "feed.jsonl"
        feed.write_text('{"id": 1, "name": "\\ud83d"}\n{"id": 2, "name": "ok"}\n', encoding="utf-8")
        target = tmp_path / f"out.{suffix}"
        result = run_task(
            settings,
            context,
            source={"type": "json", "path": str(feed)},
            destination={**destination, "path": str(target)},
        )
        assert result.status is RunStatus.SUCCESS, result.error
        assert result.metrics.rows_out == 2

    def test_text_sinks_escape_what_they_cannot_encode(self, factory, context, tmp_path):
        """A surrogate from a source that does not clean them (REST) is kept, escaped."""
        csv_target = tmp_path / "out.csv"
        write_all(
            factory.create_sink(spec("csv", path=str(csv_target))), [{"v": "a\ud83db"}], context
        )
        assert csv_target.read_text(encoding="utf-8").splitlines() == ["v", "a\\ud83db"]

        jsonl_target = tmp_path / "out.jsonl"
        write_all(
            factory.create_sink(spec("json", path=str(jsonl_target))), [{"v": "a\ud83db"}], context
        )
        assert json.loads(jsonl_target.read_text(encoding="utf-8")) == {"v": "a\ud83db"}

    def test_a_rejected_row_carrying_one_is_still_quarantined(self, settings, context, tmp_path):
        MemorySource.register("feed", [{"id": 1, "note": "ok"}, {"id": -1, "note": "a\ud83db"}])
        rejects = tmp_path / "rejects.csv"
        result = run_task(
            settings,
            context,
            source={"type": "memory", "dataset": "feed"},
            destination={"type": "memory", "buffer": "main"},
            reject_destination={"type": "csv", "path": str(rejects)},
            validation=QUARANTINE_NEGATIVE_IDS,
        )
        assert result.status is RunStatus.SUCCESS
        assert "a\\ud83db" in rejects.read_text(encoding="utf-8")

    def test_excel_accepts_what_openpyxl_refuses(self, factory, context, tmp_path):
        """IllegalCharacterError for "\\x01" also left the write-only sheet unusable."""
        openpyxl = pytest.importorskip("openpyxl")
        target = tmp_path / "out.xlsx"
        write_all(
            factory.create_sink(spec("excel", path=str(target))),
            [{"v": "a\x01b"}, {"v": "c\ud83dd"}],
            context,
        )
        sheet = openpyxl.load_workbook(target).active
        assert [row[0].value for row in sheet.iter_rows(min_row=2)] == [
            f"a{REPLACEMENT}b",
            f"c{REPLACEMENT}d",
        ]


# --------------------------------------------------------------------------- #
# Finding 5: sinks refuse modes they cannot honour, when they are built
# --------------------------------------------------------------------------- #
class TestModesTheSinkCannotHonour:
    """``append`` - the default - produced ``[...][...]`` for a JSON array, "junk
    after document element" for XML, and silently replaced Excel and Parquet."""

    @pytest.mark.parametrize(
        ("connector_type", "filename"),
        [("json", "out.json"), ("xml", "out.xml"), ("excel", "out.xlsx"), ("parquet", "out.pq")],
    )
    def test_append_to_a_whole_document_format_is_refused(
        self, factory, tmp_path, connector_type, filename
    ):
        options = {"path": str(tmp_path / filename), "mode": "append"}
        with pytest.raises(ConfigurationError, match="does not support mode 'append'"):
            factory.create_sink(spec(connector_type, **options))
        assert factory.validate(spec(connector_type, **options), kind="sink")

    @pytest.mark.parametrize(
        ("connector_type", "options"),
        [
            ("csv", {"path": "out.csv", "mode": "upsert"}),
            ("sftp", {"host": "h", "user": "u", "remote_path": "/out.csv", "mode": "append"}),
            ("memory", {"buffer": "b", "mode": "error_if_exists"}),
        ],
    )
    def test_other_unimplemented_modes_are_refused(self, factory, connector_type, options):
        with pytest.raises(ConfigurationError, match="does not support mode"):
            factory.create_sink(spec(connector_type, **options))

    def test_pipeline_validate_reports_it(self, service, tmp_path):
        pipeline = PipelineSpec.model_validate(
            {
                "name": "p",
                "tasks": [
                    {
                        "name": "t",
                        "source": {"type": "memory", "dataset": "feed"},
                        "destination": {
                            "type": "excel",
                            "path": str(tmp_path / "out.xlsx"),
                            "mode": "append",
                        },
                    }
                ],
            }
        )
        report = service.validate(pipeline)
        assert not report["valid"]
        assert any("does not support mode 'append'" in problem for problem in report["problems"])

    def test_a_json_array_is_overwritten_by_default(self, factory, context, tmp_path):
        target = tmp_path / "out.json"
        for run in (1, 2):
            write_all(factory.create_sink(spec("json", path=str(target))), [{"run": run}], context)
        assert json.loads(target.read_text(encoding="utf-8")) == [{"run": 2}]

    def test_an_xml_document_is_overwritten_by_default(self, factory, context, tmp_path):
        target = tmp_path / "out.xml"
        for run in (1, 2):
            write_all(factory.create_sink(spec("xml", path=str(target))), [{"run": run}], context)
        assert [row.findtext("run") for row in parse_xml(target)] == ["2"]

    @pytest.mark.parametrize("filename", ["out.csv", "out.jsonl"])
    def test_appendable_formats_still_append_by_default(self, factory, context, tmp_path, filename):
        target = tmp_path / filename
        kind = "csv" if filename.endswith(".csv") else "json"
        for run in (1, 2):
            write_all(factory.create_sink(spec(kind, path=str(target))), [{"run": run}], context)
        assert len(read_all(factory.create_source(spec(kind, path=str(target))), context)) == 2


# --------------------------------------------------------------------------- #
# Finding 6: skip_rows cannot outlive the task
# --------------------------------------------------------------------------- #
class _CountingReads:
    """File proxy that counts ``readline`` calls and delegates everything else."""

    def __init__(self, handle: Any) -> None:
        self._handle = handle
        self.readlines = 0

    def readline(self, *args: Any) -> str:
        self.readlines += 1
        return self._handle.readline(*args)

    def __iter__(self) -> Any:
        return iter(self._handle)

    def __enter__(self) -> _CountingReads:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self._handle.close()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._handle, name)


class TestSkipRows:
    """``skip_rows: 10**15`` spun on EOF for centuries, past any timeout."""

    def test_is_capped_when_the_source_is_built(self, factory, csv_file):
        with pytest.raises(ConfigurationError, match="skip_rows"):
            factory.create_source(spec("csv", path=str(csv_file), skip_rows=10**15))
        assert factory.validate(spec("csv", path=str(csv_file), skip_rows=10**15), kind="source")

    def test_stops_at_end_of_file(self, factory, context, tmp_path, monkeypatch):
        path = tmp_path / "preamble.csv"
        path.write_text("title\nsubtitle\na\n1\n", encoding="utf-8")
        handles: list[_CountingReads] = []
        open_file = Path.open

        def counting_open(self: Path, *args: Any, **kwargs: Any) -> Any:
            handle = open_file(self, *args, **kwargs)
            if self.name == path.name:
                handle = _CountingReads(handle)
                handles.append(handle)
            return handle

        monkeypatch.setattr(Path, "open", counting_open)
        source = factory.create_source(spec("csv", path=str(path), skip_rows=1_000_000))
        assert read_all(source, context) == []
        assert handles[0].readlines <= 5

    def test_honours_cancellation(self, factory, context, tmp_path):
        path = tmp_path / "preamble.csv"
        path.write_text("a\n1\n", encoding="utf-8")
        context.cancellation.cancel("operator stop")
        source = factory.create_source(spec("csv", path=str(path), skip_rows=10))
        with pytest.raises(PipelineError, match="operator stop"):
            read_all(source, context)


# --------------------------------------------------------------------------- #
# Finding 8: the XML writer only publishes well-formed documents
# --------------------------------------------------------------------------- #
class TestXmlOutputIsWellFormed:
    """A value with "\\x01" (or a hostile root_tag) published XML that did not
    parse, and the run reported success."""

    def test_characters_xml_forbids_are_replaced(self, factory, context, tmp_path):
        target = tmp_path / "out.xml"
        write_all(
            factory.create_sink(spec("xml", path=str(target))),
            [{"v": "a\x01b", "w": "c\ud83dd", "x": "tab\tand\nnewline"}],
            context,
        )
        record = parse_xml(target).find("record")
        assert record.findtext("v") == f"a{REPLACEMENT}b"
        assert record.findtext("w") == f"c{REPLACEMENT}d"
        assert record.findtext("x") == "tab\tand\nnewline"

    def test_root_tag_is_sanitised(self, factory, context, tmp_path):
        target = tmp_path / "out.xml"
        write_all(
            factory.create_sink(spec("xml", path=str(target), root_tag="rows><evil")),
            [{"v": 1}],
            context,
        )
        assert parse_xml(target).tag == "rows__evil"

    def test_names_the_parser_rejects_are_rewritten(self, factory, context, tmp_path):
        """str.isalnum() accepts characters XML names do not."""
        target = tmp_path / "out.xml"
        accented = "pr\N{LATIN SMALL LETTER E WITH ACUTE}nom"
        write_all(
            factory.create_sink(spec("xml", path=str(target))),
            [{"a\N{SUPERSCRIPT TWO}": 1, "\N{MICRO SIGN}": 2, accented: 3}],
            context,
        )
        assert [child.tag for child in parse_xml(target).find("record")] == ["a_", "_", accented]

    def test_the_declaration_names_the_encoding_actually_used(self, factory, context, tmp_path):
        """It said UTF-8 whatever ``encoding`` was, so a strict parser misread it."""
        target = tmp_path / "out.xml"
        write_all(
            factory.create_sink(spec("xml", path=str(target), encoding="latin-1")),
            [{"v": "caf\N{LATIN SMALL LETTER E WITH ACUTE}"}],
            context,
        )
        assert target.read_bytes().startswith(b'<?xml version="1.0" encoding="latin-1"?>')
        assert parse_xml(target).find("record").findtext("v") == "café"

    def test_an_encoding_name_cannot_inject_into_the_prolog(self, factory, context, tmp_path):
        sink = factory.create_sink(
            spec("xml", path=str(tmp_path / "out.xml"), encoding='utf-8"?><!DOCTYPE x [')
        )
        with pytest.raises(ConfigurationError, match="XML encoding name"):
            sink.open(context)


class TestExcelHeader:
    def test_a_configured_column_list_still_gets_a_header_row(self, factory, context, tmp_path):
        """With ``columns:`` set, the sheet used to start at the first data row."""
        openpyxl = pytest.importorskip("openpyxl")
        target = tmp_path / "out.xlsx"
        write_all(
            factory.create_sink(spec("excel", path=str(target), columns=["id", "name"])),
            [{"id": 1, "name": "a", "extra": "ignored"}],
            context,
        )
        rows = list(openpyxl.load_workbook(target).active.iter_rows(values_only=True))
        assert rows == [("id", "name"), (1, "a")]


# --------------------------------------------------------------------------- #
# Finding 9: incremental needs a source that can apply the watermark
# --------------------------------------------------------------------------- #
class TestIncrementalNeedsAWatermarkAwareSource:
    """A file source ignored the watermark: every "incremental" run was a full load."""

    def test_is_refused_before_anything_is_read(self, settings, context, csv_file, tmp_path):
        target = tmp_path / "out.csv"
        result = run_task(
            settings,
            context,
            source={"type": "csv", "path": str(csv_file)},
            destination={"type": "csv", "path": str(target)},
            strategy="incremental",
            incremental={"column": "id"},
        )
        assert result.status is RunStatus.FAILED
        assert isinstance(result.error, ConfigurationError)
        assert "watermark" in str(result.error)
        assert not target.exists()
