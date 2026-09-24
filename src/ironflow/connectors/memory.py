"""In-memory connectors.

Two purposes:

1. **Testing.**  A pipeline test should exercise the real engine, orchestrator
   and transformation chain without touching a filesystem or a database.  These
   connectors make an end-to-end test a pure function.
2. **Streaming simulation.**  :class:`GeneratorSource` produces synthetic
   records at a configurable rate, which is how the streaming/batch behaviour of
   a pipeline is exercised in CI without standing up a broker.

Not registered for production use in the sense that they hold everything in
memory - the row cap is enforced so a misconfiguration cannot OOM the process.
"""

from __future__ import annotations

import random
import string
import time
from collections.abc import Iterator, Sequence
from typing import Any, ClassVar

from ironflow.config.models import ConnectorSpec
from ironflow.connectors.base import BaseSink, BaseSource, ConnectorRuntime, sink, source
from ironflow.core.context import ExecutionContext
from ironflow.core.errors import LoadingError
from ironflow.core.types import LoadMode, Record, RecordBatch, RecordStream, batched

MAX_MEMORY_ROWS = 5_000_000


@source("memory", "inline")
class MemorySource(BaseSource):
    """Yield records supplied inline in the spec or injected programmatically.

    Options: ``records`` (list of mappings), or ``dataset`` naming a dataset
    registered with :meth:`register`.
    """

    #: Datasets injected by tests / the CLI's ``--inline-data``.
    _datasets: ClassVar[dict[str, list[Record]]] = {}

    @classmethod
    def register(cls, name: str, records: Sequence[Record]) -> None:
        cls._datasets[name] = [dict(r) for r in records]

    @classmethod
    def clear(cls) -> None:
        cls._datasets.clear()

    def read(self, context: ExecutionContext) -> RecordStream:
        dataset = self.str_option("dataset")
        if dataset:
            records = list(self._datasets.get(dataset, []))
        else:
            raw = self.option("records", []) or []
            records = [dict(r) for r in raw if isinstance(r, dict)]

        if len(records) > MAX_MEMORY_ROWS:
            raise LoadingError("in-memory dataset is too large", context={"rows": len(records)})
        return batched(records, self.batch_size, source=self.name)

    def count(self) -> int | None:
        dataset = self.str_option("dataset")
        if dataset:
            return len(self._datasets.get(dataset, []))
        return len(self.option("records", []) or [])


@sink("memory")
class MemorySink(BaseSink):
    """Collect written records in a list.

    Transactional in the useful sense: rows land in a pending buffer and only
    move to :attr:`records` on commit, so a test can assert that a failed run
    published nothing.  Supports ``append`` and ``overwrite``.
    """

    transactional = True
    supported_modes = frozenset({LoadMode.APPEND, LoadMode.OVERWRITE})

    #: Named buffers so a test can read results after the pipeline closed.
    _buffers: ClassVar[dict[str, list[Record]]] = {}

    def __init__(self, spec: ConnectorSpec, runtime: ConnectorRuntime | None = None) -> None:
        super().__init__(spec, runtime)
        self._pending: list[Record] = []
        self._buffer_name = self.str_option("buffer", self.name)

    @classmethod
    def buffer(cls, name: str) -> list[Record]:
        return cls._buffers.setdefault(name, [])

    @classmethod
    def clear(cls) -> None:
        cls._buffers.clear()

    @property
    def records(self) -> list[Record]:
        return self._buffers.setdefault(self._buffer_name, [])

    def _on_open(self, context: ExecutionContext) -> None:
        self._pending = []
        if self.mode is LoadMode.OVERWRITE:
            self._buffers[self._buffer_name] = []
        else:
            self._buffers.setdefault(self._buffer_name, [])
        self.rows_written = 0

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        self._assert_writable()
        if len(self._pending) + len(batch) > MAX_MEMORY_ROWS:
            raise LoadingError(
                "in-memory sink exceeded its row cap", context={"limit": MAX_MEMORY_ROWS}
            )
        self._pending.extend(dict(record) for record in batch.records)
        self.rows_written += len(batch)
        return len(batch)

    def commit(self) -> None:
        self._buffers.setdefault(self._buffer_name, []).extend(self._pending)
        self._pending = []

    def rollback(self) -> None:
        self._pending = []
        self.rows_written = 0


@source("generator", "synthetic")
class GeneratorSource(BaseSource):
    """Generate synthetic records - load testing and streaming simulation.

    Options: ``rows`` (default 1000), ``columns`` (list of names),
    ``rate`` (rows/second, 0 = unlimited), ``seed`` (reproducible output).
    """

    def read(self, context: ExecutionContext) -> RecordStream:
        rows = self.int_option("rows", 1000, minimum=0, maximum=MAX_MEMORY_ROWS)
        columns = self.list_option("columns", ["id", "name", "amount", "created_at"])
        rate = float(self.option("rate", 0) or 0)
        seed = self.option("seed")
        rng = random.Random(seed)  # noqa: S311 - synthetic data, not security
        batch_size = self.batch_size
        interval = 1.0 / rate if rate > 0 else 0.0

        def generate() -> Iterator[RecordBatch]:
            buffer: list[Record] = []
            sequence = 0
            for index in range(rows):
                context.cancellation.raise_if_cancelled()
                buffer.append({column: _synthetic(column, index, rng) for column in columns})
                if interval:
                    time.sleep(interval)
                if len(buffer) >= batch_size:
                    yield RecordBatch(buffer, sequence=sequence, source=self.name)
                    sequence += 1
                    buffer = []
            if buffer:
                yield RecordBatch(buffer, sequence=sequence, source=self.name)

        return generate()

    def count(self) -> int | None:
        return self.int_option("rows", 1000, minimum=0)


def _synthetic(column: str, index: int, rng: random.Random) -> Any:
    """Produce a plausible value based on the column's name."""
    lowered = column.lower()
    if lowered in {"id", "pk"} or lowered.endswith("_id"):
        return index + 1
    if "amount" in lowered or "price" in lowered or "total" in lowered:
        return round(rng.uniform(1, 10_000), 2)
    if "date" in lowered or lowered.endswith("_at"):
        return f"2026-{rng.randint(1, 12):02d}-{rng.randint(1, 28):02d}T00:00:00+00:00"
    if "email" in lowered:
        return f"user{index}@example.com"
    if "flag" in lowered or lowered.startswith("is_"):
        return rng.choice([True, False])
    return "".join(rng.choices(string.ascii_lowercase, k=8))


@sink("null", "devnull")
class NullSink(BaseSink):
    """Discard everything.  Used for dry runs and throughput benchmarking."""

    transactional = True

    def write(self, batch: RecordBatch, context: ExecutionContext) -> int:
        self.rows_written += len(batch)
        return len(batch)


__all__ = ["GeneratorSource", "MemorySink", "MemorySource", "NullSink"]
