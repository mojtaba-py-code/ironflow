# Developer guide

## Setup

```bash
pip install -e ".[dev,columnar,excel,remote,api]"
```

```bash
pre-commit install
```

```bash
make check      # lint + types + tests + security, i.e. what CI runs
```

---

## Adding a connector

A connector is a class plus a decorator. No engine code changes.

```python
# src/ironflow/connectors/kafka.py
from collections.abc import Iterator

from ironflow.connectors.base import BaseSource, source
from ironflow.core.context import ExecutionContext
from ironflow.core.errors import ExtractionError
from ironflow.core.types import RecordBatch, RecordStream


@source("kafka")
class KafkaSource(BaseSource):
    """Consume a Kafka topic.

    Options: ``brokers`` (required), ``topic`` (required), ``group_id``,
    ``max_messages``.
    """

    def _on_open(self, context: ExecutionContext) -> None:
        self._consumer = ...  # acquire here, not in __init__

    def read(self, context: ExecutionContext) -> RecordStream:
        batch_size = self.batch_size

        def generate() -> Iterator[RecordBatch]:
            buffer, sequence = [], 0
            for message in self._consumer:
                context.cancellation.raise_if_cancelled()  # cooperative shutdown
                buffer.append(self._decode(message))
                if len(buffer) >= batch_size:
                    yield RecordBatch(buffer, sequence=sequence, source=self.name)
                    sequence += 1
                    buffer = []
            if buffer:
                yield RecordBatch(buffer, sequence=sequence, source=self.name)

        return generate()

    def _on_close(self) -> None:
        self._consumer.close()
```

Register it by importing the module in `connectors/__init__.py` — those imports
are load-bearing, not incidental.

### The rules a connector must follow

1. **Yield, do not accumulate.** Returning a list defeats the whole streaming
   design.
2. **Check cancellation between batches.** `context.cancellation.raise_if_cancelled()`.
3. **Resolve options through the base helpers.** `self.option`, `self.int_option`,
   `self.secret_option` — they give consistent errors and route secrets through
   the resolver.
4. **Resolve paths through the runtime.** `self.runtime.resolve_path(p)` applies
   the data-root confinement.
5. **Make HTTP calls through `ironflow.security.net.build_client`**, with the
   operator's `NetworkPolicy.from_settings(...)` narrowed by the connector's
   options - never a bare `httpx.Client`. The guarded client re-checks every
   connection's address (DNS rebinding), ignores proxy variables and follows no
   redirects; read bodies with `read_capped`, and pass credentials per request,
   only to the origin they belong to. `validate_url(url, policy=...)` gives an
   early, readable error but is not the control on its own.
6. **Never format values into SQL.** Bind them; validate identifiers.
7. **Make `open`/`close` idempotent.** The base class handles the bookkeeping if
   you implement `_on_open`/`_on_close`.
8. **Be honest about `transactional`.** If `rollback()` cannot actually undo the
   writes, leave it `False`. The engine warns and `validate` reports it.
9. **Wrap driver exceptions** in `ExtractionError`/`LoadingError`/`ConnectionError`
   with context, so retry classification works.

For a sink, stage and publish in `commit()` — see `_StagedFileSink` for the
pattern.

---

## Adding a transformation

Per-record — the common case:

```python
from ironflow.transformation.base import RecordTransformation, transformation


@transformation("redact_domain")
class RedactDomain(RecordTransformation):
    """Replace the domain part of an email.

    Options: ``columns`` (required), ``replacement``.
    """

    def __init__(self, spec):
        super().__init__(spec)
        self._columns = self.list_option("columns", required=True)
        self._replacement = self.str_option("replacement", "example.com")

    def transform_record(self, record, context):
        out = dict(record)
        for column in self._columns:
            value = out.get(column)
            if isinstance(value, str) and "@" in value:
                out[column] = value.split("@")[0] + "@" + self._replacement
        return out  # return None to drop the record
```

Returning `None` drops the record — that is how filters are expressed without a
separate mechanism.

Whole-stream transformations subclass `StreamTransformation`, set
`blocking = True`, **document the memory profile in the class docstring** and
enforce a `max_rows` cap. See `transformation/blocking.py`.

Parse options in `__init__`, not per record: a bad option should fail once at
task start, not a million times.

---

## Adding a validation rule

```python
from ironflow.validation.rules import Rule, rule


@rule("iban")
class IbanRule(Rule):
    """The field must be a structurally valid IBAN."""

    def check(self, record, index):
        field = self.require_field()
        value = record.get(field)
        if value is None:
            return []
        if _iban_checksum_ok(str(value)):
            return []
        return [self.violation(f"'{field}' is not a valid IBAN", index)]
```

`check` returns violations; it does not raise for bad data. A
`ConfigurationError` *does* propagate — a misconfigured rule fires on every
record, so burying it under a million warnings is worse than failing.

Stateful rules must implement `reset()` and cap their memory.

---

## Testing

```bash
pytest -q                                  # everything
pytest tests/test_security.py -q           # one module
pytest --cov=ironflow --cov-report=html    # coverage
pytest -m "not integration" -q             # skip filesystem/database tests
```

### Fixtures

`conftest.py` gives every test an isolated `tmp_path` home, its own SQLite
state database and a fresh `Settings`. Use them:

| Fixture | Gives you |
|---|---|
| `settings` | Settings confined to `tmp_path` |
| `database` | initialised state database |
| `factory` | `ConnectorFactory` |
| `context` | `ExecutionContext` with metrics and an event bus |
| `service` | fully wired `PipelineService` |
| `csv_file`, `sample_records`, `batch` | data |

### Testing a pipeline without touching the disk

```python
from ironflow.connectors.memory import MemorySink, MemorySource


def test_pipeline(runner):
    MemorySource.register("orders", [{"id": 1, "amount": 100}])
    pipeline = PipelineSpec.model_validate(
        {
            "name": "p",
            "tasks": [
                {
                    "name": "t",
                    "source": {"type": "memory", "dataset": "orders"},
                    "destination": {"type": "memory", "buffer": "out", "mode": "overwrite"},
                }
            ],
        }
    )
    result = runner.run(pipeline, install_signal_handlers=False)
    assert result.status is RunStatus.SUCCESS
    assert MemorySink.buffer("out") == [{"id": 1, "amount": 100}]
```

`MemorySink` only publishes on commit, so you can assert that a failed run wrote
nothing.

### Testing HTTP

Never hit the network. `httpx.MockTransport` plus the `_stub` helper in
`tests/test_connectors.py` gives a deterministic server.

### What a good test asserts here

Name the behaviour, not the implementation, and say *why* it matters when the
reason is not obvious:

```python
def test_watermark_is_not_advanced_on_failure(...):
    assert watermarks.get("p", "t") is None, "advancing here would skip the rows forever"
```

The security suites are executable threat models — each parametrised case is a
real attack. Do not weaken one to make something else pass.

---

## Code standards

```bash
ruff check . && ruff format --check . && mypy
```

- Line length 100, formatted by `ruff format`.
- Full type hints on every public function; `mypy` runs with
  `disallow_untyped_defs`.
- Docstrings explain **why**, not what. The signature says what.
- Exceptions derive from `IronFlowError` and carry `context`.
- Log through `logging.getLogger(__name__)`; never `print`.
- Never log a secret. If you must log a structure, pass it as an `extra` — the
  redaction filter handles nested mappings.

### The dependency rule

Dependencies point inwards (see [architecture.md](architecture.md)). `core` must
not import from `connectors`; engines depend on the protocols in
`core/interfaces.py`, never on a concrete connector. If you find yourself adding
an import that points outwards, the abstraction is in the wrong place.

---

## Release

1. Bump `src/ironflow/version.py` and `pyproject.toml`.
2. Update `CHANGELOG.md`.
3. `make check`.
4. `make build`.
5. Tag `v1.x.y`.
