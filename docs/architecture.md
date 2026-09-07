# Architecture

## The shape of the system

```
                        ┌──────────────────────────────────────┐
   CLI ── serve ───────►│           PipelineService            │  composition root:
   REST API ───────────►│  authorisation · audit · notify      │  builds everything
                        └───────────────────┬──────────────────┘
                                            │
                        ┌───────────────────▼──────────────────┐
                        │            PipelineRunner            │  DAG levels,
                        │  TaskGraph · thread pool · resume    │  checkpoints
                        └───────────────────┬──────────────────┘
                                            │  one TaskExecutor per task
   ┌──────────┐   ┌────────────┐   ┌────────▼─────┐   ┌────────────┐   ┌────────┐
   │  Source  │──►│ Extraction │──►│  Transform   │──►│ Validation │──►│  Load  │
   │ connector│   │ watermark  │   │ chain (lazy) │   │ quarantine │   │  txn   │
   └──────────┘   │ drift check│   └──────────────┘   └────────────┘   └────────┘
                  └────────────┘
                     ◄────── one batch in flight per stage ──────►

   cross-cutting:  config · security · observability · repositories
```

## Layers and the dependency rule

Dependencies point **inwards**. An arrow may go from an outer ring to an inner
one, never the reverse.

| Ring | Package | Knows about |
|---|---|---|
| 0 | `core` | nothing but the standard library |
| 0 | `expressions` | `core` |
| 1 | `config`, `security`, `observability` | `core` |
| 2 | `connectors`, `validation`, `transformation` | `core`, `config`, `security` |
| 3 | `pipeline`, `orchestration`, `repositories` | rings 0–2, via protocols |
| 4 | `services` | everything below |
| 5 | `cli`, `api` | `services` |

The rule is enforced by the shape of the imports, and it is what makes the
engines testable: `TaskExecutor` depends on `DataSource` and `DataSink`
*protocols* from `core/interfaces.py`, never on `CsvSource`. Swapping a
connector, or substituting an in-memory one in a test, changes nothing above.

## The data path

### Record batches, not DataFrames

The transport type is `Iterator[RecordBatch]`, where a `RecordBatch` wraps
`list[dict[str, Any]]`. Three reasons:

1. **Bounded memory.** Peak RSS is a function of `batch_size`, not of source
   size. A 40 GB export streams through a 10,000-row window.
2. **Heterogeneity.** REST, GraphQL and XML produce ragged, nested records.
   Forcing them into a rectangle up front loses information and costs a copy.
3. **Dependency isolation.** `pandas`/`pyarrow` stay optional extras used only
   by the columnar connectors.

### Where streaming stops

Sorts, joins, aggregations and global deduplication cannot stream. They are
implemented as `StreamTransformation` with `blocking = True`, they log what they
materialise, and they enforce a `max_rows` cap. The engine logs which steps are
blocking at task start, so a surprising memory profile is diagnosable from the
run log rather than from a core dump.

The cap is deliberate. A job that dies at 03:10 naming the transformation is
strictly better than a container OOM-killed with no diagnostics. Every
docstring says the same thing: if the dataset genuinely exceeds memory, push the
operation into the source query, where an index and spill-to-disk already exist.

### Lazy composition

`TaskExecutor._build_stream` wires the stages into one generator chain:

```python
stream = extraction.read(source, context)  # generator
stream = validate(stream)  # generator (optional, pre-transform)
stream = transformations.apply(stream, ctx)  # generator chain
stream = validate(stream)  # generator (default, post-transform)
load_engine.load(stream, context)  # the only consumer
```

Nothing runs until the load engine pulls. Consecutive batch-level
transformations are *fused* into a single pass, so a chain of ten renames costs
one loop over each batch rather than ten.

## Transaction model

The load engine owns the destination's transaction boundary:

```
open() → write(batch)* → commit()          success
open() → write(batch)* → rollback()        any exception
```

Nothing commits until the whole stream is consumed without error. For a
transactional destination — SQL, staged files, Parquet — a failed run leaves the
destination byte-identical to how it started.

File sinks achieve this by staging: output goes to a sibling temporary file and
is published in `commit()` with `Path.replace` (atomic on POSIX and Windows).
`rollback()` deletes the staging file.

SQL sinks wrap the whole load in one transaction. `mode: overwrite` issues
`DELETE FROM` rather than `TRUNCATE`, because TRUNCATE is DDL on several engines
and implicitly commits — which would break exactly this guarantee.

Destinations that cannot be transactional (REST) declare `transactional = False`,
the engine warns at open time, and `ironflow pipeline validate` reports it. The
limitation is known before the incident rather than during it.

## Incremental extraction

The watermark advances **only after the destination commits**:

```python
load_result = load_engine.load(stream, context)
if load_result.committed:
    extraction.commit_watermark(context)
```

Advancing optimistically is how rows get silently skipped forever when a load
fails after extraction.

### The overlap window

A row inserted in a transaction that commits at 10:00:05 may carry
`updated_at = 10:00:00`. If the previous run's mark was 10:00:02 that row is
invisible for ever. Configuring `overlap: 30` rewinds the mark by 30 seconds on
each read; `key_columns` then deduplicates the rows the overlap re-delivers.

Overlap applies only to *temporal* watermarks. Subtracting seconds from an
auto-increment id would re-read an arbitrary number of rows, so
`_apply_overlap` returns a non-temporal watermark unchanged.

## Orchestration

`TaskGraph` runs Kahn's algorithm and returns **levels** rather than a flat
topological order. Every task in a level has its dependencies satisfied, so the
level executes concurrently — that is where a pipeline's parallelism comes from.
Whatever the algorithm cannot emit is exactly the cycle, so cycle reporting names
the participating tasks for free.

Threads, not processes: ETL tasks are I/O bound and every blocking call releases
the GIL, so threads give real concurrency with shared connection pools and no
pickling of batches. CPU-bound transformation is the exception, and the honest
answer there is to push the work into the database.

Cancellation is cooperative. SIGINT sets a token; tasks check it between
batches; in-flight transactions roll back cleanly. Killing threads mid-write is
how a half-committed load happens.

## Failure handling

| Level | Mechanism |
|---|---|
| Record | Validation policy: `fail`, `quarantine` (default), `drop`, `warn` |
| Batch | Not retried — a partially loaded non-idempotent destination would duplicate |
| Task | Retry with exponential backoff and full jitter, after a rollback |
| Pipeline | `on_failure: fail` abandons downstream tasks; `continue` yields `PARTIAL` |
| Run | Checkpoints let `pipeline resume` restart at the failure |

Retries wrap the *whole task*, never individual batches, and the rollback runs
first — so attempt 2 starts from a clean destination.

Two circuit breakers stop a systemically broken run: an absolute reject count
(`max_errors`) and a reject rate (`max_error_rate`). The rate breaker arms only
after 100 records, otherwise one bad first row trips a 5 % threshold.

## Extension points

Adding a connector, transformation or rule means writing a class and decorating
it. No engine code changes:

```python
from ironflow.connectors.base import BaseSource, source


@source("kafka")
class KafkaSource(BaseSource):
    def read(self, context):
        yield from ...
```

The registries reject anything not explicitly registered, so a pipeline file can
never name an arbitrary import path — the worst a malicious YAML can do is
request a component that does not exist.

## Design decisions worth knowing

| Decision | Why |
|---|---|
| Custom YAML loader | PyYAML implements YAML 1.1, where `on`/`no`/`yes` are booleans. `on: [failed]` broke, and `NO` (Norway) became `False`. The loader keeps only `true`/`false`. |
| AST expression sandbox instead of `eval` | A pipeline file is configuration that more people can write than can deploy. `eval` there is remote code execution. |
| Own metrics registry | The platform runs as a short-lived batch job as often as a service; a pull-only client cannot snapshot metrics into run history at exit. |
| Own scheduler | ~200 lines, and it needs the run history to enforce `max_concurrent_runs`, which an external library cannot see. |
| Own HS256 JWT verification | Three lines of `hmac`, and it lets the algorithm allow-list be checked *before* verification — the `alg: none` bypass. |
| Hash-chained audit log | Compliance asks for tamper-*evidence*, not tamper-proofing. A chain gives that in 100 lines. |
| Validation after transformation by default | A `type: integer` rule must see the cast value, not the raw CSV string. |
