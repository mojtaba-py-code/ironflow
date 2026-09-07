# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-07

First stable release.

### Core

- Streaming record-batch pipeline: extraction → transformation → validation →
  loading, composed as one lazy generator chain so peak memory is a function of
  `batch_size` rather than dataset size.
- Transactional loading. The load engine owns the destination transaction;
  nothing commits until the whole stream is consumed without error. File sinks
  stage and publish atomically; SQL sinks wrap the load in one transaction and
  use `DELETE` rather than `TRUNCATE` for overwrite, so a rolled-back run leaves
  the destination byte-identical.
- Full, incremental and CDC load strategies. The watermark advances only after
  the destination commits, with a configurable overlap window and business-key
  deduplication for late-committed rows.
- Schema-drift detection with `strict` / `additive` / `permissive` policies.
- DAG orchestration with level-based parallelism, conditional branching,
  per-task retries with exponential backoff and full jitter, checkpointing and
  resume, and cooperative cancellation.

### Connectors

- Sources: CSV, JSON/JSON Lines, XML, Parquet, Excel, SQLite, PostgreSQL,
  MySQL, REST, GraphQL, SFTP, FTP/FTPS, in-memory and a synthetic generator.
- Destinations: CSV, JSON, XML, Parquet, Excel, SQLite, PostgreSQL, MySQL,
  REST, SFTP, FTP, in-memory and null.
- Optional dependencies degrade with an actionable message rather than breaking
  the import, so a slim install still runs the CSV/SQL/REST paths.

### Data quality

- 14 validation rules plus a compact declarative `schema:` block.
- Violation policies: `fail`, `quarantine` (default), `drop`, `warn`.
- Two circuit breakers — absolute reject count and reject rate — with a
  warm-up so one bad first row cannot trip a 5 % threshold.

### Transformations

- 22 streaming operations and 5 blocking ones. Blocking operations declare
  themselves, document their memory profile and enforce a row cap.
- Privacy transformations (`mask_pii`, `hash_columns`, `encrypt_columns`) run
  before the load, so plaintext never reaches the destination.

### Security

- AST-sandboxed expression evaluator. No `eval`; attribute access resolves
  through mappings rather than `getattr`. 27 documented escape techniques are
  covered by tests.
- SQL injection prevention: values always bound, identifiers validated and
  quoted.
- Path-traversal confinement that resolves symlinks before comparing.
- SSRF guard applied to the configured URL and re-applied to every redirect and
  pagination hop.
- Secret references (`env:`, `file:`, `enc:`) with a non-`str` `SecretStr`
  wrapper; Fernet encryption with scrypt-derived keys.
- RBAC with four least-privilege roles and pipeline-name scoping; HS256 JWT
  verification that checks the algorithm allow-list before verifying.
- Hash-chained, tamper-evident audit trail with `state audit --verify`.
- Production hardening check that fails closed on missing auth, literal secrets,
  unconfined data roots, disabled TLS or a SQLite control plane.
- One rule is not conditional on the environment: with `auth_enabled` true, a
  `jwt_secret` under 32 characters refuses to construct `Settings` at all. HMAC
  with an empty key is still a valid HMAC, so an unkeyed staging deployment
  would verify an `admin` token the caller signed themselves. `issue_token` and
  `verify_token` refuse an empty secret independently.
- The expression evaluator bounds `pow()` the same way it bounds `**`:
  `pow(2, 5_000_000)` builds a five-million-bit integer in under a second, so the
  function table needed the same lock as the operator.

### Observability

- Structured JSON logging with correlation/execution/pipeline/task ids and
  automatic secret redaction on every handler.
- Prometheus-compatible metrics registry that also snapshots into run history,
  so a short-lived batch job records its metrics before exiting.
- Run history, per-task breakdowns, watermarks, checkpoints and schema
  snapshots in a SQLAlchemy control plane (SQLite or PostgreSQL).
- Peak RSS and CPU sampling per run.

### Interfaces

- Typer CLI with meaningful exit codes (`0` success, `1` failure, `2` invalid
  configuration, `3` partial, `130` cancelled) - including a rejected *setting*,
  which is raised while the settings object is built and would otherwise escape
  as a traceback with exit code 1.
- `config init` scaffolds the example pipeline's input alongside it, so the four
  commands the README opens with complete instead of ending in an
  `ExtractionError` against a path that was never created.
- Console output survives a redirected stdout on Windows. The run summary
  contains characters the ANSI code page cannot encode, which made
  `ironflow pipeline run x > run.log` fail *after* a successful load.
- Optional FastAPI REST API, server-rendered dashboard and `/metrics` endpoint.
- Self-contained HTML and JSON run reports.

### Notable design decisions

- **Custom YAML loader.** PyYAML implements YAML 1.1, where `on`, `off`, `yes`
  and `no` are booleans. That broke the `on:` notification key and silently
  turned the ISO-3166 country code `NO` into `False`. The loader keeps only
  `true`/`false`.
- **Text arithmetic is refused.** `"12.50" * 2` is valid Python and evaluates to
  `"12.5012.50"`. Over an uncast CSV column that is a plausible-looking wrong
  value that reaches the warehouse, so mixed text/number arithmetic raises and
  the record follows the `on_error` policy.
- **Retries wrap the whole task, never a batch.** Retrying at batch granularity
  against a non-idempotent destination creates duplicates; the task retry rolls
  back first.
- **A shared TLS context.** Constructing an `httpx.Client` re-parses the CA
  bundle each time (~1.4 s measured); the context is now built once per process.

### Quality

- 979 tests, 90 % branch coverage, enforced by a CI floor of 88 %.
- `ruff check`, `ruff format --check` and `mypy` clean.
- CI matrix over Python 3.11/3.12 on Linux and Windows, plus a slim-install job,
  a PostgreSQL integration job, a dependency audit, a committed-secret scan and
  a container build.

[1.0.0]: https://github.com/mojtaba-py-code/ironflow/releases/tag/v1.0.0
