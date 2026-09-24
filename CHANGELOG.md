# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] - 2026-09-24

A security release. The whole codebase went through an adversarial review -
six reviews, one per area, each finding reproduced with a proof of concept
before it was fixed - and the repository and its supply chain were hardened
alongside. Every fix below has a regression test that reproduces the original
attack, and each of those tests was confirmed to fail with its fix reverted.

### Security

- **A pipeline file can no longer read past itself.** `env:` references and
  `${NAME}` interpolation resolved any variable in the process, and `file:`
  any file the process could open; a REST sink then carried the value to any
  public host the file named - `token: env:IRONFLOW_JWT_SECRET` sent the API's
  signing key out as a bearer header. IronFlow's own settings are now never
  readable, `IRONFLOW_PIPELINE_ENV` allow-lists the rest, and `file:` works
  only inside `IRONFLOW_SECRET_FILE_ROOTS`.
- **The SSRF guard belongs to the operator.** A connector's
  `allow_private_network: true` overrode the platform setting - in production
  too. A pipeline can now only narrow the network policy; internal APIs are
  opened by name or CIDR range with `IRONFLOW_HTTP_PRIVATE_HOSTS`, all egress
  can be bounded with `IRONFLOW_HTTP_ALLOWED_HOSTS`, and link-local addresses
  (cloud metadata) are never reachable. Addresses are judged by `is_global`,
  which also catches carrier-grade NAT.
- **DNS rebinding.** The guard resolved a host and then httpx resolved it again
  to connect. Connections are now checked inside the transport, on the address
  actually dialled; proxy environment variables are ignored.
- **Credentials stay with their origin.** A redirect or a `next` link to another
  host received the bearer token; credentials and custom headers now go only
  to the configured origin.
- **Responses are capped while they stream.** The size limit was checked after
  httpx had read and decompressed the whole body - 200 KB of gzip became 200 MB
  before a 1 MB cap was consulted. Bodies are now inflated under zlib's
  `max_length`; the same bomb peaks at about 2 MB.
- **API scopes hold on every read.** A principal scoped to `sales_*` read `hr_*`
  runs through `/api/runs`, `/api/runs/{id}`, `/api/statistics` and `/metrics`.
  Those reads now filter by scope, an out-of-scope run is a 404, `/metrics`
  needs an unscoped principal, and the dashboard needs a token when
  authentication is on - it rendered every pipeline to anyone. CORS no longer
  runs in credentials mode.
- **`pipeline resume` refuses another pipeline's execution id** - and an
  unknown one; a principal scoped to one pipeline could resume under another's
  id, rewrite its run history and skip its tasks.
- **Expression sandbox.** Powers of integers past float range are sized
  correctly (`(10**1000) ** 5000` built a sixteen-million-bit integer), and
  `decimal` errors follow `on_error` instead of aborting the run.
- **ReDoS.** Regular expressions from pipeline files run on the `regex` engine
  with a per-match timeout, are disabled after repeated timeouts, and
  `regex_match` accepts only a literal pattern. `(a+)+$` took 45 seconds on a
  26-character value.
- **YAML.** Documents are size-capped and their alias expansion bounded
  (387 million nodes fitted in under 500 bytes); recursive aliases and pipeline
  names declared by more than one file are refused.
- **SMTP** STARTTLS verifies the server's certificate.
- **SQL identifiers** must match in full - `re.match` with `$` accepted
  `"orders\n"` - and the raw `where` screen also refuses time-delay and
  server-side file functions and `#` comments.
- **Terminal output.** Pipeline fields and run data are printed as plain text:
  an `owner: "[/x]"` crashed `pipeline list` for the whole directory, and Rich
  markup or escape sequences in a pipeline reached the operator's terminal.
- **Redaction.** A database password containing `/` - routine in base64 - or
  passed as a query parameter was printed by `config show`, `config check` and
  error logs. URLs are now redacted by a parser, not a regex, and a token
  given as the user name (`https://<token>@host`) is masked too.
- **Install advice.** Error messages and guides told operators to install
  `ironflow[api]`, `ironflow[columnar]` and the like by name. IronFlow is not
  on PyPI, and the `ironflow` package there is another project, so wherever
  IronFlow was not installed yet the advice installed someone else's code. The
  messages now name each extra's own packages, and a test fails if bare-name
  advice returns.
- **Audit trail.** Deleting the last entries - or the whole file - still
  verified as intact, and anyone who could edit the file could re-derive the
  chain. The chain is now keyed from the platform key and its head anchored, so
  truncation, deletion and edits are all detected, and an operator can verify
  against a head recorded off-host. The API, the scheduler and CLI runs share
  the trail safely: each process chained from the head it read at start-up, so
  the first run after another process's forked the chain, and verification
  reported tampering that never happened.

### Fixed

- **A failed run publishes nothing.** The main destination was published before
  the reject destination; when the reject publish failed, the main file stayed
  replaced while the run reported failure, and the re-run loaded the rows again.
  The commit is now two-phase: both destinations prepare, the rejects publish
  first and the main data last.
- **Rejects are never silently lost.** A reject that cannot be written fails the
  load; it used to be logged and dropped while the report still counted it.
- **One lone surrogate no longer blocks a feed.** A legal JSON `"\ud83d"` failed
  the main sink on every retry and emptied the quarantine at the reject sink.
  File and HTTP sources replace lone surrogates; text sinks escape what their
  encoding cannot hold.
- **`append` no longer corrupts whole-document formats.** It produced invalid
  JSON arrays and XML and silently replaced Excel and Parquet files. Sinks now
  declare their modes and refuse the rest at validation; `mode` defaults to the
  destination's own default.
- **Memory follows `batch_size` for hostile input.** Excel rows no wider than
  the header, CSV `max_columns` and cell-bounded batches, XML records detached
  as they are read, Parquet directories read batch by batch, and a 100 MiB
  default for whole JSON documents.
- **Formula neutralisation covers headers**, in CSV, Excel and the reject CSV.
- **`on_violation: warn` keeps the row.** It dropped the record from the load and
  quarantined it, contrary to its documentation.
- `skip_rows` stops at end of file, honours cancellation and is capped.
- Parquet directories are confined file by file (a symlink inside one escaped
  the data roots).
- The XML writer always produces well-formed XML, and its declaration names the
  encoding actually used.
- The Excel sink writes a header row when `columns:` is set.
- `strategy: incremental` is refused on file sources, which never applied the
  watermark.
- `enc:` references decrypt in connectors, which were built without the key.
- `pipeline logs` shows the per-task breakdown; task results were never
  recorded.
- `--json` output is plain JSON under `FORCE_COLOR` or on a terminal; piped to
  `jq`, it carried Rich's colour escape sequences.

### Changed - upgrade notes

- Production requires `IRONFLOW_PIPELINE_ENV`.
- `file:` references require `IRONFLOW_SECRET_FILE_ROOTS`.
- A connector's `allow_private_network: true` is refused unless the platform
  allows private networks; list internal APIs in `IRONFLOW_HTTP_PRIVATE_HOSTS`.
- `regex_match` takes its pattern as a string literal.
- With authentication on, the dashboard needs a token, and `/metrics` a
  principal without a pipeline scope.
- `mode: append` is refused on JSON-array, XML, Excel, Parquet, SFTP and FTP
  destinations, and `mode` defaults to what the destination supports.
- HTTP clients ignore proxy environment variables.
- A URL's user name without a password is masked in logs and output
  (`postgresql://***@db/prod`): it cannot be told apart from a token.
- An audit log from an earlier version has no head anchor; the first audited
  action after the upgrade creates it. Rotating `IRONFLOW_ENCRYPTION_KEY` now
  means closing the audit trail first - see `docs/deployment.md`.
- The container image runs Python 3.14, without `curl` or `pip`;
  docker-compose requires `POSTGRES_PASSWORD` and runs read-only.

### Supply chain and CI

- The dependency audit now audits: it had failed on every run behind
  `continue-on-error`, so no advisory was ever reported.
- gitleaks over the full history, the project scanner in CI (as SECURITY.md
  had claimed), dependency review on pull requests, and a weekly run.
- Python 3.11-3.14 on Linux, Windows and macOS; the container smoke-tested
  read-only with every capability dropped and scanned with Grype.
- OpenSSF Scorecard; persist-credentials off and timeouts on every job.
- Releases carry a CycloneDX SBOM, checksums and SLSA build provenance signed
  through Sigstore.
- The base image is pinned by digest; Dependabot is limited to security
  updates, the dev toolchain, the actions and the image digest.
- The licence is an SPDX expression and the version has one source of truth.

### Quality

- 1,443 tests, 91.5 % branch coverage; the CI floor rises to 89 %.
- The configuration reference is tested against the settings model, so a
  setting can no longer go undocumented.

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
- Bounded aggregates (`count_distinct`, `list`, `concat`) raise when they reach
  their limit instead of returning a truncated result. Answering `1000000` for a
  group that holds more distinct values is a wrong number that looks entirely
  right, and it reaches the warehouse with nothing marking it.
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
- The expression evaluator bounds `pow()` the same way it bounds `**`, and both
  bound the *result* rather than the exponent. Capping the exponent alone
  rejected `1.05 ** 240` — twenty years of monthly compound interest — while
  `pow(2, 5_000_000)` walked straight past the operator guard.
- `hash_columns` accepts only collision-resistant fixed-length digests.
  `hashlib.new("md5", ...)` succeeds silently, which in the one operation whose
  purpose is irreversibility is the wrong default. Rejected when the
  transformation is built, so `pipeline validate` catches it.

### Observability

- Structured JSON logging with correlation/execution/pipeline/task ids and
  automatic secret redaction on every handler. Redaction runs over the formatted
  message and its arguments, not the format string alone: a DSN passed as an
  argument - the commonest way to write it - was reaching disk in plaintext, and
  a `%s` sitting inside the credential region was itself deleted by the scrub,
  after which the record could no longer be interpolated and the line was
  dropped in favour of a TypeError on stderr.
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
  The `202` from a run trigger returns the id the run actually executes under,
  so `GET /api/runs/{execution_id}` resolves; the endpoint used to mint an id
  for the response and let the runner invent a different one, which made every
  poll a 404.
- Self-contained HTML and JSON run reports.

### Notable design decisions

- **A pipeline that will not load says why.** Looking one up by name used to
  swallow the validation error and report `no pipeline named 'sales' was found`,
  which sends an operator hunting for a file that is sitting right there - and
  `pipeline list` then suggested `config init`, which would have scaffolded over
  it. Both now name the real problem.
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

- 1013 tests, 90 % branch coverage, enforced by a CI floor of 88 %.
- `ruff check`, `ruff format --check` and `mypy` clean.
- CI matrix over Python 3.11/3.12 on Linux and Windows, plus a slim-install job,
  a PostgreSQL integration job, a dependency audit, a committed-secret scan and
  a container build.
- The container build context is an allow-list: without a `.dockerignore` every
  local checkout uploaded its `.mypy_cache`, its `.venv` and - the part that
  matters - `.ironflow/state.db`, `logs/` and `data/curated/`, which is run
  history and processed data, to the Docker daemon on every build.

[1.1.0]: https://github.com/mojtaba-py-code/ironflow/releases/tag/v1.1.0
[1.0.0]: https://github.com/mojtaba-py-code/ironflow/releases/tag/v1.0.0
