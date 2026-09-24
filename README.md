# Enterprise ETL Data Pipeline

**IronFlow** — an enterprise ETL data pipeline platform. Pipelines are declared
in YAML, executed as a dependency graph, and every stage — extraction,
validation, transformation, loading — streams in bounded memory with a
transactional destination. A pipeline file is treated as untrusted input from
end to end.

[![CI](https://github.com/mojtaba-py-code/ironflow/actions/workflows/ci.yml/badge.svg)](https://github.com/mojtaba-py-code/ironflow/actions/workflows/ci.yml)
[![Security](https://github.com/mojtaba-py-code/ironflow/actions/workflows/security.yml/badge.svg)](https://github.com/mojtaba-py-code/ironflow/actions/workflows/security.yml)
[![CodeQL](https://github.com/mojtaba-py-code/ironflow/actions/workflows/codeql.yml/badge.svg)](https://github.com/mojtaba-py-code/ironflow/actions/workflows/codeql.yml)
[![Python 3.11–3.14](https://img.shields.io/badge/python-3.11%E2%80%933.14-blue)](https://www.python.org)
[![Tests](https://img.shields.io/badge/tests-1443-brightgreen)](https://github.com/mojtaba-py-code/ironflow/actions/workflows/ci.yml)
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-91.5%25-brightgreen)](https://github.com/mojtaba-py-code/ironflow/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Why this exists

Most ETL scripts fail the same way: they load half a dataset, leave the
destination in an unknown state, and give the on-call engineer a stack trace
instead of an answer. IronFlow is built around four guarantees that address
exactly that.

| Guarantee | How |
|---|---|
| **A failed run changes nothing** | The load engine owns the destination transaction. Nothing commits until the whole stream is consumed without error; any failure rolls back. With a quarantine, the commit is two-phase: both destinations prepare, the rejects publish first and the main data last, so a reject file that cannot be written fails the run before the main destination is touched. Non-transactional destinations declare themselves and are flagged by `pipeline validate`. |
| **Memory is a function of `batch_size`, not dataset size** | Every stage is a generator over record batches, bounded by cells as well as rows, so a hostile file cannot widen a batch into gigabytes. Operations that genuinely cannot stream (sort, join, aggregate) are marked *blocking*, documented, and capped. |
| **Bad data is quarantined, not lost** | Rejected records are routed to a reject destination together with the reason, and a reject that cannot be written fails the run rather than vanishing. Two circuit breakers (absolute count and error rate) abort a run whose data has gone systemically wrong. |
| **Configuration is untrusted input** | Pipeline files are validated with Pydantic and bounded before they are built. Expressions run in an AST sandbox, paths are confined to allow-listed roots, SQL identifiers are validated and values always bound. What a pipeline may read from the environment and where it may connect are the operator's settings, which a pipeline can narrow and never widen. |

---

## Quick start

```bash
git clone https://github.com/mojtaba-py-code/ironflow.git && cd ironflow
```

```bash
pip install -e ".[columnar,excel,api]"
```

IronFlow is not published on PyPI, and the `ironflow` package there is an
unrelated project: install from this repository or from a
[release wheel verified with `gh attestation verify`](docs/deployment.md#install),
never by bare name.

```bash
ironflow config init
```

That scaffolds `pipelines/example.yaml` and `.env.example`. Then:

```bash
ironflow pipeline validate example
```

```bash
ironflow pipeline run example --dry-run
```

```bash
ironflow pipeline run example
```

---

## A pipeline

```yaml
name: sales_daily
version: "2"
owner: data-engineering

variables:
  raw: ./data/raw
  curated: ./data/curated

defaults:
  batch_size: 10000
  retry: { max_attempts: 3, initial_delay: 2 }

tasks:
  - name: load_orders
    source:
      type: csv
      path: "${var.raw}/orders.csv"

    transformations:
      - type: normalize_columns              # "Order Date" -> order_date
      - type: cast
        columns: { order_id: integer, amount: float, order_date: date }
      - type: derive
        column: amount_with_vat
        expression: "round(amount * 1.21, 2)"
      - type: mask_pii                       # PII never reaches the warehouse
        columns: [customer_email]
        strategy: email
      - type: add_metadata
        include: [execution_id, loaded_at]

    validation:
      on_violation: quarantine
      max_error_rate: 0.05                   # abort if >5% of rows are rejected
      rules:
        - { type: not_null, field: order_id }
        - { type: unique,   field: order_id }
        - { type: range,    field: amount, min: 0,
            message: "order amount cannot be negative" }

    destination:
      type: parquet
      path: "${var.curated}/orders.parquet"
      mode: overwrite

    reject_destination:
      type: csv
      path: "${var.curated}/orders_rejected.csv"
      mode: overwrite

  - name: summarise
    depends_on: [load_orders]
    source: { type: parquet, path: "${var.curated}/orders.parquet" }
    transformations:
      - type: aggregate
        group_by: [region]
        aggregations:
          revenue: { column: amount_with_vat, function: sum }
          orders:  { column: order_id,        function: count }
    destination: { type: json, path: "${var.curated}/summary.jsonl", mode: overwrite }

schedule:
  cron: "0 2 * * *"
  timezone: Europe/Amsterdam

notifications:
  - type: slack
    target: env:SLACK_WEBHOOK_URL
    on: [failed, partial]

profiles:                                    # ironflow --profile production ...
  production:
    defaults: { batch_size: 50000 }
```

---

## Architecture

```
                        ┌──────────────────────────────────────┐
   CLI ── serve ───────►│           PipelineService            │  facade: auth,
   REST API ───────────►│  (composition root, audit, notify)   │  audit, notify
                        └───────────────────┬──────────────────┘
                                            │
                        ┌───────────────────▼──────────────────┐
                        │            PipelineRunner            │  DAG levels,
                        │   TaskGraph · parallelism · resume   │  checkpoints
                        └───────────────────┬──────────────────┘
                                            │  per task
   ┌──────────┐   ┌────────────┐   ┌────────▼─────┐   ┌────────────┐   ┌────────┐
   │  Source  │──►│ Extraction │──►│ Transform    │──►│ Validation │──►│  Load  │
   │ connector│   │ watermark  │   │ chain (lazy) │   │ quarantine │   │  txn   │
   └──────────┘   │ drift      │   └──────────────┘   └────────────┘   └────────┘
                  └────────────┘         ▲ one batch in flight per stage ▲

   cross-cutting:  config · security (crypto, secrets, RBAC, guards) ·
                   observability (structured logs, metrics, audit chain) ·
                   repositories (run history, watermarks, checkpoints)
```

Dependencies point inwards. `core` knows nothing about connectors; engines
depend only on the protocols in `core/interfaces.py`. That is what makes the
engines testable without a database and connectors replaceable without touching
the runner.

### Layout

```
src/ironflow/
  core/           types, context, errors, retry, events, registry
  config/         settings, pipeline models, YAML loader (profiles, includes)
  security/       crypto, secrets, masking, guards (path/SSRF/SQL), RBAC
  observability/  structured logging, metrics, hash-chained audit, resources
  expressions.py  AST-sandboxed expression evaluator
  connectors/     csv json xml · parquet excel · sql · rest graphql · sftp ftp · memory
  validation/     rules + enforcement engine
  transformation/ streaming ops + blocking ops + chain engine
  pipeline/       extraction, loading, task executor, runner, results
  orchestration/  task graph, cron scheduler
  repositories/   SQLAlchemy models + repository layer
  services/       facade, notifications, reporting
  cli/  api/      delivery mechanisms
```

---

## Components

**Sources** — `csv` `json`/`jsonl` `xml` `parquet` `excel` `sqlite` `postgres`
`mysql` `rest`/`http` `graphql` `sftp` `ftp`/`ftps` `memory` `generator`

**Destinations** — `csv` `json` `xml` `parquet` `excel` `sqlite` `postgres`
`mysql` `rest` `sftp` `ftp` `memory` `null`

**Transformations** — `rename` `drop` `select` `normalize_columns` `add_column`
`derive` `cast` `fill_null` `map_values` `string_ops` `split_column`
`concat_columns` `flatten` `parse_date` `convert_timezone` `convert_currency`
`filter` `add_metadata` `dedupe_batch` `hash_columns` `encrypt_columns`
`mask_pii` · blocking: `sort` `deduplicate` `aggregate` `join` `limit`

**Validation rules** — `not_null` `required_columns` `type` `range` `length`
`regex` `email` `uuid` `date_format` `in_set` `unique` `expression`
`comparison` `sequence`

`ironflow connectors list` prints the live registry.

---

## CLI

```
ironflow pipeline   run · validate · list · show · status · history · retry · resume · logs
ironflow schedule   list · start
ironflow state      clean · watermarks · audit
ironflow config     show · check · schema · init
ironflow secrets    generate-key · encrypt · decrypt
ironflow connectors list
ironflow serve
```

Exit codes are meaningful, so cron and CI can branch on them:
`0` success · `1` failure · `2` invalid configuration · `3` partial · `130` cancelled.

---

## Security

Full detail in [docs/security.md](docs/security.md). The short version:

- **No `eval`.** Expressions are parsed with `ast` and walked against an
  allow-list. Attribute access resolves through mappings, never `getattr`, so
  `().__class__.__bases__` yields `None` instead of the type graph. Powers are
  sized before they are built, and regular expressions run on a time-bounded
  engine, from literal patterns only.
- **SQL injection.** Values are always bound parameters; identifiers must fully
  match `[A-Za-z_][A-Za-z0-9_]{0,62}` and are quoted.
- **Path traversal.** Every path is resolved (following symlinks) and asserted
  to be inside an allow-listed data root - file by file inside a directory.
- **What a pipeline can read.** `env:` and `${NAME}` reach only the variables the
  operator allows, never IronFlow's own settings; `file:` only the operator's
  secret directories.
- **Where a pipeline can connect.** The SSRF policy is the operator's: private
  destinations are opened by name or range, never from YAML, and cloud metadata
  never. Every connection's address is re-checked at connect time (DNS
  rebinding), every redirect and pagination hop is re-validated, credentials go
  only to the origin they belong to, and response size is capped on decoded
  bytes while the body streams.
- **Secrets.** Pipeline files hold references (`env:`, `file:`, `enc:`), never
  values. Resolved secrets are wrapped in a `SecretStr` that renders as `***`.
- **PII.** `mask_pii`, `hash_columns` (keyed HMAC) and `encrypt_columns` run
  before the load, so plaintext never reaches the destination.
- **API.** Bearer tokens with an algorithm allow-list, pipeline scopes enforced
  on every read, and a dashboard that needs a token like everything else.
- **Audit.** Privileged actions are appended to a hash chain, keyed with the
  platform key, whose head is anchored, so `ironflow state audit --verify`
  detects an edit, a deletion - including of the last entries - or a missing
  file. A head recorded off-host (`--expect-head`) also catches the log and its
  anchor replaced together. The API, the scheduler and CLI runs can share the
  trail without forking it.
- **Production fails closed.** `Settings.validate_production_hardening()` blocks
  start-up on missing auth, literal secrets, unconfined data roots, an
  unrestricted environment or disabled TLS.
- **Supply chain.** SHA-pinned actions, signed commits on a protected `main`,
  gitleaks over the full history, a dependency audit that fails the build,
  CodeQL, a Grype-scanned container, and releases with an SBOM and signed SLSA
  provenance.

---

## Operations

```bash
ironflow pipeline history --limit 20
```

```bash
ironflow pipeline logs <execution-id>
```

```bash
ironflow pipeline resume sales_daily <execution-id>
```

Resume skips tasks that already checkpointed successfully. Watermarks advance
**only after the destination commits**, so a load that fails after extraction
never skips rows on the next run.

`ironflow serve` exposes the dashboard at `/`, Prometheus metrics at `/metrics`,
and a REST API under `/api`.

---

## Development

```bash
pip install -e ".[dev,columnar,excel,api]"
```

```bash
make check     # lint, types, tests and the secret scan - what CI runs
```

**1,443 tests, 91.5 % branch coverage** — and the numbers are
enforced, not asserted. CI fails the build below 89 %; runs the suite on Python
3.11, 3.12, 3.13 and 3.14 on Linux, and on Windows and macOS, because path
confinement is a security control and each platform resolves paths its own way;
installs without the optional extras to prove the slim path still imports; runs
the integration tests against a real PostgreSQL; and builds the container image
and runs it read-only with every capability dropped.

The security fixes are held to a stricter bar than coverage: each one has a
regression test that reproduces the original attack, and each such test was
confirmed to fail with its fix reverted. A separate workflow audits the
dependency set, scans the whole git history for secrets and reviews every
dependency a pull request adds; CodeQL and OpenSSF Scorecard run on every push.

See [docs/](docs/) for the configuration reference, deployment guide, developer
guide and troubleshooting notes; [CONTRIBUTING.md](CONTRIBUTING.md) for the
development loop and [SECURITY.md](SECURITY.md) for the disclosure policy.

## License

MIT — see [LICENSE](LICENSE).
