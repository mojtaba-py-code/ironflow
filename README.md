# IronFlow

**An enterprise ETL data pipeline platform.** Pipelines are declared in YAML,
executed as a dependency graph, and every stage — extraction, validation,
transformation, loading — streams in bounded memory with a transactional
destination.

[![CI](https://github.com/mojtaba-py-code/ironflow/actions/workflows/ci.yml/badge.svg)](https://github.com/mojtaba-py-code/ironflow/actions/workflows/ci.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org)
[![Tests](https://img.shields.io/badge/tests-979%20passing-brightgreen)](https://github.com/mojtaba-py-code/ironflow/actions/workflows/ci.yml)
[![Branch coverage](https://img.shields.io/badge/branch%20coverage-90%25-brightgreen)](https://github.com/mojtaba-py-code/ironflow/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Why this exists

Most ETL scripts fail the same way: they load half a dataset, leave the
destination in an unknown state, and give the on-call engineer a stack trace
instead of an answer. IronFlow is built around four guarantees that address
exactly that.

| Guarantee | How |
|---|---|
| **A failed run changes nothing** | The load engine owns the destination transaction. Nothing commits until the whole stream is consumed without error; any failure rolls back. Non-transactional destinations declare themselves and are flagged by `pipeline validate`. |
| **Memory is a function of `batch_size`, not dataset size** | Every stage is a generator over record batches. Operations that genuinely cannot stream (sort, join, aggregate) are marked *blocking*, documented, and capped. |
| **Bad data is quarantined, not lost** | Rejected records are routed to a reject destination together with the reason. Two circuit breakers (absolute count and error rate) abort a run whose data has gone systemically wrong. |
| **Configuration is untrusted input** | Pipeline files are validated with Pydantic, expressions run in an AST sandbox, paths are confined to allow-listed roots, SQL identifiers are validated and values always bound, and outbound URLs pass an SSRF guard. |

---

## Quick start

```bash
pip install -e ".[columnar,excel,api]"
```

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
  `().__class__.__bases__` yields `None` instead of the type graph.
- **SQL injection.** Values are always bound parameters; identifiers are
  validated against `^[A-Za-z_][A-Za-z0-9_]*$` and quoted.
- **Path traversal.** Every path is resolved (following symlinks) and asserted
  to be inside an allow-listed data root.
- **SSRF.** Outbound URLs are validated — scheme, host allow-list, and rejection
  of private/loopback/link-local addresses — and every pagination hop and
  redirect is re-validated.
- **Secrets.** Pipeline files hold references (`env:`, `file:`, `enc:`), never
  values. Resolved secrets are wrapped in a `SecretStr` that renders as `***`.
- **PII.** `mask_pii`, `hash_columns` (keyed HMAC) and `encrypt_columns` run
  before the load, so plaintext never reaches the destination.
- **Audit.** Privileged actions are appended to a SHA-256 hash chain;
  `ironflow state audit --verify` detects any edit or deletion.
- **Production fails closed.** `Settings.validate_production_hardening()` blocks
  start-up on missing auth, literal secrets, unconfined data roots or disabled
  TLS.

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
make check     # lint + types + 979 tests + secret scan, i.e. everything CI runs
```

**979 tests, 90 % branch coverage** — and the numbers are enforced, not
asserted: CI fails the build below 88 %, runs the suite on Python 3.11 and 3.12
across Linux and Windows, installs without the optional extras to prove the slim
path still imports, runs the integration tests against a real PostgreSQL, audits
the dependency tree and builds the container image.

See [docs/](docs/) for the configuration reference, deployment guide, developer
guide and troubleshooting notes; [CONTRIBUTING.md](CONTRIBUTING.md) for the
development loop and [SECURITY.md](SECURITY.md) for the disclosure policy.

## License

MIT — see [LICENSE](LICENSE).
