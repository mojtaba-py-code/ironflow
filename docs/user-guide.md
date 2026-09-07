# User guide

From zero to a running pipeline.

---

## 1. Install and scaffold

```bash
pip install "ironflow[columnar,excel]"
```

```bash
ironflow config init
```

That writes `pipelines/example.yaml` and `.env.example`.

```bash
cp .env.example .env
```

Set `IRONFLOW_DATA_ROOTS` to the directories your pipelines may read and write.

---

## 2. Write a pipeline

A pipeline is a name, a list of tasks, and — per task — a source, some
transformations, a data-quality contract and a destination.

```yaml
name: orders
tasks:
  - name: load
    source:
      type: csv
      path: ./data/orders.csv
    destination:
      type: parquet
      path: ./data/orders.parquet
      mode: overwrite
```

That is a complete, valid pipeline. Everything else is refinement.

### The order of transformations matters

A chain that works:

```yaml
transformations:
  - type: normalize_columns          # 1. predictable names first
  - type: cast                       # 2. real types, before anything computes
    columns: {order_id: integer, amount: float, discount: float}
  - type: fill_null                  # 3. no nulls in the arithmetic
    columns: {discount: 0.0}
  - type: filter                     # 4. filter early: fewer rows downstream
    expression: "amount is not None"
  - type: derive                     # 5. now compute
    column: net
    expression: "round(amount * (1 - discount), 2)"
  - type: mask_pii                   # 6. privacy before the load
    columns: [customer_email]
    strategy: email
  - type: add_metadata               # 7. lineage on the finished record
    include: [execution_id, loaded_at]
```

The most common mistake is skipping step 2 for a column that step 5 uses. CSV
gives you strings; `"12.50" * 2` is `"12.5012.50"` in Python. IronFlow refuses
that arithmetic rather than writing nonsense — but the fix is to cast.

### Quality gates

```yaml
validation:
  on_violation: quarantine        # keep bad rows, do not lose them
  max_error_rate: 0.05            # abort if more than 5% fail
  rules:
    - {type: not_null, field: order_id}
    - {type: unique,   field: order_id}
    - type: range
      field: net
      min: 0
      message: "net cannot be negative"

reject_destination:
  type: csv
  path: ./data/orders_rejected.csv
  mode: overwrite
```

Rejected rows land in the reject file with a `_ironflow_violations` column
explaining exactly which rules they broke.

Policies: `quarantine` (default), `fail` (abort, roll back), `drop` (discard),
`warn` (keep and count).

---

## 3. Validate, rehearse, run

```bash
ironflow pipeline validate orders
```

Catches cycles, unknown connectors, bad transformation options and invalid
rules — without credentials for any target system.

```bash
ironflow pipeline run orders --dry-run
```

Reads, transforms and validates everything; writes nothing. A real rehearsal,
not a syntax check.

```bash
ironflow pipeline run orders
```

```
┌──────────────── orders · exec_c09bb4aa059040ea ─────────────────┐
│ SUCCESS  10 read → 6 written  (2 rejected)  in 1.2s             │
│ ┌────────┬─────────┬─────────┬────┬─────┬──────────┐            │
│ │ Task   │ Status  │ Seconds │ In │ Out │ Rejected │            │
│ ├────────┼─────────┼─────────┼────┼─────┼──────────┤            │
│ │ load   │ success │    1.15 │  6 │   4 │        2 │            │
│ └────────┴─────────┴─────────┴────┴─────┴──────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 4. Multiple tasks

Tasks declare dependencies; independent tasks run in parallel automatically.

```yaml
tasks:
  - name: load_orders
    ...
  - name: load_customers
    ...                       # runs concurrently with load_orders
  - name: build_report
    depends_on: [load_orders, load_customers]
    condition: "state.load_orders.rows_out > 0"
    ...
```

```bash
ironflow pipeline show orders --mermaid
```

`condition` is a sandboxed expression with `params`, `state`, `pipeline`, `task`
and `dry_run` in scope. `state.<task>.rows_out` is how a task skips itself when
its input was empty.

---

## 5. Incremental loading

For a table too big to reload nightly:

```yaml
strategy: incremental
incremental:
  column: updated_at
  overlap: 30             # re-read 30s to catch late-committed rows
  key_columns: [order_id] # dedupe what the overlap re-delivers
```

The watermark advances **only after the destination commits**, so a failed load
never skips rows on the next run.

```bash
ironflow state watermarks orders
```

To force a full reload:

```bash
ironflow state clean --reset-watermarks orders --yes
```

---

## 6. Secrets

Never put a credential in a pipeline file.

```yaml
source:
  type: postgres
  dsn: env:CUSTOMERS_DSN        # from the environment
  # or: file:/run/secrets/dsn   # Docker/Kubernetes secret
  # or: enc:ironflow:v1:...     # encrypted with the platform key
```

```bash
ironflow secrets generate-key           # once, store in a secret manager
export IRONFLOW_ENCRYPTION_KEY=...
ironflow secrets encrypt                # prompts, so it misses shell history
```

Paste the resulting `ironflow:v1:...` envelope into the pipeline file.

---

## 7. Environments

One definition, per-environment overrides:

```yaml
defaults:
  batch_size: 1000

profiles:
  production:
    defaults:
      batch_size: 50000
```

```bash
ironflow --profile production pipeline run orders
```

Shared fragments go in an underscore-prefixed file (skipped by discovery):

```yaml
include: [_defaults.yaml]
```

---

## 8. Scheduling and notifications

```yaml
schedule:
  cron: "0 2 * * *"
  timezone: Europe/Amsterdam
  max_concurrent_runs: 1

notifications:
  - type: slack
    target: env:SLACK_WEBHOOK_URL
    on: [failed, partial]
```

```bash
ironflow schedule list
ironflow schedule start
```

Run exactly one scheduler instance. In Kubernetes, a `CronJob` per pipeline with
`concurrencyPolicy: Forbid` is usually the better answer — see
[deployment.md](deployment.md).

`validate` warns if you schedule a pipeline with no notifications: a 03:00
failure would otherwise go unnoticed until someone looked.

---

## 9. When something fails

```bash
ironflow pipeline history --status failed
ironflow pipeline logs <execution-id>          # which task, which error
ironflow pipeline resume orders <execution-id> # restart at the failure
```

Resume skips tasks that already succeeded. Because transactional destinations
rolled back, there is nothing to clean up first.

For a fresh attempt from the beginning:

```bash
ironflow pipeline retry orders
```

[troubleshooting.md](troubleshooting.md) covers the specific errors.

---

## 10. Monitoring

```bash
ironflow pipeline status orders     # last run + 30-day statistics
ironflow serve                      # dashboard, /metrics, REST API
```

```bash
ironflow pipeline run orders --report report.html
```

A self-contained HTML report you can attach to a ticket.

---

## Command reference

| Command | Does |
|---|---|
| `pipeline list` | discovered pipelines |
| `pipeline show NAME [--mermaid]` | structure and DAG |
| `pipeline validate NAME [--all]` | static checks, no credentials needed |
| `pipeline run NAME` | execute |
| `pipeline status NAME` | current state and statistics |
| `pipeline history [NAME]` | recent executions |
| `pipeline logs EXEC_ID` | per-task breakdown |
| `pipeline retry NAME` | re-run a failed execution |
| `pipeline resume NAME EXEC_ID` | continue from the failure |
| `schedule list` / `start` | scheduling |
| `state watermarks` / `clean` / `audit` | maintenance |
| `config show` / `check` / `schema` / `init` | configuration |
| `secrets generate-key` / `encrypt` / `decrypt` | secrets |
| `connectors list` | every registered component |
| `serve` | API and dashboard |

### Useful flags

| Flag | Effect |
|---|---|
| `--dry-run` | read and transform, write nothing |
| `--param k=v` | runtime parameter, JSON-typed |
| `--var k=v` | template variable |
| `--set a.b=v` | override a config key |
| `--only TASK` | run a subset (dependencies included) |
| `--profile NAME` | apply a profile overlay |
| `--json` | machine-readable output |
| `--log-level DEBUG` | full stack traces |
| `--report PATH` | write an HTML/JSON report |

### Exit codes

`0` success · `1` failure · `2` invalid configuration · `3` partial · `130` cancelled
