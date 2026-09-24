# Configuration reference

Two kinds of configuration, kept separate on purpose:

- **Platform settings** — where state lives, how noisy the logs are, whether
  auth is on. Environment variables, `IRONFLOW_`-prefixed.
- **Pipeline definitions** — what data moves where. YAML or JSON files.

Conflating them is how a project ends up redeploying the service to change a
filter.

---

## Platform settings

Precedence, highest first: constructor argument → environment variable →
`.env` file → built-in default.

### Identity and paths

| Variable | Default | Notes |
|---|---|---|
| `IRONFLOW_ENVIRONMENT` | `local` | `local`, `development`, `staging`, `production` |
| `IRONFLOW_SERVICE_NAME` | `ironflow` | Appears in structured logs |
| `IRONFLOW_HOME` | `./.ironflow` | State, checkpoints, reports, audit |
| `IRONFLOW_PIPELINES_DIR` | `pipelines` | Where definitions are discovered |
| `IRONFLOW_DATA_ROOTS` | *(empty)* | Directories connectors may touch. Comma-separated or a JSON array. **Required in production.** |

### Logging

| Variable | Default | Notes |
|---|---|---|
| `IRONFLOW_LOG_LEVEL` | `INFO` | |
| `IRONFLOW_LOG_JSON` | `false` | Set true in production so the shipper can parse it |
| `IRONFLOW_LOG_FILE` | *(auto)* | File output is always JSON, regardless of the flag |
| `IRONFLOW_LOG_MAX_BYTES` | `52428800` | Rotation size |
| `IRONFLOW_LOG_BACKUP_COUNT` | `5` | Bounded, so a runaway job cannot fill the disk |

### State database

| Variable | Default | Notes |
|---|---|---|
| `IRONFLOW_STATE_DATABASE_URL` | SQLite under `HOME` | Production must use a server database |
| `IRONFLOW_STATE_POOL_SIZE` | `5` | |
| `IRONFLOW_STATE_MAX_OVERFLOW` | `10` | |
| `IRONFLOW_STATE_ECHO` | `false` | Logs every statement; debugging only |

SQLite gets `journal_mode=WAL` (so the dashboard can read while a pipeline
writes) and `foreign_keys=ON` (SQLite ignores them otherwise, silently skipping
the cascade on `task_runs`).

### Execution

| Variable | Default |
|---|---|
| `IRONFLOW_DEFAULT_BATCH_SIZE` | `10000` |
| `IRONFLOW_MAX_PARALLEL_TASKS` | `4` |
| `IRONFLOW_TASK_TIMEOUT` | `3600` |
| `IRONFLOW_CHECKPOINT_ENABLED` | `true` |

### Security

| Variable | Default | Notes |
|---|---|---|
| `IRONFLOW_AUTH_ENABLED` | `false` | **Required true in production** |
| `IRONFLOW_JWT_SECRET` | *(empty)* | ≥ 32 characters whenever auth is on, in **every** environment - start-up fails otherwise |
| `IRONFLOW_JWT_ISSUER` | `ironflow` | Enforced on every token |
| `IRONFLOW_JWT_AUDIENCE` | `ironflow-api` | Enforced on every token |
| `IRONFLOW_ENCRYPTION_KEY` | *(empty)* | `ironflow secrets generate-key`. Also keys the audit chain - see [rotating it](deployment.md#rotating-the-platform-key) before you change it |
| `IRONFLOW_ALLOW_LITERAL_SECRETS` | `true` | Set false in production |
| `IRONFLOW_AUDIT_ENABLED` | `true` | |
| `IRONFLOW_AUDIT_FILE` | `$IRONFLOW_HOME/audit/audit.jsonl` | The hash-chained trail, with its head anchor in `<file>.head` and a `<file>.lock` its writers take turns on. Put it on a local volume that survives the container, and back up the log and `.head` together |
| `IRONFLOW_MASK_PII_IN_REPORTS` | `true` | Masks detected PII in HTML/JSON run reports |

### What a pipeline file may reach

A pipeline file is untrusted input, so what it can read from the host and where
it can connect is the operator's decision, made here. A pipeline can narrow any
of these for itself; none of them can be widened from YAML.

| Variable | Default | Notes |
|---|---|---|
| `IRONFLOW_PIPELINE_ENV` | *(empty)* | Environment variables pipeline files may read through `${NAME}` and `env:NAME`, as glob patterns (`PG*,API_TOKEN`). Empty means any variable **except IronFlow's own settings**, which are never readable. **Required in production.** |
| `IRONFLOW_SECRET_FILE_ROOTS` | *(empty)* | Directories `file:` references may read from, e.g. `/run/secrets`. Empty disables `file:` |
| `IRONFLOW_ALLOW_PRIVATE_NETWORK` | `false` | Opens every private address to HTTP connectors - the SSRF guard off. Refused in production; a connector may switch it off for itself, never on |
| `IRONFLOW_HTTP_PRIVATE_HOSTS` | *(empty)* | Specific private destinations HTTP connectors may reach: host names (and their subdomains) or CIDR ranges. How an internal API is reached in production. Link-local addresses (cloud metadata) are never reachable |
| `IRONFLOW_HTTP_ALLOWED_HOSTS` | *(empty)* | If set, the **only** hosts (and subdomains) that HTTP connectors, OAuth2 token endpoints and webhook/Slack notifications may contact - the control that stops a pipeline from sending data somewhere nobody approved |

### HTTP

| Variable | Default | Notes |
|---|---|---|
| `IRONFLOW_HTTP_TIMEOUT` | `30` | Seconds, per connect/read |
| `IRONFLOW_HTTP_VERIFY_TLS` | `true` | Cannot be false in production |
| `IRONFLOW_HTTP_MAX_RETRIES` | `3` | Applies to 5xx/429 and transport errors only, never to a 4xx |
| `IRONFLOW_HTTP_MAX_RESPONSE_BYTES` | `268435456` | Cap on a *decoded* response body, enforced while it streams |

### API

| Variable | Default | Notes |
|---|---|---|
| `IRONFLOW_API_HOST` | `127.0.0.1` | `0.0.0.0` only behind a proxy, with auth on |
| `IRONFLOW_API_PORT` | `8080` | |
| `IRONFLOW_API_CORS_ORIGINS` | *(empty)* | Comma-separated or a JSON array. Never used in credentials mode |

Run `ironflow config check` to see what a given environment is missing.

---

## Pipeline definitions

### Top level

```yaml
name: sales_daily          # required; letters, digits, _ . -
version: "1"
description: ...
owner: data-engineering
enabled: true
tags: [sales, tier-1]

include: [_defaults.yaml]  # merged first; the including file wins

variables: {raw: ./data}   # referenced as ${var.raw}
parameters: {full_refresh: false}   # runtime, via --param
defaults: {batch_size: 10000, retry: {...}}   # pushed into tasks at load time

max_parallel_tasks: 4
tasks: [...]               # required, at least one
schedule: {...}
notifications: [...]
profiles: {production: {...}}
```

Unknown top-level keys are **rejected**. A silently ignored `retires: 3` is the
failure mode that produces the "but I configured retries!" incident.

### Variable interpolation

| Form | Resolves from |
|---|---|
| `${VAR}` | environment, within `IRONFLOW_PIPELINE_ENV` |
| `${var.name}` | the `variables:` block |
| `${VAR:-fallback}` | environment, with a default |

A whole-string reference preserves type (`batch_size: "${BATCH}"` yields an
int); an embedded one stringifies. An unresolved reference is an **error** with
its location — so a missing production variable fails at load, not by writing to
a path literally named `/data/${REGION}/out.csv`.

Environment references pass the same policy as `env:` secrets: IronFlow's own
settings (`IRONFLOW_JWT_SECRET`, `IRONFLOW_ENCRYPTION_KEY`, ...) are refused
even when unset, and with `IRONFLOW_PIPELINE_ENV` configured nothing outside it
resolves. An interpolated value lands in a plain field that the API, the
dashboard and the logs show, so it must never be a secret - use `env:` in a
secret-typed option instead.

A file larger than 1 MiB, or whose YAML aliases would expand past 100,000
nodes, is refused before it is built.

### Profiles

```yaml
defaults: {batch_size: 100}
profiles:
  production:
    defaults: {batch_size: 50000}
```

```bash
ironflow --profile production pipeline run sales_daily
```

Mappings merge key-wise; every other type, **including lists**, is replaced.
Replacing is deliberate: appending would make it impossible for a profile to
*remove* a task or a transformation.

### Tasks

```yaml
tasks:
  - name: load_orders          # required
    type: etl                  # etl | sql | noop
    description: ...
    enabled: true
    depends_on: [upstream]
    condition: "params.full_refresh"   # sandboxed boolean

    source: {type: csv, ...}
    destination: {type: parquet, ...}
    reject_destination: {type: csv, ...}

    transformations: [...]
    validation: {...}

    strategy: full             # full | incremental | cdc
    incremental: {column: updated_at, overlap: 30, key_columns: [id]}
    schema_evolution: {mode: additive}

    batch_size: 10000
    retry: {max_attempts: 3, initial_delay: 2}
    timeout: 3600
    on_failure: fail           # fail | continue
    checkpoint: true
```

`condition` is evaluated in the expression sandbox with `params`, `state`,
`pipeline`, `task` and `dry_run` in scope. `state.<task>.rows_out` lets a task
skip itself when its upstream produced nothing.

### Connectors

Every connector takes `type` plus connector-specific keys. `ironflow connectors
list` prints the live registry; each class docstring lists its options.

Common to all: `name`, `mode`, `batch_size`, `retry`.

`mode` is one of `append`, `overwrite`, `upsert`, `error_if_exists`, and each
destination accepts only the modes it can honour - anything else is refused
when the sink is built, so `pipeline validate` reports it:

| Destination | Modes | Default |
|---|---|---|
| CSV, JSON Lines | `append`, `overwrite`, `error_if_exists` | `append` |
| SQL (SQLite, PostgreSQL, MySQL) | all four | `append` |
| JSON array, XML, Excel, Parquet | `overwrite`, `error_if_exists` | `overwrite` |
| SFTP, FTP | `overwrite` | `overwrite` |
| memory | `append`, `overwrite` | `append` |

File sources bound what hostile input can cost: CSV refuses a header wider than
`max_columns` (default 4096); CSV and Excel end a batch early once it holds
`batch_size × 256` cells, so a very wide file yields more, smaller batches;
Excel ignores cells to the right of the header; `skip_rows` is capped at
1,000,000; XML and JSON honour `max_bytes`, and a whole JSON document (not JSON
Lines) defaults to 100 MiB because it is parsed at once.

### Validation

```yaml
validation:
  enabled: true
  stage: post_transform        # post_transform (default) | pre_transform
  on_violation: quarantine     # fail | quarantine | drop | warn
  max_error_rate: 0.05
  max_errors: 1000
  schema:                      # compact form, expands into rules
    order_id: {type: integer, nullable: false, unique: true}
    amount:   {type: float, min: 0}
    status:   {values: [pending, paid]}
  rules:
    - {type: not_null, field: order_id}
    - type: expression
      expression: "amount > 0 and quantity <= 10000"
      message: "implausible order"
      severity: error          # error (rejects) | warning | info (annotate)
```

`stage: post_transform` is the default because a `type: integer` rule must see
the value produced by the `cast` step, not the raw CSV string. Use
`pre_transform` when the contract being enforced is with the *upstream system*.

### Schema evolution

```yaml
schema_evolution:
  mode: additive               # strict | additive | permissive
  fail_on_removed_columns: true
  fail_on_type_change: true
```

`additive` accepts new columns and fails on removed ones — loading NULLs over an
existing column is worse than failing. After a *deliberate* change, re-baseline:

```bash
ironflow state clean --reset-schemas sales_daily --yes
```

### Schedule

```yaml
schedule:
  cron: "0 2 * * *"            # or interval_seconds, exactly one
  timezone: Europe/Amsterdam
  enabled: true
  catchup: false               # no back-fill storm after downtime
  max_concurrent_runs: 1       # two runs race on the watermark
```

Five-field cron with `*`, `N`, `N-M`, `*/S` and comma lists. `@reboot`, `L`,
`W` and `#` are deliberately unsupported: their semantics produce schedules
nobody can reason about at 3am.

### Notifications

```yaml
notifications:
  - type: slack                # console | webhook | slack | email
    target: env:SLACK_WEBHOOK_URL
    on: [failed, partial]      # started | success | failed | partial
```

> `on:` works because IronFlow's YAML loader disables YAML 1.1's
> `yes`/`no`/`on`/`off` boolean coercion. That same fix keeps the country code
> `NO` from becoming `False`.

---

## Editor support

```bash
ironflow config schema --output .ironflow-schema.json
```

Then in VS Code's `settings.json`:

```json
{ "yaml.schemas": { "./.ironflow-schema.json": "pipelines/*.yaml" } }
```

## Validate before you run

```bash
ironflow pipeline validate --all
```

Checks the graph for cycles, resolves every connector, compiles every
transformation and rule, and warns about quarantine without a
`reject_destination`, non-transactional destinations, and scheduled pipelines
with no notifications. It needs no credentials for the target systems.
