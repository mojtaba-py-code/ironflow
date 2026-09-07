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
| `IRONFLOW_JWT_ISSUER` / `_AUDIENCE` | `ironflow` / `ironflow-api` | Both enforced |
| `IRONFLOW_ENCRYPTION_KEY` | *(empty)* | `ironflow secrets generate-key` |
| `IRONFLOW_ALLOW_LITERAL_SECRETS` | `true` | Set false in production |
| `IRONFLOW_ALLOW_PRIVATE_NETWORK` | `false` | This is the SSRF guard |
| `IRONFLOW_AUDIT_ENABLED` | `true` | |
| `IRONFLOW_HTTP_VERIFY_TLS` | `true` | Cannot be false in production |

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
| `${VAR}` | environment |
| `${var.name}` | the `variables:` block |
| `${VAR:-fallback}` | environment, with a default |

A whole-string reference preserves type (`batch_size: "${BATCH}"` yields an
int); an embedded one stringifies. An unresolved reference is an **error** with
its location — so a missing production variable fails at load, not by writing to
a path literally named `/data/${REGION}/out.csv`.

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

Common to all: `name`, `mode` (`append` | `overwrite` | `upsert` |
`error_if_exists`), `batch_size`, `retry`.

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
