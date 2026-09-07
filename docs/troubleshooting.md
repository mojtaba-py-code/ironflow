# Troubleshooting

Start here:

```bash
ironflow pipeline history --status failed --limit 10
```

```bash
ironflow pipeline logs <execution-id>     # per-task breakdown with the error
```

```bash
ironflow config check                     # database + production hardening
```

Add `--log-level DEBUG` to any command for the full stack trace.

---

## Configuration

### `unresolved variable ${X}`

An interpolation reference resolves from neither `variables:` nor the
environment. The error names the location (`tasks.0.source.path`).

Deliberate? Give it a default: `${REGION:-eu-west-1}`.

### `pipeline definition failed validation`

The message lists the exact paths (`tasks.2.destination.mode`). Common causes:

- a typo in a top-level key — unknown keys are rejected, not ignored;
- `type: null` unquoted in YAML, which parses as `None`. Write `type: "null"`;
- `strategy: incremental` without an `incremental:` block.

### `no pipeline named 'X' was found`

`pipeline list` shows what was discovered. If yours is absent it failed to
parse — the loader logged the reason at ERROR. Files starting with `_` are
treated as shared fragments and skipped deliberately.

### A value became `True`/`False` unexpectedly

IronFlow's loader disables YAML 1.1 boolean coercion, so `on`, `off`, `yes`,
`no` stay strings. If you see this, something else in your toolchain is parsing
the file — check for a templating step ahead of IronFlow.

---

## Security errors

### `path escapes the configured data roots`

The resolved path — after collapsing `..` and following symlinks — is outside
`IRONFLOW_DATA_ROOTS`. Add the directory to the roots; do not remove the roots.

### `URL resolves to a non-public address (SSRF guard)`

The target resolves to a private, loopback or link-local address. For a genuinely
internal API, prefer an explicit per-connector allow-list over disabling the
guard globally:

```yaml
source:
  type: rest
  url: https://internal-api.corp.local/v1/orders
  allow_private_network: true
  allowed_hosts: [internal-api.corp.local]
```

`allow_private_network` cannot be enabled in a production environment.

### `invalid SQL identifier`

A table or column name contains something outside
`^[A-Za-z_][A-Za-z0-9_]{0,62}$`. Identifiers cannot be bound as parameters, so
they must be validated. Rename the column, or select it explicitly with an
alias in a custom `query:`.

### `encrypted secret found but no encryption key is configured`

Set `IRONFLOW_ENCRYPTION_KEY`. Generate one with `ironflow secrets generate-key`.

### `expression uses a forbidden construct`

The sandbox rejected the expression. Attribute access, lambdas, comprehensions
and imports are not available. Nested data is reached with subscripts
(`row["a"]["b"]`) or mapping-style dots (`params.force`).

---

## Data errors

### `arithmetic is not defined for text values; cast the column first`

The most common real bug this catches:

```yaml
- type: derive
  expression: "quantity * unit_price"     # both still strings from the CSV
```

Python would evaluate `"2" * 3` as `"222"` and put it in your warehouse. Cast
first:

```yaml
- type: cast
  columns: {quantity: integer, unit_price: float}
```

Every column an expression touches must be cast, including ones that only appear
inside a `coalesce`.

### Everything landed in the reject file

Check the reason column:

```bash
head -3 data/curated/orders_rejected.csv
```

Usually validation is running against uncast values. The default
`stage: post_transform` avoids this — if you set `pre_transform`, a
`type: integer` rule sees the raw CSV string and rejects every row.

### `reject rate exceeded max_error_rate`

The circuit breaker fired: too large a share of rows failed validation, which
usually means the source format changed rather than that the data is bad.
Inspect the reject file, then either fix the pipeline or raise the threshold
deliberately.

### `columns disappeared from the source`

Schema drift. The source no longer provides a column the previous run had, and
loading NULLs over existing data is worse than failing.

If the change is expected, re-baseline:

```bash
ironflow state clean --reset-schemas sales_daily --yes
```

### `column types changed in the source`

Same mechanism. Note that *editing your own transformations* changes the output
schema of a task, so this fires after a legitimate pipeline change — re-baseline
as above.

---

## Runtime and performance

### Out of memory

Peak RSS ≈ `batch_size × row size × pipeline depth`, plus the **entire dataset**
for any blocking transformation (`sort`, `aggregate`, `join`, `deduplicate`).
The engine logs which steps are blocking at task start.

In order of effectiveness:

1. Push the operation into the source query — `ORDER BY`/`GROUP BY` in SQL uses
   an index and spills to disk.
2. Filter earlier. Move `type: filter` to the front of the chain.
3. Lower `batch_size`.
4. Only then raise the transformation's `max_rows`.

The run history records peak RSS under `resources`; size container limits from a
real run.

### A run is slower than it was

```bash
ironflow pipeline logs <execution-id>
```

Per-step timings are recorded, so the step that went from 2 s to 40 s is
visible. Common causes: a blocking transformation that now exceeds memory and is
swapping; a `join` whose lookup grew; an API whose rate limit is throttling you
(look for `retry_attempts_total` climbing).

### The pipeline seems to hang

Most often a REST source paginating without an end condition. `max_pages` caps
it and logs a warning when the cap is hit — if you see that warning, the
pagination configuration is wrong, and the result set was silently truncated.

### `task exceeded its timeout`

The timeout is checked between batches, so an in-flight batch always finishes and
the rollback is clean. Raise `timeout`, or reduce the work.

---

## Connectors

### `unable to create the database engine … No module named 'psycopg'`

Install the driver extra: `pip install "ironflow[postgres]"` (or `[mysql]`).

### `this connector requires the 'columnar' extra`

`pip install "ironflow[columnar]"` for Parquet, `[excel]` for XLSX,
`[remote]` for SFTP.

### `SFTP authentication failed`

Check `user`/`password`/`private_key` resolve — `env:NAME` fails loudly if the
variable is unset. Note that agent forwarding and default key discovery are
**disabled** on purpose (implicit credentials make a connection
non-reproducible), so the key must be named explicitly.

### SFTP fails with a host-key error

The default is `RejectPolicy`. Add the host to a known-hosts file and point at
it with `known_hosts:`. `strict_host_key_checking: false` exists but is refused
in production — `AutoAddPolicy` accepts any key on first contact, which is not
authentication.

### `the API rate limit was exceeded`

Set `rate_limit` (requests/second) on the connector to stay inside the
provider's quota. IronFlow already honours `Retry-After`.

### The destination has partial data after a failure

Check whether the destination is transactional:

```bash
ironflow pipeline validate <name>
```

It warns for non-transactional destinations. The REST sink cannot un-send a
request; for exactly-once semantics, land to a transactional destination and
push from there.

---

## Operations

### Resume did nothing

Resume needs checkpoints from the original execution id:

```bash
ironflow pipeline history --limit 5      # find the execution id
ironflow pipeline resume <pipeline> <execution-id>
```

With no checkpoints it behaves as a full retry and logs a warning saying so.

### An incremental run re-read everything

Its watermark is missing:

```bash
ironflow state watermarks <pipeline>
```

Watermarks are cleared by `state clean --reset-watermarks`, and are never set by
a run that failed before its destination committed — which is the correct
behaviour, not a bug.

### An incremental run skipped rows

Almost always the commit-timestamp race: a row committed at 10:00:05 carrying
`updated_at = 10:00:00`, after the mark had already passed it. Add an overlap:

```yaml
incremental:
  column: updated_at
  overlap: 30
  key_columns: [id]     # dedupes what the overlap re-delivers
```

### The scheduler ran a job twice

More than one scheduler instance. It holds no distributed lock — run exactly one,
or use your orchestrator's scheduler with `concurrencyPolicy: Forbid`.

### `audit chain broken at entry N`

The audit file was edited or truncated. Entry N is the first that does not
verify. This is what the hash chain is for; investigate before dismissing it.

---

## Getting more detail

```bash
ironflow --log-level DEBUG pipeline run <name>
```

```bash
ironflow --json pipeline run <name> > result.json     # machine-readable
```

```bash
ironflow pipeline run <name> --report report.html     # shareable artefact
```

```bash
ironflow pipeline show <name> --mermaid               # the DAG
```

A dry run exercises read, transform and validate without writing anything:

```bash
ironflow pipeline run <name> --dry-run
```
