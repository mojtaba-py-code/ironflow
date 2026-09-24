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

The target resolves to a private or loopback address. Reaching one is the
operator's decision, not the pipeline's: list the host (or its address range)
in the platform settings rather than disabling the guard.

```bash
IRONFLOW_HTTP_PRIVATE_HOSTS=internal-api.corp.local,10.20.0.0/16
```

The check runs on the address the connection actually uses, so a name that
resolves differently at connect time than it did a moment earlier is refused
too. "that no setting opens" in the message means a link-local address - where
cloud metadata services answer - which nothing makes reachable.

### `a pipeline cannot switch off the SSRF guard`

A connector set `allow_private_network: true` while the platform does not allow
private addresses. That option can only switch the guard *on* for a connector;
use `IRONFLOW_HTTP_PRIVATE_HOSTS` as above.

### `host is not in the IRONFLOW_HTTP_ALLOWED_HOSTS allow-list`

The operator has bounded where pipelines may send data, and this host is not on
the list. Ask for it to be added; a connector's own `allowed_hosts` can only
narrow the operator's list.

### `environment variable is not in IRONFLOW_PIPELINE_ENV` / `pipeline files cannot read IronFlow's own configuration`

A `${NAME}` or `env:NAME` names a variable outside the operator's allow-list,
or one of IronFlow's own settings (`IRONFLOW_JWT_SECRET` and the rest), which
no pipeline may read. Add the variable to `IRONFLOW_PIPELINE_ENV` if a pipeline
genuinely needs it.

### `file: secret references are disabled`

`file:` needs `IRONFLOW_SECRET_FILE_ROOTS` - the directories secrets may be read
from, such as `/run/secrets`. A path outside them is refused as a security
error.

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

Install the driver: `pip install 'psycopg[binary]>=3.1'` (the `postgres` extra),
or `pip install 'PyMySQL>=1.1'` for MySQL.

### `this connector requires the 'columnar' extra`

The message names the packages to install: `pyarrow` and `pandas` for Parquet
(the `columnar` extra), `openpyxl` for XLSX (`excel`), `paramiko` for SFTP
(`remote`). Or reinstall IronFlow with the extra, from where you installed it -
never by the bare name `ironflow`, which on PyPI is another project.

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

### `audit chain broken ...`

`ironflow state audit --verify` names the first problem it finds, and - when it
is in one entry - that entry's position, counting from 0. `--json` adds a stable
`problem` code for scripts. This is what the chain is for: treat each of these
as possible tampering until you have ruled it out.

| `problem` | The message says | Usually means |
|---|---|---|
| `key_required` | `... no audit key is configured` | The log is keyed. Verify with `IRONFLOW_ENCRYPTION_KEY` set to the platform's key |
| `entry_modified` | `it does not match its hash - it was edited, or written under a different IRONFLOW_ENCRYPTION_KEY` | An edited entry - or the key was changed; see [rotating the platform key](deployment.md#rotating-the-platform-key) |
| `chain_broken` | `it does not link to the entry before it` | An entry was inserted, removed or reordered |
| `downgraded` | `it is unkeyed although earlier entries are keyed` | The tail was rewritten by someone without the key |
| `entry_unreadable` | `it is not a well-formed audit entry` | A damaged line: an edit, or a disk that filled mid-write |
| `truncated` | `the log ends after N of the M entries its head anchor records` | The last entries were deleted |
| `log_missing` | `the log is missing but its head anchor records N entries` (or `empty`) | The log was deleted or emptied |
| `anchor_missing` | `the log has N entries but no head anchor` | The `.head` file was deleted - or the log was written by a version before 1.1.0, in which case the next audited action creates it |
| `anchor_unreadable`, `anchor_forged` | `the head anchor ...` | The `.head` file was edited, or written under a different key |
| `anchor_unkeyed` | `the head anchor is not keyed although an audit key is configured` | The key was set only just now (the next audited action re-anchors), or the log was rewritten without it |
| `anchor_mismatch` | `it is not the head the anchor records` | The log was rewritten |
| `unanchored_entries` | `the anchor covers only the first N of M` | An append whose anchor update failed - the next append heals it - or entries added by hand |
| `expected_head_missing` | `the expected head is not in the log` | The head you recorded with `--expect-head` is gone: entries up to it were deleted or rewritten |

The writer never "repairs" a log that contradicts its anchor - that would erase
the evidence. Once you have investigated, move the log **and** its `.head` file
aside together and keep them; the next audited action starts a new chain.

Several IronFlow processes - the API, the scheduler, your CLI runs - may share
one audit file: they take turns on `<audit file>.lock`. That lock needs a local
file system; on network storage without working locks, give each host its own
`IRONFLOW_AUDIT_FILE`. If the log shows `audit log lock unavailable`, the
entries are still written, but two processes appending at the same moment could
break the chain.

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
