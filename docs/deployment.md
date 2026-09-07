# Deployment

## Install

```bash
pip install "ironflow[columnar,excel,api]"
```

Extras are opt-in so a slim image stays slim. `pyarrow` alone is ~90 MB.

| Extra | Adds |
|---|---|
| `columnar` | Parquet (`pyarrow`, `pandas`) |
| `excel` | XLSX (`openpyxl`) |
| `remote` | SFTP (`paramiko`) |
| `api` | REST API and dashboard (`fastapi`, `uvicorn`) |
| `postgres` / `mysql` | database drivers |
| `all` | everything |

A connector whose extra is missing fails with an actionable message
(`pip install 'ironflow[columnar]'`) rather than an ImportError at start-up.
CI has a job that proves the slim install still runs the CSV/SQL/REST paths.

---

## Container

```bash
docker build -f docker/Dockerfile -t ironflow:1.0.0 .
```

```bash
docker run --rm \
  -e IRONFLOW_ENVIRONMENT=production \
  -e IRONFLOW_STATE_DATABASE_URL="postgresql+psycopg://ironflow:***@db:5432/ironflow" \
  -e IRONFLOW_ENCRYPTION_KEY="$(cat /run/secrets/ironflow_key)" \
  -e IRONFLOW_DATA_ROOTS=/data \
  -v /srv/pipelines:/etc/ironflow/pipelines:ro \
  -v /srv/data:/data \
  ironflow:1.0.0 pipeline run sales_daily
```

The image is multi-stage: the builder has compilers, the runtime does not.
It runs as uid 1001 and writes only under `/var/lib/ironflow`.

### Local stack

```bash
docker compose -f docker/docker-compose.yml up --build
```

PostgreSQL, the API on `127.0.0.1:8080`, and a single scheduler replica.

---

## Production checklist

```bash
ironflow config check
```

Refuses to start unless every item below holds. All problems are reported at
once, not one per attempt.

- [ ] `IRONFLOW_ENVIRONMENT=production`
- [ ] `IRONFLOW_STATE_DATABASE_URL` points at PostgreSQL, not SQLite
- [ ] `IRONFLOW_ENCRYPTION_KEY` set from a secret manager
- [ ] `IRONFLOW_AUTH_ENABLED=true` with a ≥32-character `IRONFLOW_JWT_SECRET`
- [ ] `IRONFLOW_ALLOW_LITERAL_SECRETS=false`
- [ ] `IRONFLOW_ALLOW_PRIVATE_NETWORK=false`
- [ ] `IRONFLOW_DATA_ROOTS` confines connectors to explicit directories
- [ ] `IRONFLOW_LOG_JSON=true`
- [ ] Notifications configured on every scheduled pipeline

---

## Running the three ways

### Batch (cron, Airflow, Argo, Nomad)

```bash
ironflow pipeline run sales_daily --log-json
```

Exit codes are meaningful, so the orchestrator can branch:
`0` success · `1` failure · `2` invalid configuration · `3` partial · `130` cancelled.

`3` matters: a partial run produced output but something failed. Treating it as
success hides a real problem; treating it as failure triggers a pointless full
re-run.

### Scheduler

```bash
ironflow schedule start --poll 30
```

**Run exactly one instance.** The scheduler holds no distributed lock, so two
replicas double-trigger every job. In Kubernetes that means
`replicas: 1` with `strategy: Recreate`. If you need HA, run the batch form from
an orchestrator that already has leader election.

### Service

```bash
ironflow serve --host 0.0.0.0 --port 8080
```

Put a reverse proxy in front for TLS termination. `serve` refuses to start an
unauthenticated API in a production environment and warns when binding to all
interfaces without auth.

---

## Kubernetes

A `CronJob` per pipeline is usually better than the built-in scheduler:
Kubernetes already handles scheduling, retries, concurrency policy and history.

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: ironflow-sales-daily
spec:
  schedule: "0 2 * * *"
  concurrencyPolicy: Forbid      # two runs race on the watermark
  successfulJobsHistoryLimit: 3
  failedJobsHistoryLimit: 5
  jobTemplate:
    spec:
      backoffLimit: 0            # IronFlow does its own retries, with rollback
      template:
        spec:
          restartPolicy: Never
          securityContext:
            runAsNonRoot: true
            runAsUser: 1001
            fsGroup: 1001
          containers:
            - name: ironflow
              image: ironflow:1.0.0
              args: ["pipeline", "run", "sales_daily", "--log-json"]
              envFrom:
                - configMapRef: {name: ironflow-config}
                - secretRef:    {name: ironflow-secrets}
              resources:
                requests: {memory: 512Mi, cpu: 250m}
                limits:   {memory: 2Gi,   cpu: "2"}
              securityContext:
                allowPrivilegeEscalation: false
                readOnlyRootFilesystem: true
                capabilities: {drop: [ALL]}
              volumeMounts:
                - {name: pipelines, mountPath: /etc/ironflow/pipelines, readOnly: true}
                - {name: state,     mountPath: /var/lib/ironflow}
                - {name: tmp,       mountPath: /tmp}
          volumes:
            - {name: pipelines, configMap: {name: ironflow-pipelines}}
            - {name: state, persistentVolumeClaim: {claimName: ironflow-state}}
            - {name: tmp, emptyDir: {}}
```

`backoffLimit: 0` is deliberate: IronFlow retries internally *after rolling
back*, so a Kubernetes-level restart would duplicate that work with a less
careful failure model.

Sizing memory: peak RSS ≈ `batch_size × row size × pipeline depth`, plus the
full dataset for any blocking transformation. The run history records peak RSS
under `resources`, so size the limit from a real run rather than a guess.

---

## Database

```sql
CREATE DATABASE ironflow;
CREATE USER ironflow WITH PASSWORD '...';
GRANT ALL PRIVILEGES ON DATABASE ironflow TO ironflow;
```

Tables are created on first connection. The control-plane schema is small
(six tables); the data itself never passes through it.

### Retention

Run history and checkpoints grow without bound. Schedule a weekly clean:

```bash
ironflow state clean --history-days 90 --checkpoint-days 30
```

---

## Observability

### Metrics

`/metrics` serves Prometheus text exposition.

```yaml
- job_name: ironflow
  static_configs: [{targets: ["ironflow:8080"]}]
```

| Metric | Type | Alert on |
|---|---|---|
| `ironflow_pipeline_runs_total{status}` | counter | rising `failed` rate |
| `ironflow_pipeline_duration_seconds` | histogram | p95 regression |
| `ironflow_rows_loaded_total` | counter | a sudden drop to zero |
| `ironflow_rows_quarantined_total` | counter | a spike |
| `ironflow_validation_violations_total` | counter | a spike |
| `ironflow_retry_attempts_total` | counter | sustained non-zero |

A useful starting alert — a daily pipeline that produced nothing:

```yaml
- alert: IronFlowPipelineProducedNoRows
  expr: increase(ironflow_rows_loaded_total{pipeline="sales_daily"}[26h]) == 0
  for: 1h
```

### Logs

With `IRONFLOW_LOG_JSON=true` every line is one JSON object carrying
`correlation_id`, `execution_id`, `pipeline_id` and `task_id`, so a single run
is greppable end to end. Secrets are scrubbed by a filter on every handler.

### Health

`/health` returns `degraded` when the state database is unreachable or
production hardening is violated. The container `HEALTHCHECK` uses it, so an
orchestrator restarts rather than silently serving a broken instance.

---

## Backup and recovery

Back up the **state database**. It holds run history, watermarks, checkpoints
and schema snapshots — losing the watermarks means the next incremental run
re-reads everything from the beginning.

The audit log (`$IRONFLOW_HOME/audit/audit.jsonl`) is append-only and
hash-chained; back it up separately and verify after restore:

```bash
ironflow state audit --verify
```

### Recovering a failed run

```bash
ironflow pipeline history --status failed
```

```bash
ironflow pipeline logs <execution-id>        # which task, which error
```

```bash
ironflow pipeline resume sales_daily <execution-id>
```

Resume skips tasks that already checkpointed successfully. Because transactional
destinations rolled back, there is nothing to clean up first.

---

## Upgrading

1. Read `CHANGELOG.md`.
2. `ironflow pipeline validate --all` against the new version — schema and
   option changes surface here.
3. Deploy to staging; run one pipeline with `--dry-run`.
4. Deploy. Tables are created additively; no migration step for 1.x.
