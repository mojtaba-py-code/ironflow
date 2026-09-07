# Documentation

| Document | Read it when |
|---|---|
| [user-guide.md](user-guide.md) | You want to build and run a pipeline. Start here. |
| [configuration.md](configuration.md) | You need the full reference for a setting or a spec key. |
| [architecture.md](architecture.md) | You want to know how it works, or you're about to change it. |
| [security.md](security.md) | You're reviewing this for production, or auditing it. |
| [deployment.md](deployment.md) | You're putting it in Docker, Kubernetes or cron. |
| [developer-guide.md](developer-guide.md) | You're adding a connector, transformation or rule. |
| [troubleshooting.md](troubleshooting.md) | Something failed and you want the specific answer. |

## The five-minute version

```bash
git clone https://github.com/mojtaba-py-code/ironflow.git && cd ironflow
pip install -e ".[columnar]"
ironflow config init
ironflow pipeline validate example
ironflow pipeline run example --dry-run
ironflow pipeline run example
```

## The four guarantees

Everything in these documents follows from four properties the design is built
around:

1. **A failed run changes nothing.** The load engine owns the destination
   transaction; nothing commits until the whole stream is consumed cleanly.
2. **Memory is a function of `batch_size`, not dataset size.** Every stage is a
   generator; the operations that genuinely cannot stream say so and cap
   themselves.
3. **Bad data is quarantined, not lost.** Rejected rows are routed to a reject
   destination with the reason attached.
4. **Configuration is untrusted input.** Expressions run in an AST sandbox,
   paths are confined, SQL values are bound, outbound URLs pass an SSRF guard.

## Bundled examples

`pipelines/` contains three worked pipelines, each demonstrating a different
slice of the platform:

| File | Shows |
|---|---|
| `sales_daily.yaml` | the full-load shape: cast → derive → mask → validate → Parquet, plus a dependent aggregation |
| `customers_incremental.yaml` | watermarks, an overlap window, CDC deduplication, upsert loading, a post-load SQL task |
| `api_ingest.yaml` | OAuth2, cursor pagination, rate limiting, JSON flattening, a lookup join |

`sales_daily` runs against the committed fixtures in `data/sample/`. It
pseudonymises `customer_id` with a keyed HMAC, so unlike the scaffolded
`example` it needs one secret - and it fails loudly rather than falling back to
an unkeyed digest, which for a low-entropy value is reversible by enumeration:

```bash
export IRONFLOW_HASH_KEY="$(openssl rand -base64 32)"
ironflow pipeline run sales_daily
```

For the zero-setup path, use the scaffolded `example` above.
