# Operations Guide (v1)

## Run modes

- `full` — run complete pipeline from ingest through report
- `max-run` — run a limited subset of packs for fast debugging
- `validate-only` — skip Hunt and re-run Validate/Dedupe/Report from cached findings
- `resume` — continue from state DB, skipping completed tasks

## Troubleshooting quick paths

- **429 storms**: lower concurrency (free tier default: 3), keep model fallback chain enabled
- **Empty responses**: ensure system message is present; skip model and continue chain
- **Schema repair loops**: cap repair attempts at 2 then fail stage with explicit error
- **Auth key nesting**: support nested provider key objects in auth file parsing

## Recommended defaults

### Free tier
- Sync request path
- Max workers: 3
- Strict model fallback enabled

### Paid tier
- Async optional
- Max workers: 20+
- Keep disjoint Hunt/Validate model pools
