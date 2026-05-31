# Logging Facilities

Every harness built with this skill must implement the following logging
conventions. See `stages/runtime.py` docstring for the implementation.

## Dual-channel output (cardinal rule)

- **Stderr**: all status, progress, warnings, errors, and debug output.
- **Stdout**: ONLY structured JSON data (findings, report, PoC results).
  This lets users pipe findings directly:
  ```
  python3 run.py --mode full --repo ./target | tee findings.jsonl
  ```

## Conventions

| Aspect | Convention |
|---|---|
| Format | `HH:MM:SS [LEVEL] message` — no millis, no PID |
| Stage entry | `[stage N] StageName: description...` |
| Stage exit | `  -> N items after filtering` (leading spaces for visual indent) |
| Model call timing | `call_llm(domain) returned in 12.4s (cache: hit)` at debug level |
| Bad model tracking | `bad model provider:model: HTTP 429` at warning level |
| Parallel progress | `[pack] domain done` per pack completion |
| Summary | `[done] summary: {...}` as final log line |

## Log level conventions

| Level | When to use |
|---|---|
| `info()` | Stage entry/exit with counts, health results |
| `warning()` | Model failure (429/502/503), bad model detection, gapfill retry, truncated JSON |
| `error()` | Pack crash, stage failure, unrecoverable API error, schema validation failure |
| `debug()` | Per-API-call timing, cache hits/misses, per-finding details |

## Model health check logging

```
[health] probing models...
  -> 7/27 alive
  dead models (will try at runtime):
    openrouter:deepseek/deepseek-v3:free: HTTP 429
    groq:llama3-70b-8192: HTTP 403 (geo-blocked)
```
