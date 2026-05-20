# Logging Facilities

Every harness built with this skill must implement the following logging
conventions. They are required for debugging, audit trails, and pipeline
observability.

## Dual-channel output (cardinal rule)

- **Stderr**: all status, progress, warnings, errors, and debug output.
- **Stdout**: ONLY structured JSON data (findings, report, PoC results).
  Nothing else. This lets users pipe stdout into files/analyzers without
  parsing log noise:
  ```shell
  python3 run.py --mode full --repo ./target | tee findings.jsonl
  # stderr shows progress; stdout is a valid JSONL stream
  ```

## Logger setup

Use Python's `logging` module with dual handlers — file + stderr:

```python
import logging

_LOG_FILE = '/tmp/ai-vuln-harness.log'
_log = logging.getLogger('ai-vuln-harness')
_log.setLevel(logging.DEBUG)

# File handler (persistent, full detail)
_fh = logging.FileHandler(_LOG_FILE)
_fh.setFormatter(logging.Formatter(
    '%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'))
_log.addHandler(_fh)

# Stderr handler (live progress)
_sh = logging.StreamHandler()
_sh.setFormatter(logging.Formatter(
    '%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S'))
_log.addHandler(_sh)
```

## Log level conventions

| Level | When to use | Example |
|---|---|---|
| `_log.info()` | Stage entry, stage exit with counts, health results, model chain composition | `[stage 4] Hunter cluster: running parallel hunters...` → `-> 12 raw findings, 4 gaps` |
| `_log.warning()` | Model failure (429/502/503), bad model detection, gapfill retry, truncated JSON | `bad model openrouter:...: 429 Too Many Requests` |
| `_log.error()` | Pack crash, stage failure, unrecoverable API error, schema validation failure | `pack mem-safety crashed: ConnectionError` |
| `_log.debug()` | Per-API-call timing, cache hits/misses, per-finding details (not emitted in production) | `call_llm(mem-safety) returned in 12.4s (cache: hit)` |

## Log format

`HH:MM:SS [LEVEL] message` — compact, human-readable. No millis, no PID.
The timestamp precision is seconds because stages run for minutes, not ms.
Persistent file uses the same format for grep compatibility.

## Stage entry/exit pattern

Every stage logs entry with `[stage N]` prefix and exit with `->` indented
on a new line. This makes stage boundaries visually distinct:

```
12:00:00 [INFO] [stage 1] Ingestor: loading repo files...
12:00:05 [INFO]   -> 181 snippets after filtering
12:00:05 [INFO] [stage 2] Recon: building hunt tasks...
12:00:40 [INFO]   -> 6 tasks across domains
```

The leading spaces on `->` lines visually indent results under the stage name.

## Model health check logging

Health check output must distinguish alive vs dead models with the error
reason for each dead model:

```
12:00:00 [INFO] [health] probing models...
12:00:20 [INFO]   -> 7/27 alive
12:00:20 [INFO]   dead models (will try at runtime):
                  openrouter:deepseek/deepseek-v3:free: HTTP 429
                  groq:llama3-70b-8192: HTTP 403 (geo-blocked)
                  cerebras:llama3.1-8b: connection timeout
```

## Model call timing

Every LLM call should log duration at debug level. This surfaces slow
models and rate-limiting patterns:

```python
_start = time.time()
result = call_llm(model, prompt)
_log.debug('call_llm(%s) returned in %.1fs (cache: %s)',
            domain, time.time() - _start, 'hit' if cached else 'miss')
```

## Bad model tracking

When a model produces an error, log it with `_log.warning()` and add it
to the bad-models set so the pipeline skips it for subsequent packs:

```python
_log.warning('bad model %s%s', model_id, f': {reason[:80]}' if reason else '')
_bad_models.add(model_id)
```

This prevents spending time on the same broken model across multiple
packs in a single run.

## Progress indicator for parallel workers

When running N packs in parallel via `ThreadPoolExecutor`, log per-pack
completion so the operator can monitor progress even when individual
packs take 5-15 minutes:

```python
with ThreadPoolExecutor(max_workers=parallel) as pool:
    futures = {pool.submit(run_pack, p): p['agent'] for p in packs}
    for f in as_completed(futures):
        _log.info('  [pack] %s done', futures[f])
```

## Summary line

The final log line before exit summarizes the entire run in one line:

```python
_log.info('[done] summary: %s', json.dumps(report['summary']))
```

This lets the operator grep the last log line for a quick status check
without parsing the full report.
