# Failure Mode Analysis: ai-vuln-harness

**Date:** 2026-06-09
**Artifact:** Multi-agent vulnerability research pipeline (17 stages)
**Methodology:** Structured failure mode enumeration (Likelihood × Impact × Detectability)

## Summary

Multi-agent vulnerability research pipeline with 17 stages, LLM-driven code analysis, distributed async API calls, and multiple caching layers. Primary risk surface: **silent correctness failures in LLM output parsing**, **data corruption under concurrency**, **resource exhaustion**, and **latent race conditions in shared state**.

---

## High Priority Failures (score ≥ 8)

### 1. `JsonCache.put()` race corrupts cache file under concurrent threads

| Axis | Score |
|---|---|
| **Likelihood** | 3-High |
| **Impact** | 3-High |
| **Detectability** | 3-Silent |
| **Priority** | **9** |

`JsonCache.put()` at `runtime.py:293-295` reads the entire file, updates the dict in memory, then writes it back — all without a lock. `call_llm()` is called from `ThreadPoolExecutor` (hunt_workers up to 10). Two threads caching results simultaneously: T1 reads A, T2 reads A, T1 writes A+B, T2 writes A+C → T1's B is silently lost. No error, no warning.

**Mitigation:** Add `threading.Lock()` to `JsonCache.put()`, or switch to append-only log + periodic compaction, or use SQLite with WAL.

---

### 2. LLM output parsed as valid finding without cross-field validation

| Axis | Score |
|---|---|
| **Likelihood** | 3-High |
| **Impact** | 3-High |
| **Detectability** | 2-Hard |
| **Priority** | **8** |

`parse_findings()` accepts any JSON the LLM produces. There is zero validation that `snippet_id` actually exists in the snippet DB, that `class` is a valid attack class, that `file`/`lines` exist, or that the LLM didn't hallucinate an entire function name. False positives flow downstream through VALIDATE → VOTING → REPORT as if they were real.

**Mitigation:** Validate `snippet_id` against the existing snippet DB immediately after parsing. Reject or flag findings referencing non-existent snippets. Validate `class` against a known enum.

---

### 3. Thread-safety violation in `StateDB` (SQLite without `check_same_thread=False`)

| Axis | Score |
|---|---|
| **Likelihood** | 2-Medium |
| **Impact** | 4-Critical |
| **Detectability** | 2-Hard |
| **Priority** | **8** |

`StateDB` at `runtime.py:310` creates SQLite connection with default `check_same_thread=True`. `_enforce_cost_limit()` is called from `run()` which also spawns threads. If cost enforcement runs during threaded pack processing, SQLite raises `ProgrammingError` and the pipeline crashes mid-run. Timing-dependent — may only manifest under specific concurrency patterns.

**Mitigation:** Add `check_same_thread=False` to `sqlite3.connect()` call, or ensure all DB writes happen from the main thread only.

---

### 4. No client-side rate limiting — burst of N requests to shared API provider

| Axis | Score |
|---|---|
| **Likelihood** | 3-High |
| **Impact** | 2-Medium |
| **Detectability** | 1-Easy |
| **Priority** | **8** |

With `hunt_workers=10`, the system launches 10 concurrent `urlopen()` calls to the same provider. Free-tier APIs (opencode.ai, OpenRouter) have aggressive rate limits. The retry logic handles individual 429s but the burst pattern can trigger IP-level throttling that affects all concurrent requests simultaneously, cascading into 3× retry delays for every pack.

**Mitigation:** Add a `threading.Semaphore` or token-bucket rate limiter per provider. Gate calls to `urlopen()` through it. Configure per-provider RPM limits.

---

### 5. JsonCache grows unbounded — O(n) serialization, no eviction

| Axis | Score |
|---|---|
| **Likelihood** | 2-Medium |
| **Impact** | 3-High |
| **Detectability** | 1-Easy |
| **Priority** | **8** |

Every `put()` serializes the entire dict to pickle. With 10,000+ cached LLM responses, the cache file grows to tens of MB and each write becomes increasingly slow. The pipeline writes to cache on every successful LLM call — this creates a compounding slowdown over long runs. No TTL or LRU eviction.

**Mitigation:** Implement LRU eviction with `max_entries`. Switch to SQLite-backed cache. Or at minimum, bound the file size and log a warning when approaching the limit.

---

## Medium Priority Failures (score 5–7)

### 6. Gapfill findings bypass VALIDATE entirely

| Axis | Score |
|---|---|
| **Likelihood** | 2-Medium |
| **Impact** | 3-High |
| **Detectability** | 2-Hard |
| **Priority** | **7** |

`_gapfill_rerun()` re-hunts gap domains and injects results directly into the validated findings list. These results never go through the adversarial VALIDATE stage. If the model hallucinates during gapfill (prompted to "try harder"), those hallucinations become validated findings without review.

**Mitigation:** Route gapfill findings through VALIDATE before promotion. Or tag them as `gapfill=True` so downstream stages can treat them with lower confidence.

---

### 7. Pickle deserialization across all persistence layers

| Axis | Score |
|---|---|
| **Likelihood** | 2-Medium |
| **Impact** | 4-Critical |
| **Detectability** | 3-Silent |
| **Priority** | **7** |

`snippet_db.pkl`, `context_packs.pkl`, `cache.pkl`, `recon_tasks.pkl` all use `pickle.loads()`. In a CI/CD or shared environment, a malicious pickle file achieves arbitrary code execution. Even in a single-user setup, a corrupted pickle file silently returns wrong data.

**Mitigation:** Use JSON or msgpack for persistence. Or use `pickle.loads()` with a custom `Unpickler` that restricts allowed classes.

---

### 8. Diff filter silently returns empty snippet set on git error

| Axis | Score |
|---|---|
| **Likelihood** | 2-Medium |
| **Impact** | 2-Medium |
| **Detectability** | 3-Silent |
| **Priority** | **7** |

`get_changed_line_ranges()` at `diff.py:36` runs `git diff --unified=0`. If git fails (not a repo, commit doesn't exist, detached HEAD), `subprocess.check_output()` raises `CalledProcessError` which propagates up and crashes the pipeline. But `filter_snippets_by_diff()` itself returns an empty list — the pipeline continues with zero snippets, builds zero packs, produces zero findings, and reports "clean" with no error.

**Mitigation:** Catch git errors explicitly, log the failure, and decide: abort or fall through with a warning. Never silently return empty.

---

### 9. `budget_tokens` computed from the weakest model — underutilizes capable models

| Axis | Score |
|---|---|
| **Likelihood** | 3-High |
| **Impact** | 2-Medium |
| **Detectability** | 1-Easy |
| **Priority** | **6** |

`budget_tokens = min(model_limits.values()) * budget_ratio` at `run.py:1937`. If one model has 8K context and another has 128K, all packs are sized for 8K. The capable model runs many small packs instead of fewer large ones, wasting throughput and fragmenting cross-file analysis.

**Mitigation:** Compute per-model budget. When using a large-context model, merge adjacent packs for that model.

---

### 10. No input sanitization on `--scope-notes` file content

| Axis | Score |
|---|---|
| **Likelihood** | 1-Low |
| **Impact** | 3-High |
| **Detectability** | 3-Silent |
| **Priority** | **7** |

`scope_notes` reads an arbitrary file and passes it verbatim into every hunt pack's prompt. A malicious notes file can inject prompt overrides, alter the model's behavior, or leak other prompt content. No size limit either.

**Mitigation:** Validate input length (reject > 4096 chars). Strip or escape control characters. Treat as untrusted.

---

### 11. `_rephrase_gap_prompt()` appends hint — doesn't change the fundamental difficulty

| Axis | Score |
|---|---|
| **Likelihood** | 2-Medium |
| **Impact** | 2-Medium |
| **Detectability** | 1-Easy |
| **Priority** | **5** |

The gap prompt simply appends "The previous model produced no findings, double-check carefully". If the original prompt was too large for the model's context window, or the model couldn't reason about the code, this hint doesn't help. Appending text makes the context even larger.

**Mitigation:** Restructure the prompt more aggressively — reduce snippet count, increase signal, add explicit reasoning steps.

---

### 12. `--repo-head 0` with empty diff yields zero snippets, no warning

| Axis | Score |
|---|---|
| **Likelihood** | 2-Medium |
| **Impact** | 2-Medium |
| **Detectability** | 2-Hard |
| **Priority** | **6** |

`--repo-head 0` sets `base_commit=HEAD~1`. If the HEAD commit only touches non-supported file extensions (`.proto`, `.md`, `.json`), `get_changed_snippets()` returns an empty list. Pipeline continues with `snippets=[]`, builds `packs=[]`, prints "pack total=0", and exits with "no findings" — looking like a clean security audit.

**Mitigation:** After diff filtering, if `len(snippets) == 0`, log a WARNING listing which files were in the diff but excluded.

---

### 13. CVE severity parsing fragile — many CVEs produce "UNKNOWN"

| Axis | Score |
|---|---|
| **Likelihood** | 3-High |
| **Impact** | 1-Low |
| **Detectability** | 1-Easy |
| **Priority** | **5** |

`_cvss_severity()` parses CVSS vector strings with `str.split("/")`. Non-standard vectors, missing version prefixes, or empty strings silently return "UNKNOWN". Severity information is silently dropped for many CVEs.

**Mitigation:** Use a CVSS parsing library. Fall back gracefully with a warning on first parse failure.

---

### 14. Model health cache never expires in-process

| Axis | Score |
|---|---|
| **Likelihood** | 1-Low |
| **Impact** | 2-Medium |
| **Detectability** | 3-Silent |
| **Priority** | **6** |

`model_health_timestamp` is stored in cache but never checked for staleness. Once cached, a dead model is never re-probed. With `--skip-health`, all models are assumed alive even if they're dead.

**Mitigation:** Add TTL to health status (e.g., 30 minutes). Re-probe on cache expiry.

---

### 15. `--target` mode skips CVE injection — no known-entries dedup in dir mode

| Axis | Score |
|---|---|
| **Likelihood** | 3-High |
| **Impact** | 1-Low |
| **Detectability** | 1-Easy |
| **Priority** | **5** |

When running with `--target`, `no_fetch_cves` and `no_scan_git_cves` are forced to `True`. This means `known_entries` is always empty in dir mode. The LLM may rediscover known vulnerabilities.

**Mitigation:** Allow `--no-fetch-cves` to be explicitly unset in target mode. Log that known-CVE dedup is disabled.

---

## Low Priority Failures (score ≤ 4)

- **`_load_prompt()` crashes on missing file** — `read_text()` raises `FileNotFoundError` with no graceful fallback.
- **`max_tokens` hardcoded to 8192** in `call_llm()` — reasoning models may need more output budget.
- **Retry backoff fixed at 5×N seconds** — no jitter, could cause synchronized retry storms across concurrent workers.
- **No logging of which snippets were sent in each pack** — debugging false positives requires reconstruction from the cache key hash.
- **`--load-packs-cache` silently uses stale packs** — if the target repo changed, old packs produce stale findings with no warning.
- **No persistent daemon / API mode** — single-shot CLI only.
- **Auth key precedence not documented** — env var overrides file, but file priority between `auth.json` and `~/.local/share/opencode/auth.json` is order-dependent.

---

## Key Mitigations

1. **Add `threading.Lock()` to `JsonCache.put()`** — trivial change, prevents silent data loss.
2. **Validate `snippet_id` against snippet DB** after `parse_findings()` — cuts false positive rate significantly.
3. **Add per-provider rate limiter** (`threading.Semaphore` with configurable RPM) before `urlopen()`.
4. **Add `check_same_thread=False` to `StateDB`** — prevents rare but catastrophic mid-run crash.
5. **Route gapfill findings through VALIDATE** before promotion to confirmed.
6. **Replace pickle with JSON** for all persisted artifacts in shared/CI environments.

---

## Assumptions Made

- **Threat model:** Opportunistic external attacker + accidental misuse by authorized users. No nation-state adversary.
- **Operational context:** Single-user workstation, trusted filesystem, no concurrent pipeline instances on the same cache file.
- **Scope boundary:** Not analyzing the correctness of the LLM models themselves (prompt injection, jailbreak, poisoning are model-level risks). Also not analyzing third-party provider API availability.
- **What was NOT analyzed:** The Validate, Shield, Exploit-Synthesis, and POC stages' internal failure modes (scope constrained to pipeline architecture, data flow, and stage orchestration).
