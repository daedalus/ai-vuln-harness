# Operations Reference

Practical notes and gotchas from implementing and running the pipeline.
Load this when debugging pipeline behavior, handling model quirks, or
optimizing for cost/reliability.

---

## Findings Density Expectation

Not every domain produces findings. Findings counts vary significantly
by model quality and target codebase.

Some domains may produce zero findings for a given target — this is
honest coverage output, not a pipeline failure. The gapfill stage
should re-queue these with narrowed scope.

### Concrete numbers from the zlib run

zlib: 608 functions from 49 files, C library, ~1.1M snippet DB.

| Domain | Snippets | Findings | Validate result |
|---|---|---|---|
| mem-safety | 198 | 0 | N/A (0 findings to validate) |
| auth | 198 | 0 (gaps: "no auth in compression lib") | N/A |
| crypto | 173 | 0 (gaps: "no crypto primitives") | N/A |
| ipc | 198 | 0 | N/A |
| data-flow | 198 | 0 | N/A |
| format-str | 150 | 3 (format-string in gzprintf) | 2 rejected, 1 backlog |

Total: 3 raw findings → 1 backlog, 2 false_positive, 0 fix_now.

This is the correct profile for a heavily-audited 30-year-old C library.
A greenfield JavaScript app would produce very different numbers.

### Tag inflation warning

- **`external-input` keyword-match** on `buf`, `arg`, `len`, `src` in a C
  library matches 607/608 functions (99.9%). This makes `auth`, `ipc`, and
  `data-flow` packs identical to `mem-safety` — same snippets, same size,
  wasted API calls. Fix: strip `external-input` from all domain filters
  EXCEPT `data-flow` when targeting compiled libraries. For `data-flow`,
  use a smarter heuristic (detect `read()`, `recv()`, `fgets()` calls).
- **`integer-arith` keyword-match** on `len`, `size`, `count` matches
  every buffer-processing function — essentially every function in a C
  library. Narrow to operations on untrusted lengths only.

- **data-flow findings in a library** are mostly "attacker data enters library"
  — these are reachability questions, not library bugs. They become useful in
  the Trace stage when mapped to consumer repos.
- **auth/crypto/ipc packs** in a narrow-scope library will inflate on the
  `external-input` tag overlap. Consider removing `external-input` from these
  domains' tag filters when targeting a library with a tight functional scope.

## Model Behavior Observations

- **Free-tier model quality varies wildly.** Some responses are excellent
  (correctly identifying UAF patterns); some hallucinate code that doesn't exist.
- **Reasoning models** (nemotron, deepseek) produce longer, more thorough
  analyses but take 30-60s per response on free tier.
- **Standard models** (gemma, z-ai, baidu) respond in 5-15s but miss subtle
  patterns.
- **Paid models would reduce variance** significantly. Free tier is viable
  for prototyping but not production auditing.

## Pipeline Robustness Patterns

- **Print all status to stderr, findings JSONL to stdout.** This is the most
  important pattern — it lets users pipe findings directly and keeps logs
  separate from data.
- **`--reingest` flag** prevents accidental re-runs of expensive extraction.
- **Output checking** before each stage: if output exists and `--reingest`
  not set, skip the stage. This enables restartable pipelines.
- **Each stage is a standalone script** that reads JSON(L) files and writes
  JSON(L) files. This lets you rerun individual stages without the full pipeline.
- **`--max-run N` flag** is essential for debugging — running all 6 packs
  costs ~60 API calls on a target.
- **3 concurrent workers** is the sweet spot for free-tier OpenRouter.
  Higher concurrency triggers HTTP 429 rate limits.

### Timing expectations (free tier, zlib, 6 packs)

| Operation | Wall clock | API calls | Notes |
|---|---|---|---|
| Model chain fetch | ~2s | 1 | First call, cached for rest of pipeline |
| Hunt (6 packs, 3 workers) | 5-15 min | 6 | Most models 429; fallback chain adds 30-60s per skip |
| Validate (3 findings) | 2-5 min | 3 | Faster because less context per call |
| Trace (3 findings) | 2-5 min | 3 | Same as Validate |
| Cache replay | <1s | 0 | All stages skip to cached output |

Total first-run: ~15-25 minutes for a library of zlib's size. Re-runs: instant.

## Cache Strategy (Critical for Cost)

Without caching, each re-run of the pipeline burns API calls on identical
prompts. Implement a simple JSON file cache:

```python
import hashlib, threading

_cache = {}
_cache_lock = threading.Lock()

def cache_key(stage: str, model: str, text: str) -> str:
    h = hashlib.sha256(text.encode()).hexdigest()[:12]
    return f"{stage}:{model}:{h}"

def cache_get(key: str):
    with _cache_lock:
        return _cache.get(key)

def cache_put(key: str, value: str):
    with _cache_lock:
        _cache[key] = value
        json.dump(_cache, open(CACHE_FILE, "w"))
```

Cache key format: `hunt:deepseek/deepseek-v4-flash:free:a1b2c3d4e5f6`.
Check cache before every API call; save after every successful response.
On re-run, the pipeline loads from cache and skips all prior API calls,
making re-runs instant.

## Python str.format() Trap

System prompts that contain JSON examples with `{` `}` braces will crash
`str.format()` with `KeyError`. For example:

```python
PROMPT = """... emit a coverage_gap record: {"coverage_gap": "<area>"} ..."""
PROMPT.format(domain="mem-safety")  # KeyError: '"coverage_gap"'
```

**Fix:** Double-escape literal braces that aren't intended as format
placeholders:
```python
PROMPT = """... emit a coverage_gap record: {{"coverage_gap": "<area>"}} ..."""
```

Rule: if it's not a `{name}` format placeholder, write it as `{{...}}`.

## Validate Needs a System Message

Some models (nemotron, trinity) return **empty responses** when there is
no system message in the API call. Always include one:

```python
messages = [
    {"role": "system", "content": "You are an adversarial code reviewer. "
     "Disprove findings. Output ONLY a JSON object with 'status' and 'reason'."},
    {"role": "user", "content": prompt},
]
```

## Validate Model Chain Must Be Disjoint from Hunt

A critical finding from the zlib run: **if Validate shares a model with Hunt,
correlated biases slip through.** The Hunt stage used deepseek-v4-flash and
reported gzprintf format strings as HIGH findings. The Validate stage used
nemotron-nano (completely different model family) and correctly rejected them
as by-design API behavior. If both stages had used deepseek, the shared
bias toward reporting format-string patterns would have left false positives
in the final triage.

Implementation rule: fetch the model list once at startup, then split:
- Hunt gets models A-J (e.g., deepseek, qwen, gemma)
- Validate gets models K-Z (e.g., nemotron, trinity, z-ai)
- No overlap. Not one model in common.

If the model list is too small for a clean split (e.g., only 3-4 reliable
models for free tier), prioritize: give the strongest model to Validate
because disagreement beats agreement:
```
hunt_models = [m for m in sorted_models if "deepseek" in m or "qwen" in m or "gemma" in m]
validate_models = [m for m in sorted_models if "nemotron" in m or "trinity" in m]
```

## Validate Model Chain Should Be Curated

Not all models work for validation. Many return empty bodies on OpenRouter's
free tier. Of 24 free models tested, only these reliably produced output:
`nvidia/nemotron-nano-12b-v2-vl:free`, `deepseek/deepseek-v4-flash:free`,
`nvidia/nemotron-3-super-120b-a12b:free`, `arcee-ai/trinity-large-thinking:free`.

For validate, prefer a curated model order rather than raw context-length
sorting. Push known-working models to the front of the chain.

## PoC Compilation Blocker

The PoC confirmation loop assumes a sandboxed compile+run environment.
For C/C++ targets, this requires:
- A compiler toolchain in the sandbox
- The target library compiled as a shared object
- A harness that links against it and triggers the finding
- Network-isolated execution

Without this infrastructure, PoC confirmation is speculative. The pipeline
still produces useful findings, but they lack the strongest evidence level.

## API-by-Design False Positives (Library-Specific)

The most common misclassification in library targets: **findings where the
library intentionally exposes a dangerous-looking API by design.**

Example from zlib: `gzprintf(format, ...)` works like `printf(3)` — the
caller provides the format string. This is not a format string vulnerability
in zlib. The vulnerability would only exist if a *consumer* passes
attacker-controlled data as the format argument, which is a misuse of the
API at the call site, not a bug in zlib.

How to catch these:
1. **Validate stage** must check whether the alleged "attacker-controlled"
   parameter is by-design caller-controlled (like printf's format arg).
2. **Tag the API contract** in `SECURITY_CONTEXT.md`: "Functions named
   `*printf*` intentionally accept caller-controlled format strings."
3. **Bucket rule**: if the exploit requires the consumer to misuse the API,
   it's `backlog` at best (documentation improvement), never `fix_now`.

Known API patterns that produce this false positive:
- `*printf*(format, ...)` — caller provides format string by design
- `*write*(buf, len)` — caller provides data by design
- `*read*(buf, len)` — caller provides buffer by design
- `execute*(cmd)` — caller provides command by design
- `*open*(path, ...)` — caller provides path by design

## Entry-Point Anchoring for Library Targets

Findings in a shared library have no intrinsic entry point — the library
has no `main()`. Every function is callable. For `fix_now` classification:

- A library finding needs a **consumer context** to be actionable
- The Trace stage (consumer fan-out) is essential for library targets
- Until traced, library findings should default to `backlog` unless CRITICAL
