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

## Entry-Point Anchoring for Library Targets

Findings in a shared library have no intrinsic entry point — the library
has no `main()`. Every function is callable. For `fix_now` classification:

- A library finding needs a **consumer context** to be actionable
- The Trace stage (consumer fan-out) is essential for library targets
- Until traced, library findings should default to `backlog` unless CRITICAL
