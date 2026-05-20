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

Total: 3 raw findings -> 1 backlog, 2 false_positive, 0 fix_now.

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
- **`--validate-only` flag** skips the Hunt stage entirely and loads cached
  findings from `output/findings.jsonl`. Useful for re-running Validate with
  a different model pool or after adjusting the validate prompt, without
  re-hunting. Runs Validate -> Dedupe -> Report from cache in under a second.
- **`--skip-health` flag** skips model health check at startup and loads
  cached health results. Essential for fast re-runs on the same target.
- **3 concurrent workers** is the sweet spot for free-tier OpenRouter.
  Higher concurrency triggers HTTP 429 rate limits.

### Timing expectations (free tier, zlib, 6 packs)

| Operation | Wall clock | API calls | Notes |
|---|---|---|---|
| Model chain fetch | ~2s | 1 | First call, cached for rest of pipeline |
| Health check (27 models) | ~20s | 27 | Parallel with 8 workers |
| Hunt (6 packs, 3 workers) | 5-15 min | 6 | Most models 429; fallback chain adds 30-60s per skip |
| Validate (3 findings) | 2-5 min | 3 | Faster because less context per call |
| Trace (3 findings) | 2-5 min | 3 | Same as Validate |
| `--skip-health` save | ~0s | 0 | Loads cached health results |
| `--validate-only` replay | <1s | 0 | Loads cached findings, Validate from cache, re-report |
| Cache replay (full) | <1s | 0 | All stages skip to cached output |

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

## Health Check (Essential for Free-Tier Runs)

Without a health check, the pipeline spends 15-60s per dead model. For a
27-model chain where 20 are dead, that is 5-20 minutes of timeouts before
useful work.

### Implementation

Run health checks in parallel at startup with 8 workers:

```python
with ThreadPoolExecutor(max_workers=8) as pool:
    futures = {pool.submit(probe_model, m): m for m in all_models}
    for future in as_completed(futures):
        mid, ok, err = future.result()
        if ok:
            alive.append(mid)
        else:
            dead.append((mid, err))
```

Cache result in `JsonCache("health_check")` keyed by model list hash.
Add `--skip-health` flag to load cache instead of probing.
Invalidate cache when config/defaults.json changes.

### Typical results (OpenRouter free tier)

| Status | Count | Examples |
|---|---|---|
| Alive | 7-8 | nemotron-nano, trinity, deepseek-v4-flash |
| 429 rate-limit | 10-12 | deepseek-v3, llama-4, mistral |
| 502/504 gateway | 3-5 | Various upstream providers |
| 403 geo-block | 2-3 | Groq/Cerebras from non-US IPs |

Show the full error reason for DEAD models (e.g. "HTTP 403" not just
"not available") so the operator can distinguish rate limits from
permanent rejects.

## Cross-Run Regression Risk (Critical Lesson)

The transition from run8 → run9 lost 2 catastrophic and 3 major features
that were caught only by a systematic cross-run audit. This pattern repeats
whenever a harness is restructured or re-targeted.

### Common regression vectors

| Risk | Symptom | How it happens |
|---|---|---|
| **Ingestor flattening** | File-level snippets instead of function-level | Developer replaces tree-sitter/brace-matching with simple `path.read_text()` when adding a new language or dropping a dependency |
| **Non-deterministic IDs** | `hash()` or `id()` used instead of SHA256 | Developer unfamiliar with PYTHONHASHSEED; works in dev, breaks cache on re-run |
| **Domain shrinkage** | 11 domains → 6 (or fewer) | Developer copies an older coordinator without noticing the expanded set |
| **Config simplification** | Provider matrix lost | defaults.json trimmed to remove "noise" but that noise was the multi-provider routing table |
| **Missing output files** | validated.jsonl, snippet_db.json absent | Output paths removed during refactoring without checking consumers |
| **Hardcoded model config** | MODEL_BY_DOMAIN inlined in hunt.py | Developer extracts model logic but forgets to make it config-driven |

### Mitigation checklist for every major restructure

1. Compare ingestor.py line count (run N-1 vs run N). If it shrank by >30%,
   investigate what extraction logic was dropped.
2. Check all `hash()` and `id()` calls in the codebase — these are non-deterministic.
   Every snippet ID must use SHA256.
3. Count `AGENT_DOMAINS` keys. 11 is correct for the full set. Count again
   when loading config or code.
4. Diff `config/defaults.json` against the previous version's config. Every
   field removal is a regression unless explicitly documented.
5. Check `output/` paths in `run.py` — every output file from the previous
   iteration should still have a write path.
6. Search for hardcoded model IDs in Python files (not config). They should
   live in `config/defaults.json`, not in stage code.

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

## Reasoning Models Stash Output Differently

Models like `nemotron-*` and `trinity-large-thinking` return reasoning/
rephrased content in `message.reasoning` instead of `message.content`.
If `call_llm()` only reads `content`, these models return empty strings.

### Fix: merge reasoning into content after the API call

```python
text = response.choices[0].message.content or ""
reasoning = getattr(response.choices[0].message, "reasoning", None) or ""
if reasoning and not text.strip():
    text = reasoning
```

### Side effect: reasoning models produce much longer outputs

- Standard model returns 200-400 tokens for a validate response.
- Nemotron/trinity return 800-2000 tokens — heavy reasoning trace
  capped with a short answer.
- Validate must use 8192 max_tokens (not 4096) or the JSON is
  truncated mid-brace. See Truncated JSON Repair below.

## Truncated JSON Repair in Validate

Reasoning models often exceed max_tokens limits. When validate's JSON
response is cut off mid-brace, json.loads() fails silently and the
finding is misclassified.

### Repair strategy

After json.loads() fails, attempt repair before giving up:

```python
def _repair_truncated_json(text: str) -> str:
    text = text.strip()
    if not text.endswith("}"):
        text += "}"
    depth = 0
    for ch in text:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
    while depth > 0:
        text += "}"
        depth -= 1
    while depth < 0 and text.rfind("}") > text.rfind("{"):
        text = text.rstrip("}")
        depth += 1
    return text
```

This succeeds on ~70% of truncated validate responses. The remaining 30%
need a full retry (next model in chain).

## Retry on 502/503/504 Errors (Not Just 429)

OpenRouter free tier returns HTTP 502/504 when upstream providers are
overloaded. These are transient errors, not model failures.

Expand retryable status to cover provider gateway errors:

```python
is_retryable = any(x in estr for x in (
    "429", "502", "503", "504",
    "rate", "too many",
    "try again", "temporary", "upstream"
))
```

Use exponential backoff: 5 * (attempt + 1) seconds. 3 retries max.

## Hallucination Risk: Function-Name + Identifier Matching

Raw token overlap between finding description and snippet content is too
coarse. In zlib, over half the functions share tokens like `buf`, `len`,
`size` — every finding scores "low" regardless of accuracy.

### Better heuristic

```python
# 1. Function name MUST appear in finding description
if name and name not in desc:
    return "high"

# 2. Check overlap of significant identifiers
identifiers = set(re.findall(r'\b[a-z_][a-z_0-9]+\b', content))
desc_identifiers = set(re.findall(r'\b[a-z_][a-z_0-9]+\b', desc))
overlap = identifiers & desc_identifiers

# 3. Keyword bonus for vulnerability-specific terms
keywords_in_desc = sum(1 for kw in ("overflow", "underflow",
    "uninitialized", "wrap", "oob", "memcpy", "malloc", "free",
    "null", "bounds", "stack", "heap", "recursion", "injection",
    "truncation") if kw in desc)

if len(overlap) >= 2 or keywords_in_desc >= 1:
    risk = "low"
elif len(overlap) == 1:
    risk = "medium"
else:
    risk = "high"
```

Key identifiers matter more than raw word count. A finding about `deflate`
that does not mention `deflate` or any of its local variables is hallucinated.

## Auth File Resolution Order

Multiple API keys in a shared setting create confusion. Deterministic fallback:

```python
import os, json

ORDER = [
    os.path.join(os.path.dirname(__file__), "../auth.json"),
    os.path.expanduser("~/.local/share/opencode/auth.json"),
]

def _get_auth_key(provider: str) -> str | None:
    env_map = {
        "openrouter": "OPENROUTER_API_KEY",
        "groq": "GROQ_API_KEY",
        "cerebras": "CEREBRAS_API_KEY",
    }
    env_key = os.environ.get(env_map.get(provider, ""))
    if env_key:
        return env_key
    for path in ORDER:
        try:
            data = json.load(open(path))
            key = data.get(provider) or data.get(f"{provider}_api_key")
            if key:
                return key
        except (FileNotFoundError, json.JSONDecodeError):
            continue
    return None
```

File format is flat: `{"openrouter": "sk-or-v1-...", "groq": "gsk_..."}`.
Not nested. Provider key in top-level JSON matches the provider name.
Current working directory auth.json takes priority over the global one.

## Multi-Provider Architecture

Use provider-prefixed model IDs to route through a single flat chain:

```
openrouter:nvidia/nemotron-nano-12b-v2-vl:free
groq:llama3-70b-8192
cerebras:llama3.1-8b
```

call_llm() splits on the first colon to determine base URL, auth key,
and headers. This keeps model lists homogeneous and lets you add
providers without changing the stage code.

### Implementation pattern

```python
def call_llm(model_id: str, prompt: str, **kwargs):
    provider, _, model_name = model_id.partition(":")
    if provider == "openrouter":
        return _call_openrouter(model_name, prompt, **kwargs)
    elif provider == "groq":
        return _call_groq(model_name, prompt, **kwargs)
    elif provider == "cerebras":
        return _call_cerebras(model_name, prompt, **kwargs)
    else:
        raise ValueError(f"unknown provider: {provider}")
```

Each provider function reads its own auth key via `_get_auth_key()`.

## Proxy Support Through Environment Variables

Set http_proxy/https_proxy at startup before any API calls to get
transparent proxy support via urllib's default ProxyHandler:

```python
import os

if proxy_url := args.proxy:
    os.environ["http_proxy"] = proxy_url
    os.environ["https_proxy"] = proxy_url
```

Or set `proxy` key in config/defaults.json and apply at startup.
This works for all OpenAI-compatible providers without code changes.

## PoC Confirmation (Compile + Run)

The PoC stage auto-generates C programs from findings, compiles them under
AddressSanitizer, and executes them. This is the strongest evidence level:
a compiler+ASan verdict beats any LLM opinion.

### File layout

```
output/pocs/
  poc-<snippet_id>-<class>.c      # Auto-generated C source
  poc-<snippet_id>-<class>.json   # Schema-valid PoC JSON
```

### How it detects test targets

The generator inspects snippet content for library signatures to produce
context-aware tests:

| Snippet contains | PoC links | Tests generated |
|---|---|---|
| `z_streamp`, `inflate`, `zlib.h` | `-lz` | Inflate/deflate at window bits 8/9/12/15 |
| `SSL_CTX`, `SSL_new` | `-lssl -lcrypto` | SSL init, read, write edge cases |
| nothing specific | (none) | `calloc` + `memset` bounds check |

### Class-specific test generation

Each vulnerability class gets targeted tests:

- **buffer-overflow** — allocates buffer, writes up to capacity, checks ASan
  - zlib `updatewindow` variant: actually calls `inflateInit2`/`inflate` with
    varying window sizes to exercise each code path in the circular buffer
- **format-string** — passes caller-controlled format arg through `snprintf`
- **uninitialized** — calls suspect function with zero-length read
- **recursion** — deep recursion to `MAX_DEPTH=100000` to trigger stack overflow
- **integer-wrap** — `1U << 31`, `0U - 1U`, `malloc(overflowed_size)`

### Verdict logic

| Condition | Verdict | Interpretation |
|---|---|---|
| ASan errors detected | confirmed | The finding reproduces under sanitized conditions |
| Exit code 0, no ASan errors | rejected | The alleged bug does not exist as described |
| Build failed or crashed without ASan | needs-more-info | Indeterminate — manual review required |

### CLI modes

```
--poc <id|all>      # During normal pipeline: also generate+compile+run PoCs
--poc-only          # Skip all API stages, load cached findings, just run PoCs
```

`--poc-only` is the zero-cost replay mode. It reads cached `findings.jsonl`,
re-generates any missing PoCs, compiles and runs everything, and produces
an updated report with `poc_verdict` annotations. No API calls, no LLM cost.

### What the PoC does NOT test

- **Multi-step exploits** — PoCs are single-finding, single-class. The
  Chainer stage handles composition across findings.
- **Consumer reachability** — PoC confirms the primitive exists in the
  library, not that an attacker can reach it. Trace stage handles that.
- **Other architectures** — PoCs run on the build host. ARM/MIPS/RISC-V
  require cross-compilation infrastructure.
- **Timing / side channels** — ASan does not detect these. Manual review
  or TSan needed.

### Integration with Suppression

If a finding is suppressed (known false positive), the PoC stage skips it.
If a PoC confirms a suppressed finding (unexpected ASan crash on previously
dismissed bug), the suppression is flagged for review.

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
