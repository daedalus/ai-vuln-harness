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
|--------|----------|----------|-----------------|
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

See `stages/coordinator.py` and `stages/ingestor.py` docstrings for filter construction.

Key observations from zlib:
- `external-input` keyword-match on `buf`/`arg`/`len`/`src` matches 607/608 functions (99.9%),
  making auth/ipc/data-flow packs identical to mem-safety. Strip from all domain filters
  EXCEPT data-flow when targeting compiled libraries. For data-flow, detect `read()`/`recv()`/`fgets()` calls.
- `integer-arith` on `len`/`size`/`count` matches every buffer-processing function.
  Narrow to operations on untrusted lengths only.
- data-flow findings in a library are reachability questions, not library bugs.
  They become useful in the Trace stage when mapped to consumer repos.

## Model Behavior Observations

Free-tier quality varies wildly. Reasoning models (nemotron, deepseek)
produce thorough analysis in 30-60s; standard models (gemma, z-ai, baidu)
respond in 5-15s but miss subtle patterns. Paid models would reduce
variance significantly.

## Pipeline Robustness Patterns

See `run.py` docstring for CLI flags (`--reingest`, `--max-run`, `--validate-only`, `--skip-health`)
and run modes.

Key implementation choices not in code:
- Print all status to stderr, findings JSONL to stdout.
- Each stage is a standalone script reading/writing JSON(L) files — rerunnable individually.
- 3 concurrent workers is the sweet spot for free-tier OpenRouter (higher triggers 429).

### Timing expectations (free tier, zlib, 6 packs)

| Operation | Wall clock | API calls | Notes |
|-----------|------------|-----------|-------|
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

See `stages/runtime.py` docstring for implementation.

Cache key format: `hunt:deepseek/deepseek-v4-flash:free:a1b2c3d4e5f6`.
Check cache before every API call; save after every successful response.
Without caching, each re-run burns API calls on identical prompts.

## Health Check (Essential for Free-Tier Runs)

See `stages/runtime.py` docstring for implementation (parallel probes, `--skip-health` flag).

Without a health check, the pipeline spends 15-60s per dead model.
For a 27-model chain with 20 dead models, that's 5-20 minutes of timeouts.

### Typical results (OpenRouter free tier)

| Status | Count | Examples |
|--------|-------|---------|
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
|------|---------|----------------|
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
no system message in the API call. Always include one directing the model
to output only a JSON object with `status` and `reason`.

## Validate Model Chain Must Be Disjoint from Hunt

See `stages/validate.py` and `stages/runtime.py` docstrings for full implementation.

Key finding from zlib: if Validate shares a model with Hunt, correlated biases slip through.
The Hunt stage used deepseek-v4-flash and reported gzprintf format strings as HIGH findings.
The Validate stage used nemotron-nano (completely different family) and correctly rejected
them as by-design API behavior. If both had used deepseek, shared bias toward format-string
reporting would have left false positives in final triage.

Rule: split the model list at startup — no overlap between Hunt and Validate.
Hunt gets models A-J (deepseek, qwen, gemma); Validate gets K-Z (nemotron, trinity, z-ai).
When the pool is small, give the strongest model to Validate: disagreement beats agreement.

### Validate Model Chain Should Be Curated

Of 24 free models tested, only these reliably produced output:
`nvidia/nemotron-nano-12b-v2-vl:free`, `deepseek/deepseek-v4-flash:free`,
`nvidia/nemotron-3-super-120b-a12b:free`, `arcee-ai/trinity-large-thinking:free`.
For validate, prefer a curated model order rather than raw context-length sorting.

## Reasoning Models Stash Output Differently

See `stages/runtime.py` docstring for implementation (reasoning-content merge).

Key points: models like nemotron-* return content in `message.reasoning` instead of
`message.content`. Always merge reasoning into content after the API call.

Side effect: reasoning models produce 800-2000 tokens vs 200-400 for standard models.
Validate must use 8192 max_tokens (not 4096) or the JSON is truncated mid-brace.

## Truncated JSON Repair in Validate

See `stages/runtime.py` and `stages/parser.py` docstrings for implementation.

Reasoning models often exceed max_tokens, truncating JSON mid-brace.
The repair strategy (closing unclosed braces) succeeds on ~70% of truncated responses.
The remaining 30% need a full retry (next model in chain).

## Retry on 502/503/504 Errors (Not Just 429)

See `stages/runtime.py` docstring for implementation (exponential backoff).

OpenRouter free tier returns HTTP 502/504 when upstream providers are overloaded.
Expand retryable status to cover 502, 503, 504 in addition to 429/rate-limit.
Use exponential backoff: 5 × (attempt + 1) seconds, 3 retries max.

## Hallucination Risk: Function-Name + Identifier Matching

See `stages/shield.py` docstring for implementation.

Raw token overlap is too coarse — over half of zlib functions share tokens like
`buf`/`len`/`size`. Better heuristic from the field: function name MUST appear in
finding description; check overlap of significant identifiers; keyword bonus for
vulnerability-specific terms. A finding about `deflate` that doesn't mention
`deflate` or any of its local variables is hallucinated.

## Auth File Resolution Order

See `stages/runtime.py` docstring for implementation.

Deterministic fallback: 1) environment variable (`OPENROUTER_API_KEY`, etc.),
2) `auth.json` in project directory, 3) `~/.local/share/opencode/auth.json`.
File format is flat JSON keyed by provider name. CWD auth.json takes priority
over global.

## Multi-Provider Architecture

See `stages/runtime.py` docstring for `call_llm()` implementation.

Use provider-prefixed model IDs (e.g., `openrouter:nvidia/nemotron-nano:free`,
`groq:llama3-70b-8192`) to route through a single flat chain. `call_llm()`
splits on the first colon to determine base URL, auth key, and headers.
Each provider reads its own auth key via the auth resolution chain.

## Proxy Support Through Environment Variables

Set `http_proxy`/`https_proxy` at startup before any API calls for transparent
proxy support. Can be passed via `--proxy` CLI flag or `proxy` key in
`config/defaults.json`. Works for all OpenAI-compatible providers without
code changes.

## PoC Confirmation (Compile + Run)

See `stages/poc.py` docstring for full implementation, class-specific test
generation, and CLI modes (`--poc`, `--poc-only`).

The PoC stage auto-generates programs from findings, compiles under
AddressSanitizer, and executes them. File layout:
`output/pocs/poc-<snippet_id>-<class>.c` and `.json`.

### Detection targets

| Snippet contains | PoC links | Tests generated |
|------------------|-----------|-----------------|
| `z_streamp`, `inflate`, `zlib.h` | `-lz` | Inflate/deflate at window bits 8/9/12/15 |
| `SSL_CTX`, `SSL_new` | `-lssl -lcrypto` | SSL init, read, write edge cases |
| nothing specific | (none) | `calloc` + `memset` bounds check |

### Verdict logic

| Condition | Verdict | Interpretation |
|-----------|---------|----------------|
| ASan errors detected | confirmed | The finding reproduces under sanitized conditions |
| Exit code 0, no ASan errors | rejected | The alleged bug does not exist as described |
| Build failed or crashed without ASan | needs-more-info | Indeterminate — manual review required |

### What the PoC does NOT test

- **Multi-step exploits** — Chainer stage handles composition across findings.
- **Consumer reachability** — Trace stage confirms attacker can reach it.
- **Other architectures** — ARM/MIPS/RISC-V require cross-compilation infrastructure.
- **Timing / side channels** — TSan needed, not ASan.

### Integration with Suppression

If a finding is suppressed (known false positive), the PoC stage skips it.
If a PoC confirms a suppressed finding (unexpected ASan crash on previously
dismissed bug), the suppression is flagged for review.

## API-by-Design False Positives (Library-Specific)

See `stages/validate.py` and `stages/report.py` docstrings for the validation
and triage logic.

The most common misclassification in library targets: findings where the
library intentionally exposes a dangerous-looking API by design (e.g., `gzprintf`
works like `printf(3)` — caller provides the format string; this is not a
vulnerability in zlib). The Validate stage must check whether the alleged
"attacker-controlled" parameter is by-design caller-controlled. If the exploit
requires consumer misuse, it's `backlog` at best (documentation improvement),
never `fix_now`.

Known API patterns that produce this false positive:
- `*printf*(format, ...)` — caller provides format string by design
- `*write*(buf, len)` — caller provides data by design
- `*read*(buf, len)` — caller provides buffer by design
- `execute*(cmd)` — caller provides command by design
- `*open*(path, ...)` — caller provides path by design

## Entry-Point Anchoring for Library Targets

See `stages/report.py` docstring for triage rules.

Findings in a shared library have no intrinsic entry point — the library
has no `main()`. Every function is callable. A library finding needs a
**consumer context** to be actionable. The Trace stage (consumer fan-out)
is essential for library targets. Until traced, library findings should
default to `backlog` unless CRITICAL.
