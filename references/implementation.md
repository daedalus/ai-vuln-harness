# Implementation Reference

Code sketches and prompt templates for each harness stage.
Load this file when writing, reviewing, or debugging harness code.

---

## ingestor.py

Converts a repo into a flat, typed snippet database. See `stages/ingestor.py`.

Key notes:
- Uses `tree-sitter` (≥ 0.25) for AST-level extraction — regex-based extraction is forbidden.
  **API note:** 0.22 `parser.set_language(C_LANG)` is incompatible. Use
  `parser.language = C_LANG` (property setter). For pre-built wheels with capsule API
  (0.25.2+), use `Language(c_lang())`.
- Uses `tiktoken` (required, no fallback) — char-based `len//4` overestimates C by 30-40%.
- Directory filtering: exclude `contrib`, `examples`, `test`, `tests`, `.git`.
- Tag inflation mitigation: narrow `external-input` to actual I/O syscall wrappers
  (`read`, `recv`, `fread`, `fgets`, `gets`, `scanf`); narrow `integer-arith` to
  arithmetic operators on size/length variables.
- `child_by_field_name("name")` silently returns `None` for ~60% of C/C++ functions
  when the return type is on a separate line (e.g. `static int\nfunc_name(...)`).
  The function name is nested inside a `function_declarator` child instead. Use
  `_get_function_name()` to check both paths.
- Deterministic IDs: `sha256(f"{file}:{name}:{line}")` — never `hash()` or `id()`
  (PYTHONHASHSEED randomization).
- Self-call filtering: skip function's own name when extracting callees.

---

## coordinator.py

Builds per-agent context packs from the snippet DB. See `stages/coordinator.py`.

```
AGENT_DOMAINS:
  mem-safety:      tags=[memory, integer-arith, unsafe],     exclusive=True
  auth:            tags=[auth],                               exclusive=False
  crypto:          tags=[crypto],                             exclusive=True
  ipc:             tags=[ipc],                                exclusive=False
  data-flow:       tags=[external-input],                     exclusive=False
  format-str:      tags=[format-string],                      exclusive=True
  injection:       tags=[external-input],                     exclusive=False
  path-traversal:  tags=[memory],                             exclusive=False
  concurrency:     tags=[memory],                             exclusive=False
  resource:        tags=[memory, integer-arith],              exclusive=False
  secrets:         tags=[crypto],                             exclusive=True

DOMAIN_ORDER: mem-safety, data-flow, crypto, format-str, injection,
              path-traversal, concurrency, resource, secrets, auth, ipc
```

Budget = `int(model_context_limit * 0.85)` — leaves 15% for output.

---

## run_agents.py

Runs hunter agents in parallel. See `stages/runtime.py` and `stages/parser.py`.

Two patterns available. **Sync urllib + ThreadPoolExecutor** is preferred for free-tier
API reliability (avoids hidden per-connection rate limits that async triggers). **Async**
pattern for paid/private endpoints.

Health check filter at startup probes all models in parallel, removes DEAD ones.

Per-domain model routing:
```
mem-safety:  openrouter:nvidia/nemotron-nano-12b-v2-vl:free
data-flow:   openrouter:deepseek/deepseek-v4-flash:free
crypto:      openrouter:deepseek/deepseek-v4-flash:free
format-str:  openrouter:deepseek/deepseek-v4-flash:free
ipc:         openrouter:deepseek/deepseek-v4-flash:free
auth:        openrouter:deepseek/deepseek-v4-flash:free
```

Auth resolution order: project-relative `auth.json` → `~/.local/share/opencode/auth.json`
→ env var (`OPENROUTER_API_KEY`, `GROQ_API_KEY`, `CEREBRAS_API_KEY`, `GOOGLE_API_KEY`,
`ZEN_API_KEY`). File format: `{"openrouter": "sk-or-v1-...", "groq": "gsk_...", ...}`.

`--validate-only` flag skips Hunt, re-runs Validate + Dedupe + Report from cached
`output/findings.jsonl` and `output/gaps.jsonl`.

Output parser strategies: (1) try JSON array, (2) line-by-line JSONL, (3) extract largest
balanced-brace prefix from free text. Sentinel-only `{"done": true}` auto-generates a
coverage gap if no findings or gaps were emitted.

Call path normalization at parse time: `"a -> b -> c"` string → `["a", "b", "c"]` list.
By Shield stage, `call_path` must be `list[str]` — any string is a parse-layer bug.

Truncated JSON repair: balance braces, append missing `}`s. Succeeds on ~70% of truncated
responses; remaining 30% need full retry.

Every finding includes `bucket_rationale`. Report root includes `bucket_definitions`.

---

## shield.py

Call-graph construction, call-path verification, hallucination detection, static
reachability filtering. Sits between Validate/Dedupe and Chainer.
See `stages/shield.py`.

Key notes:
- `filter_unreachable()` must accept `snippet_db` to resolve finding snippet IDs into
  function names for graph lookup. Without it, every finding uses a `sha256:...` ID as
  graph key and all are marked unreachable.
- Hallucination risk scoring uses function-name + identifier matching, not raw token overlap.
- Gapfill rerun: different model + rephrased prompt. Two iterations max; remaining gaps
  after are genuine coverage gaps.

---

## chainer.py

Builds exploit chains from findings via call-graph BFS. See `stages/chains.py`.

Key note: snippet IDs must be resolved to lowercase function names before BFS — the call
graph is keyed on function names, not `sha256:...` IDs.

### Chain reasoning agent prompt

```
Given these findings and the code they reference, determine whether they can be
chained into a single exploit. Describe:
- The exploit primitive each step provides
- Preconditions at each step
- Overall severity
- One-paragraph PoC narrative (no working shellcode)

Output JSON (one object, no other text):
{
  "chain_id": "...",
  "feasible": true,
  "severity": "CRITICAL",
  "score": 7,
  "narrative": "...",
  "steps": [
    {"snippet_id": "...", "finding_id": "...", "primitive": "..."}
  ]
}
```

---

## PoC loop

A finding with a PoC is actionable. A finding without one is speculation.

**Critical isolation:** PoC runners must have no production access — sandboxed container
with no network egress and scoped API keys. See `stages/poc.py`.

**Separate agent tasks for better reasoning:**
- Agent A: "Is this code buggy / exploitable?"
- Agent B: "Is this code path reachable from external attacker input?"
Combining these into one prompt degrades reasoning quality on both dimensions.

---

## poc.py

Auto-generates C PoCs from findings, compiles under AddressSanitizer, runs, produces
verdict. See `stages/poc.py`.

**Class-targeted test generation dispatcher:**
```
buffer-overflow / Buffer Overflow Write → _gen_buffer_tests
format-string                          → _gen_format_tests
CWE-165                                → _gen_uninit_tests
CWE-369                                → _gen_recursion_tests
integer-wrap                           → _gen_integer_tests
```

**Verdict logic:** `asan_errors > 0` → confirmed; `exit_code == 0` → rejected;
else → needs-more-info. Pushed back as `poc_verdict` and `poc_reasoning` fields.

**Schema validation** runs at every stage (generation, compilation, execution).
Refuses to proceed if JSON becomes invalid.
