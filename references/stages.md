# Stage Detail Reference

Detailed design and implementation guidance for each pipeline stage.
Load this when implementing or debugging a specific stage.

See also: `implementation.md` (code sketches), `schemas.md` (data formats).

---

## Stage 1 — Ingestor

**Goal:** convert a repo into a flat, typed snippet database that fits agents
into budget-bounded context windows, enriched with historical context.

See `schemas.md` → **Snippet schema** for the full field spec.
See `implementation.md` → **ingestor.py** for the code sketch.

### Chunking rules

- Unit: **function** for C/C++/Rust/Go; **method** for Python/Java/TS.
  Fall back to fixed 200-line windows for languages without reliable function
  boundaries.
- Hard cap: **800 tokens per snippet** (leaves budget for ~250 snippets per
  pack at 85% context window). Use `tiktoken` with `cl100k_base` encoding.
- Large functions: split at logical boundaries, emit `continuation: true` on
  subsequent pieces so the chainer can reconstruct.
- Cross-file context: embed 3-line caller/callee stubs inline — agents need
  the call signature without fetching another snippet.

### Snippet IDs

Use short sha256 IDs for readability: `sha256:{h[:6]}:{h[-6:]}` (e.g.
`sha256:e812b9:ab0d84`). Full sha256 is unnecessarily verbose in logs and
finding references.

### Tree-sitter is required (no regex fallback)

tree-sitter ≥ 0.25 is a required dependency. Regex-based brace-depth matching
is forbidden — it misses type-anchored re-exports (`int ZEXPORT inflate(...)`)
and nested-scope functions. Every such miss is a silent coverage gap that
cannot be detected from output counts.

The API changed in 0.25.x and is **not backwards compatible** with 0.22:

```python
from tree_sitter import Language, Parser

# 0.22.x (old, incompatible):
# parser.set_language(C_LANG)

# 0.25.x (required):
parser = Parser()
parser.language = C_LANG  # property setter, not method

# For pre-built wheels with capsule API (0.25.2+):
from tree_sitter_c import language as c_lang
C_LANG = Language(c_lang())
```

Verify the version at startup:

```python
import tree_sitter
parts = tuple(int(x) for x in tree_sitter.__version__.split('.')[:2])
if parts < (0, 25):
    sys.exit('fatal: tree-sitter {tree_sitter.__version__} detected, >= 0.25 required')
```

While the `_FUNC_DIRECT_RE` pattern is useful for understanding what tree-sitter
handles automatically, it must never be used as a replacement:

```python
# For reference only — NOT a fallback:
_FUNC_DIRECT_RE = re.compile(r'^\s*\w+\s*\(')
```

### Function name extraction: `child_by_field_name("name")` is not sufficient

tree-sitter-c's `function_definition` node does **not** always expose the
function name via `child_by_field_name("name")`. When the return type and
function name are on separate lines (e.g. `static int\naddr_masklen(int af)`),
the name is nested inside a `function_declarator` child node instead:

```
function_definition
  ├── storage_class_specifier: "static"
  ├── primitive_type: "int"
  ├── function_declarator: "addr_masklen(int af)"   ← name nested here
  │     ├── identifier: "addr_masklen"               ← the actual name
  │     └── parameter_list: "(int af)"
  └── compound_statement: "{ ... }"
```

A naive `node.child_by_field_name("name")` returns `None` for these functions,
causing the ingestor to silently skip them. This is a coverage gap that is hard
to detect because the output count is lower than expected but still non-zero.

**Fix:** fall back to traversing `function_declarator` children when
`child_by_field_name("name")` returns `None`:

```python
def _get_function_name(node) -> str | None:
    name_node = node.child_by_field_name("name")
    if name_node:
        return name_node.text.decode()
    decl = node.child_by_field_name("declarator")
    if decl:
        for c in decl.children:
            if c.type == "identifier":
                return c.text.decode()
    return None
```

This pattern was discovered during libopenssh analysis, where ~60% of function
definitions had multi-line return-type declarations and would have been silently
lost without this fallback.

### Callee extraction: filter self-calls

When extracting callees from a function body via regex, the function's own name
appears in its signature line and is falsely captured:

```python
def _extract_callees(body: str, func_name: str = '') -> list[str]:
    callees = []
    for m in _FUNC_NAME_RE.finditer(body):
        name = m.group(1)
        if name == func_name:       # skip self-reference from signature
            continue
        if name not in _CONTROL_FLOW and name not in seen:
            seen.add(name)
            callees.append(name)
    return callees
```

Without this filter, every function appears as a self-caller, polluting the
call graph with false edges.

### Tree-sitter API Notes (v0.25+) — if you must use it

The tree-sitter Python binding changed in 0.25.x. The v0.22 API
used `parser.set_language(lang)` and `Language("path.so", "lang")`.
In 0.25.x both changed:

```python
from tree_sitter import Language, Parser

# 0.25.x — property setter, not set_language()
parser = Parser()
parser.language = C_LANG

# Parse
tree = parser.parse(bytes(source, "utf8"))
```

For pre-built wheels, the Language constructor also changed:

```python
# 0.25.2+ — capsule constructor, not path+name
from tree_sitter_c import language as c_lang
C_LANG = Language(c_lang())
```

Check your version: `import tree_sitter; print(tree_sitter.__version__)`.
The API between 0.22.x and 0.25.x is **not backwards compatible**.

### Security tags

| Tag | Triggers |
|---|---|
| `memory` | `malloc`, `free`, `memcpy`, `ptr`, raw buffer ops |
| `external-input` | arg from network/file/env touching this function |
| `auth` | password, token, session, credential, permission |
| `crypto` | cipher, hash, key, IV, nonce, signature |
| `ipc` | socket, pipe, shm, mmap |
| `unsafe` | `unsafe` block (Rust), `reinterpret_cast` (C++) |
| `format-string` | `printf`-family with non-literal format arg |
| `integer-arith` | ops on sizes/lengths/indices without bounds check |

### Tag inflation warning (from zlib run)

Simple keyword matching for `external-input` is **too aggressive for compiled
libraries.** The keywords `buf`, `arg`, `len`, `src` appear in nearly every C
function signature. On zlib, this tagged 607/608 functions (99.9%) with
`external-input`, making `auth`, `ipc`, and `data-flow` packs identical to
`mem-safety`.

**Mitigation:** for library targets, either:
1. Remove `external-input` from all domain tag filters EXCEPT `data-flow`, or
2. Use a smarter heuristic for `data-flow`: detect actual I/O syscall wrappers
   (`read()`, `recv()`, `fgets()`, `fread()`) rather than parameter names.

Same applies to `integer-arith`: `len`, `size`, `count` match every
buffer-processing function. Narrow to operations on untrusted lengths only.

### Directory filtering (from zlib run)

Contrib, examples, and test directories contain unmaintained or harness code
that inflates snippet counts without representing the real attack surface.
On zlib, ~200 of 608 snippets came from these directories.

**Recommendation:** before building packs, filter the snippet DB to remove:
- `contrib/` — third-party, unmaintained, or single-use code
- `examples/` — demo/illustration code, not production
- `test/` — test harnesses and fixtures
- Any directory matching `^\.` — hidden/system directories

This focuses hunters on the library's actual attack surface.

### Historical Context Mining (Recon Enhancement)

Enhance the Ingestor stage by mining git history for past security patches:
- Search git log for security-related commits: `git log --grep='CVE\|security\|vuln\|sec:\|fix.*auth\|fix.*injection\|sanitize\|escape\|bypass' --oneline -50`
- For each relevant commit, identify the fixed pattern and grep the codebase for similar idioms
- Seed initial hunt tasks against unpatched copies of vulnerable patterns (sibling files)
- This adds zero cost on repositories without security history but catches cross-component bugs when present

---

## Stage 2 — Recon

**Goal:** map the repo before hunting — identify subsystems, build system,
entry points, and generate structured hunt tasks with concrete file targets
per attack class. Without this stage, the Coordinator builds packs from the
entire snippet DB with no prioritization, wasting context on irrelevant code.

See `~/code/audit/prompts/recon.md` and `~/code/audit/config/stages.yaml`
for the reference implementation.

### Recon Agent Mission

Analyze the repository and produce a prioritized list of hunt tasks:

1. **Identify subsystems** — top-level directories, module boundaries,
   core vs. test vs. example code. Output a subsystem map.
2. **Detect build system** — `Makefile`, `CMakeLists.txt`, `Cargo.toml`,
   `pyproject.toml`, `go.mod`. This tells you which code is actually compiled.
3. **Locate entry points** — `main()`, exported symbols, signal handlers,
   inbound API routes, plugin interfaces, callback registrations.
4. **Generate hunt tasks** — for each attack class, list which files to
   target and why. Example:
   ```json
   {"domain": "mem-safety", "target_files": ["inflate.c", "deflate.c", "trees.c"],
    "rationale": "decompression path handles untrusted input", "priority": "high"}
   ```

### Recon Output Schema

```json
[
  {
    "task_id": "t_core_mem-safety_1",
    "domain": "mem-safety",
    "attack_class": "buffer-overflow",
    "target_files": ["src/decompress.c", "src/stream.c"],
    "rationale": "Decompression reads untrusted input into fixed buffers",
    "priority": "high"
  }
]
```

The Recon output is consumed by the Coordinator, which filters snippets to
only the `target_files` before building domain packs.

### What Recon Prevents

- **Inflated packs** — without target file filtering, the Coordinator includes
  every function from the snippet DB. Recon narrows each pack to the relevant
  subsystem, typically cutting pack size by 40-60%.
- **Wasted context** — test harness code, contrib/ code, and unrelated modules
  are excluded before hunters ever see them.
- **Missing entry points** — without explicit entry-point identification,
  hunters miss attack surface (e.g., signal handlers, callback exports).

---

## Stage 3 — Coordinator

**Goal:** build per-agent **context packs**

 — curated snippet subsets scoped to
one security domain — so each agent can be cold-started with no repo access.

See `schemas.md` → **Context pack schema** for the full field spec.

### Agent domains (11-domain set)

| Agent | Tags selected | Exclusive | Focus |
|---|---|---|---|
| `mem-safety` | `memory`, `integer-arith`, `unsafe` | Yes | Buffer overflow, OOB R/W, UAF, integer wrap |
| `auth` | `auth` | No | Bypass, privilege escalation, session fixation |
| `crypto` | `crypto` | Yes | Weak primitives, IV reuse, padding oracle, key mgmt |
| `ipc` | `ipc` | No | TOCTOU, injection via pipes/sockets |
| `data-flow` | `external-input` | No | Untrusted data reaching sinks |
| `format-str` | `format-string` | Yes | Format string exploits |
| `injection` | `external-input` | No | Command injection, argument injection through untrusted data |
| `path-traversal` | `memory` | No | File path traversal, symlink attacks through buffer ops |
| `concurrency` | `memory` | No | Race conditions, TOCTOU, signal safety, double-fetch |
| `resource` | `memory`, `integer-arith` | No | Resource exhaustion, memory leak, file descriptor leak |
| `secrets` | `crypto` | Yes | Hardcoded secrets, credential exposure, improper secret handling |

**Exclusive domains** (`mem-safety`, `crypto`, `format-str`, `secrets`): only
get snippets whose tags match their domain tag list. Non-exclusive domains get
snippets matching their tags AND any snippet from the full DB that lacks any
targeted tag — ensuring coverage of untagged code.

**`DOMAIN_ORDER`**: `["mem-safety", "data-flow", "crypto", "format-str",
"injection", "path-traversal", "concurrency", "resource", "secrets",
"auth", "ipc"]` — dependency-ordered so memory/crypto are processed before
derivative domains.

Embed a `SECURITY_CONTEXT.md` per repo in every pack: entry points, trust
boundaries, known-unsafe modules, memory allocator in use, sanitizer flags.

### Scope Notes Integration

Incorporate scope notes to exclude specific components or attack classes:
- Accept verbatim scope notes from operator (e.g., "Mailpit (port 1025) is test-only; ignore.")
- Append scope notes verbatim to every stage's user_input
- Have agents honor exclusions listed in scope notes during processing
- This prevents wasting resources on intentionally-loose-by-design surfaces

### Budget enforcement

Each pack must not exceed **85% of the model's context window** (the remaining
15% is reserved for the model's output). For example, a 100k-context model
allows an 85k pack budget. If a domain exceeds budget, split into sub-packs
by directory prefix and run multiple instances in parallel.

### Pack size observations

Expected relative sizes for a compiled-language library with ~350 functions:

| Domain | Relative pack size | Notes |
|---|---|---|
| `mem-safety` | Largest | Most C/C++ functions touch memory |
| `ipc` | Large | `external-input` tag overlap inflates it |
| `auth` | Large | Same inflation from `external-input` overlap |
| `data-flow` | Large | Single tag, still large |
| `crypto` | Medium | Sparse unless crypto-specific code |
| `format-str` | Small | Very few printf-family calls in most codebases |

**Key takeaway:** `external-input` tag overlap inflates ipc/auth packs. In a
pure C library, mem-safety dominates. Some domains will produce honest coverage
gaps (auth, crypto, ipc) — this is normal for libraries with a narrow
functional scope. The gapfill stage should re-queue these with narrowed scope.

---

## Stage 4 — Hunter Cluster

Each agent receives its context pack and a domain-scoped system prompt:

```
You are a single-attack-class vulnerability hunter. You have one task,
one attack class, one scope. You go deep, not wide. Other hunters cover
other attack classes — you do not stray.

Determine whether the given attack class is present in the assigned
scope. Emit zero or more findings, each anchored to specific code lines
with verbatim evidence. Where possible, **prove** the bug by writing
code that triggers it, compiling it in your scratch directory, and
running it.
```

Run agents in parallel. See `implementation.md` → **run_agents.py**.

### Model Selection

Use your highest-capability model for `mem-safety`, `data-flow`, and
`crypto` — these require deep reasoning. A faster/cheaper model tier is
acceptable for `format-str` and `ipc`, which are more pattern-driven.

Implement via `MODEL_BY_DOMAIN` dict with provider-prefixed model IDs:

```python
MODEL_BY_DOMAIN = {
    "mem-safety":       "openrouter:deepseek/deepseek-v4-flash:free",
    "data-flow":        "openrouter:qwen/qwen3-coder:free",
    "crypto":           "openrouter:qwen/qwen3-coder:free",
    "format-str":       "openrouter:google/gemma-4-26b-a4b-it:free",
    "ipc":              "openrouter:google/gemma-4-26b-a4b-it:free",
    "auth":             "openrouter:google/gemma-4-26b-a4b-it:free",
    "injection":        "openrouter:deepseek/deepseek-v4-flash:free",
    "path-traversal":   "openrouter:qwen/qwen3-coder:free",
    "concurrency":      "openrouter:google/gemma-4-26b-a4b-it:free",
    "resource":         "openrouter:qwen/qwen3-coder:free",
    "secrets":          "openrouter:deepseek/deepseek-v4-flash:free",
}
```

The prefix (`openrouter:`, `groq:`, `cerebras:`) is stripped by
`call_llm()` and used to select the right provider configuration.
This keeps model lists homogeneous across providers.

Fall back to a shared default model for domains not in the dict.

### Model Fallback Chain (Important: Free-Tier Reality)

OpenRouter free-tier models are **frequently rate-limited (HTTP 429)**.
A single model per domain is not enough. You must implement a fallback
chain: try models in order of context length (descending), skipping
to the next on 429 or API error.

Implementation pattern:
1. Fetch all free models from `GET /v1/models` at startup.
2. Filter to `:free` suffix, sort by `context_length` descending.
3. Run a **parallel health check** against all models (8 workers).
4. Remove DEAD models from the chain so the pipeline does not waste
   time on them. Cache the health check result.
5. Start at the preferred model index; on 429, advance to next model.
6. 2 attempts per model before advancing (handles transient errors).
7. Retry on 502/503/504 too — these are transient provider overloads,
   not permanent failures.

```python
def fetch_model_chain(api_key: str) -> list[str]:
    req = urllib.request.Request(
        url="https://openrouter.ai/api/v1/models",
        headers={"Authorization": f"Bearer {api_key}"},
    )
    resp = urllib.request.urlopen(req, context=ssl.create_default_context(), timeout=30)
    data = json.loads(resp.read().decode())
    free = [m for m in data.get("data", [])
            if m.get("id", "").endswith(":free")
            and m.get("context_length", 0) >= 8192]
    free.sort(key=lambda m: m.get("context_length", 0), reverse=True)
    return ["openrouter:" + m["id"] for m in free]  # provider-prefixed
```

With multi-provider, the model list is defined in config/defaults.json
instead of fetched at runtime:

```json
{
  "hunt_models": [
    "openrouter:nvidia/nemotron-nano-12b-v2-vl:free",
    "openrouter:deepseek/deepseek-v4-flash:free",
    "openrouter:qwen/qwq-32b:free",
    "groq:llama3-70b-8192",
    "cerebras:llama3.1-8b"
  ]
}
```

Loops through models with `start_idx = model_chain.index(preferred)`.
On HTTP 429/502/503/504, logs the skip and tries `model_chain[start_idx + 1]`.

**Key observation:** Out of 24 free models on OpenRouter, only ~6 are
reliably available at any moment. The rest return 429 or empty responses.
Health check at startup removes the dead ones before any work begins.
The fallback chain is not optional — it is required for completion.

### Sync > Async (Practical Lesson)

Use **sync urllib**, not async httpx. Key reasons:

- Rate-limit handling is simpler in sync flow (no asyncio coordination)
- OpenRouter free-tier has hidden per-connection rate limits that
  async parallelism triggers more readily
- `ThreadPoolExecutor` with 3-4 workers provides sufficient parallelism
  without hitting rate limits
- No dependency on `httpx` or `aiohttp`

```python
import urllib.request, json

req = urllib.request.Request(
    url="https://openrouter.ai/api/v1/chat/completions",
    data=json.dumps(payload).encode(),
    headers={
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    },
)
resp = urllib.request.urlopen(req, context=ssl_context)
result = json.loads(resp.read().decode())
```

### Provider-Specific Notes

#### OpenRouter

- **`openrouter/openrouter/free` is NOT a valid model ID.** Use concrete
  model IDs like `deepseek/deepseek-v4-flash:free`. Fetch the full list
  from `GET /v1/models` and filter by `:free` suffix.
- **Model fallback chain is mandatory.** Free tier returns HTTP 429 on most
  models most of the time. Without the fallback, the pipeline stalls.
- **Reasoning models** put output in `message.reasoning`, not `message.content`:
  ```python
  content = msg.get("content", "") or ""
  reasoning = msg.get("reasoning", "") or ""
  full_output = reasoning if not content.strip() else content
  ```
- **Some models return empty response bodies.** Detect these and skip to
  the next model immediately. About 1/3 of free models exhibit this.
- **API errors without `choices`**: Always guard against `KeyError`:
  ```python
  if "choices" not in result or not result["choices"]:
      raise ValueError(f"no_choices: {json.dumps(result)[:200]}")
  ```
- **Proxy support**: Set `https_proxy` env var; urllib respects it natively.
- **`max_tokens` must be 8192 minimum** — reasoning models consume large
  output budgets for chain-of-thought. 4096 causes truncation.
- **Auth**: Read API key from project-relative `auth.json` first, then
  `~/.local/share/opencode/auth.json`, then `OPENROUTER_API_KEY` env var.
- **Retry on 502/503/504** — these are upstream provider overload, not
  permanent failures. Use exponential backoff.

#### Groq

- Requires `GROQ_API_KEY` in auth.json or env var.
- Base URL: `https://api.groq.com/openai/v1/chat/completions`
- Limited model selection but reliable uptime.
- Known to return HTTP 403 from non-US IP addresses (geo-blocking).
  Set `--proxy` to a US-based proxy if needed.
- No free-tier rate limits in practice.

#### Cerebras

- Requires `CEREBRAS_API_KEY` in auth.json or env var.
- Base URL: `https://api.cerebras.ai/v1/chat/completions`
- Smallest model selection of the three providers.
- Also geo-blocked to US from some regions.
- Best for low-latency inference on smaller models.

### Multi-Provider Routing

All providers share the same OpenAI-compatible chat completions format.
Route by model ID prefix in `call_llm()`:

```python
def call_llm(model_id: str, prompt: str, **kwargs):
    provider, _, model_name = model_id.partition(":")
    if provider == "openrouter":
        base_url = "https://openrouter.ai/api/v1"
        api_key = _get_auth_key("openrouter")
    elif provider == "groq":
        base_url = "https://api.groq.com/openai/v1"
        api_key = _get_auth_key("groq")
    elif provider == "cerebras":
        base_url = "https://api.cerebras.ai/v1"
        api_key = _get_auth_key("cerebras")
    else:
        raise ValueError(f"unknown provider: {provider}")
    return _call_openai_compatible(base_url, api_key, model_name, prompt, **kwargs)
```

This keeps the model chain flat and provider-agnostic.

### Output Parser Robustness

Models produce wildly inconsistent JSON. The parser must handle:

1. **JSON arrays** at top level: `[{...}, {...}]` (valid JSON, unwrap)
2. **Wrapper objects**: `{"finding": {...}}` (unwrap the inner object)
3. **Free-text contamination**: text before/after the JSON (strip)
4. **Sentinel objects**: trailing `{"done": true}` or `{"coverage_gap": ...}`
   — match by field presence, not position
5. **Multiple JSON objects** on one line: split by `}\n{`
6. **Truncated output** from `max_tokens`: detect missing closing `]` or `}`
7. **Line-by-line JSONL** fallback: try parsing each line independently

```python
def parse_findings(text: str) -> tuple[list[dict], list[dict]]:
    findings = []
    gaps = []
    try:
        data = json.loads(text)
        if isinstance(data, list):
            findings = [f for f in data if "snippet_id" in f]
            gaps = [g for g in data if "coverage_gap" in g]
            return findings, gaps
    except json.JSONDecodeError:
        pass
    for line in text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "coverage_gap" in obj:
            gaps.append(obj)
        elif "snippet_id" in obj:
            findings.append(obj)
    return findings, gaps
```

Every finding must include `status: "raw"` and `poc_confirmed: false` as
defaults — the Validate stage updates these. If the model omits them, the
parser should inject them.

### Per-Domain System Prompts

Domain guidance should be injected as a `guidance` field in the context pack:

| Domain | Focus |
|---|---|
| `mem-safety` | Buffer overflow, OOB R/W, UAF, integer wrap → allocation |
| `auth` | Bypass, privilege escalation, session fixation |
| `crypto` | Weak primitives, IV reuse, padding oracle, key management |
| `ipc` | TOCTOU, injection via pipes/sockets/shared-memory |
| `data-flow` | Untrusted data reaching dangerous sinks |
| `format-str` | Format string exploits with non-literal format arg |

### Parallelism and Debugging

- Use `ThreadPoolExecutor` with 3-4 workers (default: 3). Higher concurrency
  increases rate-limit risk on free-tier API providers.
- Implement `--max-run N` flag: process only the first N packs. Invaluable
  for debugging a single domain.
- Implement `--model MODEL` + `--validate-model MODEL` as separate flags.
- Progress bar via `\r` updates to stderr.
- Print all status/log to **stderr**, findings JSONL to **stdout**.

### Narrow Scope Principle

Each hunter agent must adhere to strict scoping:
- **One attack class per task**: Focus exclusively on the assigned attack class
- **Concrete target files**: Every finding must reference specific, verified files
- **Precise scope hint**: Must name the trust boundary above the sink
- **No generic catch-alls**: Use specific attack class names from the approved list
- **Logic chains exception**: Only multi-component chains may span multiple primitives, and only one chain per task

### Severity Assignment Guidelines

- **Critical**: Unauthenticated RCE, full auth bypass, arbitrary file read of secrets, fully-controlled SSRF reaching cloud-metadata/internal services
- **High**: Authenticated RCE, SQLi or path-traversal on reachable route, IDOR with sensitive data, auth-protected file overwrite
- **Medium**: Information disclosure of non-secrets, availability-degrading DoS, hardening flaws with real-but-narrow attack path
- **Low**: Defense-in-depth weaknesses not worth exploiting unless chained
- **Informational**: Notable patterns/code smells with no exploit path

### Prompt Design Patterns

| Pattern | Example |
|---|---|
| Narrow scope | `"Look for UAF in alloc_buffer() only"` |
| Trust boundaries | `"Attacker input enters at X, trust boundary at Y"` |
| Prior coverage | `"Area Z was audited in run N, skip it"` |
| Adversarial framing | `"Your job is to disprove this finding, not find new ones"` |
| Separate questions | Agent A: exploitable? Agent B: reachable from outside? |
| Historical context | `"Similar pattern was patched in commit ABC123; check unpatched siblings"` |
| Live target bias | `"Prefer techniques verifiable against http://target:8080"` |

### Validation Requirements

- All finding file paths must be repo-relative and verified to exist
- Zero findings with honest `gaps_observed` is valid output
- Never invent findings to fill queue; be conservative with severity
- Attempt PoC confirmation: if live_target provided, reproduce against service; otherwise compile/run locally
- If PoC fails, lower severity by at least one step or drop finding

---

## Stage 5 — Validate + Gapfill (inner loop)

### Validate (Adversarial Re-read)

The Validate stage employs an independent agent with different prompt and
model to attempt to *disprove* each finding:

- **Different model requirement**: Use a different LLM model than the Hunt
  stage to reduce correlated biases.
- **Role separation critical**: Validate agent has **no ability to generate
  new findings** — only assess existing ones.
- **Deliberate disagreement**: Two agents in disagreement >> one agent
  self-reviewing for accuracy.
- **Output format**: Add `status` field (`confirmed` / `rejected` /
  `needs-more-info`) and `validate_reason` to each finding.
- **Adversarial framing**: "Your job is to DISPROVE findings, not find new ones"
- **Include actual source code in the prompt**: Models cannot verify findings
  from descriptions alone. Look up the code snippet by `snippet_id` from the
  snippet DB and include it verbatim in the validate prompt. Add a fourth
  criterion: "Is the model's claim consistent with what the code actually does?"
  Without this, the validate model hallucinates confirmation of false positives
  (e.g., confirming "MOD63 should be MOD65521" when MOD63 is mathematically
  correct). With code context, the same model correctly rejects the finding.

### Output persistence

Validated findings must be written to `output/validated.jsonl` alongside the
main `findings.jsonl`. This enables `--validate-only` / `--resume` mode to
replay validation without re-running the Hunt stage:

```python
with open(VALIDATED_FILE, 'w') as f:
    for v in validated:
        f.write(json.dumps(v) + '\n')
```

### Validate Implementation Pattern

Use the same sync urllib pattern as the Hunter, but with a **system message**
(required — some models return empty responses without one) and a **model
fallback chain**:

```python
import urllib.request, json, ssl

VALIDATE_TOP_MODELS = [
    "openrouter:nvidia/nemotron-nano-12b-v2-vl:free",
    "openrouter:deepseek/deepseek-v4-flash:free",
    "openrouter:nvidia/nemotron-3-super-120b-a12b:free",
    "openrouter:arcee-ai/trinity-large-thinking:free",
    "openrouter:nvidia/nemotron-3-nano-30b-a3b:free",
]

def validate_finding(finding: dict, model_chain: list[str]) -> dict:
    snippet = snippet_db.get(finding.get("snippet_id", ""))
    snippet_code = snippet.get("content", "source not found") if snippet else "source not found"

    prompt = f"""Your job is to DISPROVE this vulnerability finding, not confirm it. Be adversarial.

Finding:
- snippet_id: {finding.get('snippet_id', '?')}
- class: {finding.get('class', '?')}
- description: {finding.get('desc', '')}
- call_path: {finding.get('call_path', [])}

Source code of the function under review:
```c
{snippet_code}
```

Output ONLY a JSON object: {{"status": "confirmed"/"rejected"/"needs-more-info", "reason": "<explanation>"}}
"""
    candidates = [m for m in VALIDATE_TOP_MODELS if m in model_chain]
    candidates += [m for m in model_chain if m not in candidates]

    for model in candidates:
        try:
            result = call_llm(model, prompt, system="You are an adversarial code reviewer. "
                              "Disprove findings. Output ONLY a JSON object with "
                              "'status' and 'reason'.", max_tokens=8192)
            text = result.choices[0].message.content or ""
            # Handle truncated JSON from reasoning models
            parsed = json.loads(_repair_truncated_json(text))
            status = parsed.get("status", "needs-more-info")
            reason = parsed.get("reason", "")
            return {**finding, "validate_status": status, "validate_reason": reason}
        except Exception as e:
            if any(x in str(e) for x in ("429", "502", "503", "504")):
                continue
            raise
    return {**finding, "validate_status": "needs-more-info", "validate_reason": "model chain exhausted"}
```

- Use `--validate-model` flag separate from `--model`
- Always include a system message
- Use a curated model chain (not raw context-length sort)
- Merge validation status back into the original finding
- Print progress to stderr; emit validated JSONL to stdout
- Cache validate responses the same way as hunt

### Gapfill (Coverage-Driven Re-queueing)

Hunters' `coverage_gap` records are re-queued as new scoped Hunt tasks.
Loop: Hunt → Validate → Gapfill → Hunt until queue drains (max 2 iterations):

```python
for gapfill_iter in range(2):
    current_gaps = [g for g in gaps if not g.get('gapfill_retried')]
    if not current_gaps:
        break
    fresh_findings, fresh_gaps = run_all_hunters(packs, hunt_models, parallel=3)
    findings.extend(fresh_findings)
    gaps = [{'gapfill_retried': True, **g} for g in current_gaps]
    gaps.extend(fresh_gaps)
    persist_findings_and_gaps(findings, gaps)
```

- **Coverage gaps** should specify: `{"coverage_gap":"<reason>","reason":"<detailed explanation>"}`
- Valid gap reasons: file size/complexity, lack of necessary context, time constraints
- Invalid gap reasons: laziness, disagreement with findings, desire to skip work
- Mark retried gaps with `gapfill_retried: true` to avoid infinite loops

---

## Stage 6 — Dedupe

Collapse findings sharing the same root cause to a single record. Dedupe on
root cause, not symptom.

### Root Cause Deduplication

- **Root cause focus**: Collapse findings sharing the same root cause to a single record
- **Not symptom-based**: The same UAF reported from 3 call paths is one bug, not three
- **Normalized key**: Embed `snippet_id` and `class` in a normalised key for comparison
- **Cluster identification**: Group findings with identical keys before surfacing to Report stage
- **Audit-specific enhancement**: Consider call stack similarity and taint propagation patterns

### Deduplication Criteria

Findings are considered duplicates when they share:
1. Same vulnerability class (e.g., `buffer-overflow`)
2. Same vulnerable function/snippet (same `snippet_id`)
3. Similar root cause context (equivalent taint propagation paths)
4. Same trust boundary crossing pattern

### Composite Key Implementation

In practice, dedup on `(snippet_id, class)` works well — it collapses
reports of the same bug class in the same function from different hunters:

```python
def deduplicate(findings: list[dict]) -> list[dict]:
    seen = {}
    for f in findings:
        key = (f["snippet_id"], f["class"])
        if key not in seen or severity_rank(f["severity"]) > severity_rank(seen[key]["severity"]):
            seen[key] = f
    return list(seen.values())
```

Keep the highest-severity variant when collapsing duplicates.

For deeper dedup, extend the key to `(file, class, source_lines_start)` to
catch cases where different snippet continuations report the same issue.

---

## Stage 6b — Shield (Call Graph + Hallucination + Reachability)

**Goal:** apply three quality gates before findings reach the chainer:
call-path verification, hallucination detection, and static reachability
filtering.

### Call-graph construction

Build a directed graph from snippet callee lists:

```python
def build_call_graph(snippets: list[dict]) -> dict[str, set[str]]:
    graph = {}
    for s in snippets:
        name = str(s.get('name') or s.get('id') or '').lower()
        callees = [c.lower() for c in (s.get('callees') or [])]
        if name:
            graph.setdefault(name, set()).update(callees)
    return graph
```

Keys are lowercase function names. This is the graph used by both the
chainer and the shield.

### Call-path verification

Check whether a finding's `call_path` matches actual edges in the graph:

```python
def verify_call_path(finding, graph) -> tuple[bool, str]:
    path = [n.lower() for n in (finding.get('call_path') or [])]
    if not path:
        return False, 'empty-call-path'
    for i in range(len(path) - 1):
        caller, callee = path[i], path[i + 1]
        if caller not in graph or callee not in graph.get(caller, set()):
            return False, f'unverified: {caller}->{callee}'
    return True, 'verified'
```

### Hallucination detection

Check that the finding's description references actual identifiers from the
snippet content. Use function-name presence + identifier overlap with a
60% threshold on description tokens and 70% on call-path names:

```python
def detect_hallucination(finding, snippet) -> tuple[bool, str]:
    content_tokens = set(re.findall(r'\b[a-z_][a-z_0-9]{3,}\b', snippet_content))
    desc_tokens = {t for t in _tokenise(desc) if len(t) > 5}
    missing = desc_tokens - content_tokens
    if desc_tokens and len(missing) / len(desc_tokens) > 0.60:
        return True, f'desc tokens missing: {sorted(missing)[:5]}'
    # Same for call_path names with 0.70 threshold
    ...
```

### Static reachability filter (filter_unreachable)

BFS from `entry_points` (e.g., `["main", "sshd_main", "ssh_main"]`) through
the call graph to determine which findings are statically reachable.

**Critical: `snippet_db` parameter.** Findings reference snippet IDs, not
function names. `filter_unreachable()` must resolve `snippet_id → function
name` before doing BFS, or all findings will appear unreachable:

```python
def filter_unreachable(findings, graph, entry_points, snippet_db=None):
    for f in findings:
        sid = f.get('snippet_id', '')
        targets = set()
        if sid and snippet_db:
            sname = snippet_db.get(sid, {}).get('name', sid)
            targets.add(sname.lower())
        # BFS from entry_points to see if any target is reachable...
```

Without `snippet_db`, the function looks for `sha256:...` keys in the
call graph, finds nothing, and marks everything unreachable.

---

## Stage 7 — Chainer

**Goal:** detect clusters where multiple low/medium findings compose into a
higher-severity exploit chain.

### Critical: graph key resolution

The call graph is keyed on **lowercase function names**, but findings reference
**snippet IDs** (e.g., `sha256:aee28b:65e614`). The chainer MUST resolve before
BFS traversal:

```python
def build_chains(findings, snippet_db, call_graph, max_hops=4):
    node_pairs = []
    for f in findings:
        sid = f.get('snippet_id', '')
        snippet = snippet_db.get(sid, {})
        node_name = str(snippet.get('name', sid)).lower()
        node_pairs.append((node_name, sid, f))
    # Now BFS using node_name against call_graph keys...
```

Without this resolution, the BFS searches for `sha256:...` keys that don't
exist in the graph, producing **zero chains** even when the call graph is valid.
This is the single most common chainer bug.

### Call-graph Algorithm

1. Build call graph from `callees` in the snippet DB.
2. Resolve snippet IDs → function names for all finding pairs.
3. For each pair `(A, B)` where A is reachable from B in ≤ 4 hops (via BFS),
   emit a candidate chain.
3. Score candidates:
   - +2 if chain crosses a trust boundary (`external-input` → sink)
   - +1 per MEDIUM / +2 per HIGH / +3 per CRITICAL finding in chain
   - +1 if chain involves recently modified files (per `git log --oneline -20`)
   - -1 if chain involves well-tested or hardened areas
4. Submit top-N chains to a **chain reasoning agent** for detailed analysis.

### Logic Chain Definition

- **Normal case**: One attack class per task (one primitive vulnerability)
- **Exception**: Logic chains (multi-component attack sequences) are allowed as ONE task
- **Chain format**: `attack_class: logic_chain` with `scope_hint` naming the specific chain
- **Target files**: May span 2-3 files for a single logic chain task
- **Limitation**: Only one chain per task

### PoC Confirmation Loop (Isolation Requirements)

A finding with a PoC is actionable. A finding without one is speculation.

- **Isolation**: Run PoCs in isolated scratch environment with no production access
- **Live target preference**: When `--target-url` provided, reproduce against live service
- **Local fallback**: Otherwise compile/run in `$scratch_dir` using available interpreters/compilers
- **Validation**: If bug doesn't reproduce against live target, drop finding
- **Evidence capture**: Log raw request/response into `poc.code`/`poc.run_output`
- **Severity adjustment**: If PoC fails, lower severity by at least one step or drop finding
- **No external calls**: Bash usage limited to `$scratch_dir`; no network calls to external hosts (except live_target)

See `implementation.md` → **PoC loop** for the confirmation pseudocode.

---

## Stage 8 — PoC Confirmation (Compile + Run)

**Goal:** disprove or confirm each finding by compiling and running a targeted
C program under AddressSanitizer. This is the strongest evidence level — a
compiler+ASan verdict beats any LLM opinion.

### Why it matters

AI hunters produce ~60-80% false positive rates on audited codebases. Validate
catches some via adversarial prompting, but the gold standard is a concrete
execution: if the alleged buffer overflow does not crash under ASan, it does
not exist as described.

### Workflow

1. **Generate** — for each finding, auto-generate a C source file with test
   cases targeting the specific class and code path:
   - `buffer-overflow` → allocation + memcpy tests at edge sizes
   - `format-string` → caller-controlled format arg test
   - `uninitialized` → zero-length read edge case
   - `recursion` → stack depth stress test
   - `integer-wrap` → unsigned underflow/overflow tests
2. **Compile** — build with `gcc -fsanitize=address -g -O0`
3. **Run** — execute under ASan, capture exit code and stderr
4. **Compare** — expected (crash + ASan errors) vs actual (exit 0, no errors)
5. **Verdict** — `confirmed` if ASan errors, `rejected` if clean exit 0,
   `needs-more-info` if build failed or unexpected crash

### Output

Each PoC produces two files in `output/pocs/`:

```
poc-<snippet_id>-<class>.json   # Schema-valid PoC JSON
poc-<snippet_id>-<class>.c      # Compilable C source
```

The JSON is self-documenting: finding ref, harness config, test cases with
both `expected` and `actual` fields, and a final `verdict`.

### CLI integration

```
--poc <finding_id|all>    # Generate + compile + run during pipeline
--poc-only                 # Skip all API stages, just PoC cached findings
```

### Schema

See `schemas/poc-schema.json` for the canonical format. Every PoC JSON is
validated against this schema before use.

### Auto-detection of target context

The generator inspects the snippet content for library signatures:
- `z_streamp`, `inflate`, `zlib.h` → links `-lz`, generates inflate tests
- `SSL_CTX`, `SSL_new` → links `-lssl -lcrypto`
- No library signature → standalone C with `calloc`/`memset` bounds test

---

## Stage 9 — Trace

For confirmed findings in **shared libraries**: fan out one tracer agent per
consumer repository to determine reachability from each consumer's external
attack surface.

### Trace Agent Mission

- **Reachability proof**: Determine if attacker-controlled input can reach the vulnerable sink
- **Call path validation**: If reachable, provide the exact call path from entry point to sink
- **Consumer-specific analysis**: Analyze each consumer repo independently
- **Prioritization**: Unreachable findings → deprioritize; Reachable findings → escalate to Feedback stage

### Trace Agent Inputs

Tracer agent receives:
- The confirmed finding (with PoC and call path from original hunt)
- The consumer repository's snippet database
- A `SECURITY_CONTEXT.md` for the consumer
- Optional: live target URL and credentials for reproduction validation

### Trace Agent Output

Output: `reachable: true/false` with supporting evidence:
- If `reachable: true`: Include call path from consumer's external attack surface to the vulnerable sink
- If `reachable: false`: Provide reasoning why the path is blocked
- When possible, validate reachability against live target using provided credentials

### Safety Constraints

- Network egress restricted to live target host + `127.0.0.1` when `--target-url` is set
- No calls to external hosts beyond the specified target
- Findings that don't reproduce against live target are dropped or rejected
- Credentials flow into relevant stages as needed for live validation

---

## Stage 10 — Feedback

Reachable traces become new Hunt tasks in consumer repos, closing the cross-repo
propagation loop.

### Feedback Mechanism

- **Trace-to-task conversion**: Each reachable trace from the Trace stage generates new Hunt tasks in consumer repositories
- **Structural identity**: Feedback tasks are structurally identical to Stage 4 hunter tasks (same format, validation rules)
- **Known entry pre-loading**: The originating finding is pre-loaded in the context pack as a `known_entry` rather than discovered during hunting
- **Cross-repo propagation**: This closes the loop for vulnerability discovery across related codebases

### Feedback Task Composition

Each feedback task includes:
- `task_id`: `t_<subsystem>_<attack_class>_<n>`
- `attack_class`: Specific vulnerability class to hunt
- `scope_hint`: Trust boundary description from the validated trace
- `target_files`: Verified files from consumer repo where the vulnerability may exist
- `known_entry`: The validated trace finding that seeded this hunt
- `evidence_basis`: Reference to the original trace that proved reachability

### Propagation Rules

- **Reachability required**: Only traces proven reachable (`reachable: true`) generate feedback tasks
- **No fabrication**: Findings that don't reproduce against live targets are not propagated
- **Credential propagation**: When live targets are used, credentials flow into feedback tasks
- **Scope inheritance**: Feedback tasks inherit scope notes and exclusions from the original investigation

---

## Stage 11 — Report

See `schemas.md` → **Report schema** for the full output spec.

### Structured bucket rationale

Every finding in the report must include a `bucket_rationale` field that
explains why it landed in its triage bucket. This makes triage decisions
transparent and auditable. Examples:

```
bucket_rationale: "Severity CRITICAL + status confirmed. Confirmed reachable
buffer-overflow requiring immediate remediation."
bucket_rationale: "Rejected by Validate: code checks buffer capacity before
writing — the alleged overflow is impossible."
bucket_rationale: "Non-cryptographic checksum by design (Adler32/CRC32).
Not exploitable as a library bug; relevant only if consumer uses it for crypto."
bucket_rationale: "Informational finding about mem-safety. Non-exploitable in
current form, documents design property of the library."
```

The report root should also include a `bucket_definitions` dictionary that
documents the criteria for each bucket. This pairs with `bucket_rationale` to
make the report self-documenting.

### Gap persistence

Gaps emitted by Hunt agents are persisted to `output/gaps.jsonl` alongside
`output/findings.jsonl`. This enables `--validate-only` to replay gaps into
the final report without re-running the Hunt stage.

### Triage buckets

| Bucket | Criteria |
|---|---|
| **Fix now** | CRITICAL individual; feasible chain score ≥ 5; HIGH + `external-input` reachable |
| **Backlog** | HIGH without external-input path; MEDIUM isolated; INFORMATIONAL design notes |
| **False positive** | No plausible call path; theoretical-only; sandbox/test-only code |

### Validate-only mode

`--validate-only` skips the Hunt stage entirely and loads cached findings
from `output/findings.jsonl` (with gaps from `output/gaps.jsonl`). This is
useful for:
- Re-running Validate with a different model pool after a failed run
- Adjusting the validate prompt and re-validating existing findings
- Iterating on the report generation logic without burning API calls

The flag is implemented in `run_agents.py` and routes directly to the
Validate → Dedupe → Report pipeline:

```
if validate_only:
    findings = load_cached_findings("output/findings.jsonl")
    gaps = load_cached_gaps("output/gaps.jsonl")
else:
    findings, gaps = run_hunt(packs, hunt_models)
    persist_cached(findings, gaps)
# Validate... Dedupe... Report...
```

The reporting agent validates its output against the schema and fixes errors
before emitting. Every `fix_now` finding must have a confirmed call path from
a known entry point (main, exported symbol, HTTP handler).
