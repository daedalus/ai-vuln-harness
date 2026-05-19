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
- Hard cap: **800 tokens per snippet** (leaves ~200k budget for 250 snippets
  per agent pack). Use any `cl100k`-compatible tokenizer.
- Large functions: split at logical boundaries, emit `continuation: true` on
  subsequent pieces so the chainer can reconstruct.
- Cross-file context: embed 3-line caller/callee stubs inline — agents need
  the call signature without fetching another snippet.

### Snippet IDs

Use short sha256 IDs for readability: `sha256:{h[:6]}:{h[-6:]}` (e.g.
`sha256:e812b9:ab0d84`). Full sha256 is unnecessarily verbose in logs and
finding references.

### Tree-sitter API Notes (v0.25+)

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

### Agent domains

| Agent | Tags selected | Focus |
|---|---|---|
| `mem-safety` | `memory`, `integer-arith`, `unsafe` | Buffer overflow, OOB R/W, UAF, integer wrap |
| `auth` | `auth`, `external-input` | Bypass, privilege escalation, session fixation |
| `crypto` | `crypto` | Weak primitives, IV reuse, padding oracle, key mgmt |
| `ipc` | `ipc`, `external-input` | TOCTOU, injection via pipes/sockets |
| `data-flow` | all `external-input` | Untrusted data reaching sinks |
| `format-str` | `format-string` | Format string exploits |

Embed a `SECURITY_CONTEXT.md` per repo in every pack: entry points, trust
boundaries, known-unsafe modules, memory allocator in use, sanitizer flags.

### Scope Notes Integration

Incorporate scope notes to exclude specific components or attack classes:
- Accept verbatim scope notes from operator (e.g., "Mailpit (port 1025) is test-only; ignore.")
- Append scope notes verbatim to every stage's user_input
- Have agents honor exclusions listed in scope notes during processing
- This prevents wasting resources on intentionally-loose-by-design surfaces

### Budget enforcement

Each pack must fit within **180k tokens** (leaving 20k for output). If a domain
exceeds budget, split into sub-packs by directory prefix and run multiple
instances in parallel.

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

Implement via `MODEL_BY_DOMAIN` dict:

```python
MODEL_BY_DOMAIN = {
    "mem-safety":  "deepseek/deepseek-v4-flash:free",
    "data-flow":   "deepseek/deepseek-v4-flash:free",
    "crypto":      "deepseek/deepseek-v4-flash:free",
    "format-str":  "deepseek/deepseek-v4-flash:free",
    "ipc":         "deepseek/deepseek-v4-flash:free",
    "auth":        "deepseek/deepseek-v4-flash:free",
}
```

Fall back to a shared default model for domains not in the dict.

### Model Fallback Chain (Important: Free-Tier Reality)

OpenRouter free-tier models are **frequently rate-limited (HTTP 429)**.
A single model per domain is not enough. You must implement a fallback
chain: try models in order of context length (descending), skipping
to the next on 429 or API error.

Implementation pattern:
1. Fetch all free models from `GET /v1/models` at startup.
2. Filter to `:free` suffix, sort by `context_length` descending.
3. Start at the preferred model index; on 429, advance to next model.
4. 2 attempts per model before advancing (handles transient errors).

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
    return [m["id"] for m in free]
```

Loops through models with `start_idx = model_chain.index(preferred)`.
On HTTP 429, logs the skip and tries `model_chain[start_idx + 1]`.

**Key observation:** Out of 24 free models on OpenRouter, only ~6 are
reliably available at any moment. The rest return 429 or empty responses.
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

### OpenRouter-Specific Notes

When using OpenRouter (`https://openrouter.ai/api/v1`) as the API provider:

- **`openrouter/openrouter/free` is NOT a valid model ID.** Use concrete
  model IDs like `deepseek/deepseek-v4-flash:free`. Fetch the full list
  from `GET /v1/models` and filter by `:free` suffix.
- **Model fallback chain is mandatory.** Free tier returns HTTP 429 on most
  models most of the time. Without the fallback, the pipeline stalls.
- **Reasoning models** put output in `message.reasoning`, not `message.content`:
  ```python
  content = msg.get("content", "") or ""
  reasoning = msg.get("reasoning", "") or ""
  full_output = reasoning + " " + content
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
- **Auth**: Read API key from `~/.local/share/opencode/auth.json` (key:
  `openrouter`) or `OPENROUTER_API_KEY` env var.

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

### Validate Implementation Pattern

Use the same sync urllib pattern as the Hunter, but with a **system message**
(required — some models return empty responses without one) and a **model
fallback chain**:

```python
import urllib.request, json, ssl

VALIDATE_TOP_MODELS = [
    "nvidia/nemotron-nano-12b-v2-vl:free",
    "deepseek/deepseek-v4-flash:free",
    "nvidia/nemotron-3-super-120b-a12b:free",
    "arcee-ai/trinity-large-thinking:free",
    "nvidia/nemotron-3-nano-30b-a3b:free",
]

def validate_finding(finding: dict, api_key: str, model_chain: list[str]) -> dict:
    prompt = f"""Your job is to DISPROVE this vulnerability finding, not confirm it. Be adversarial.

Finding:
- snippet_id: {finding.get('snippet_id', '?')}
- class: {finding.get('class', '?')}
- description: {finding.get('desc', '')}
- call_path: {finding.get('call_path', [])}

Output ONLY a JSON object: {{"status": "confirmed"/"rejected"/"needs-more-info", "reason": "<explanation>"}}
"""
    candidates = [m for m in VALIDATE_TOP_MODELS if m in model_chain]
    candidates += [m for m in model_chain if m not in candidates]

    for model in candidates:
        try:
            payload = {
                "model": model,
                "max_tokens": 2048,
                "messages": [
                    {"role": "system", "content": "You are an adversarial code reviewer. "
                     "Disprove findings. Output ONLY a JSON object with 'status' and 'reason'."},
                    {"role": "user", "content": prompt},
                ],
            }
            result = json.loads(resp.read().decode())
            status = result.get("status", "needs-more-info")
            reason = result.get("reason", "")
            return {**finding, "validate_status": status, "validate_reason": reason}
        except urllib.error.HTTPError as e:
            if e.code == 429:
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

- Hunters' `coverage_gap` records are re-queued as new scoped Hunt tasks
- Loop: Hunt → Validate → Gapfill → Hunt until queue drains
- **Coverage gaps** should specify: `{"coverage_gap":"<reason>","reason":"<detailed explanation>"}`
- Valid gap reasons: file size/complexity, lack of necessary context, time constraints
- Invalid gap reasons: laziness, disagreement with findings, desire to skip work

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

## Stage 7 — Chainer

**Goal:** detect clusters where multiple low/medium findings compose into a
higher-severity exploit chain.

### Call-graph Algorithm

1. Build call graph from `callers`/`callees` in the snippet DB.
2. For each pair `(A, B)` where `A.snippet_id` is reachable from `B.snippet_id`
   in ≤ 4 hops, emit a candidate chain.
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

## Stage 8 — Trace

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

## Stage 9 — Feedback

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

## Stage 10 — Report

See `schemas.md` → **Report schema** for the full output spec.

### Triage buckets

| Bucket | Criteria |
|---|---|
| **Fix now** | CRITICAL individual; feasible chain score ≥ 5; HIGH + `external-input` reachable |
| **Backlog** | HIGH without external-input path; MEDIUM isolated |
| **False positive** | No plausible call path; theoretical-only; sandbox/test-only code |

The reporting agent validates its output against the schema and fixes errors
before emitting. Every `fix_now` finding must have a confirmed call path from
a known entry point (main, exported symbol, HTTP handler).
