---
name: ai-vuln-harness
description: >
  Design and implement multi-agent vulnerability research harnesses following
  the Project Glasswing / Cloudflare methodology. Use this skill whenever the
  user wants to: build an AI-assisted code auditing pipeline, design a
  multi-agent security research workflow, set up adversarial validation between
  agents, structure exploit chain construction with LLMs, reduce false-positive
  noise from AI vulnerability scanners, or architect a harness around a
  security-focused model (e.g. Mythos, GPT-5.5, Opus). Also trigger when the
  user asks how to get better coverage from an LLM on a large codebase, wants
  to chain subagents for security research, mentions "hunt/validate/dedupe"
  workflows, PoC generation loops, signal-to-noise problems in AI security
  findings, or wants to implement snippet-based context distribution to agent
  clusters. Trigger even if the user just says "vuln harness", "security agent
  pipeline", "audit harness", "scan this repo for vulns", "chain low-severity
  bugs", "audit this codebase with AI", "SAST with LLMs", "LLM-assisted
  pentesting", "reduce LLM scanner noise", "AI security findings are too noisy",
  or "how do I use Claude for security research at scale". Prefer this skill
  over generic coding assistance whenever the goal is systematic vulnerability
  discovery, exploit chaining, or structured security output from an AI agent.
---

# AI Vulnerability Research Harness

Design and implementation guide for multi-agent, pipeline-style vulnerability
research — based on the Project Glasswing methodology published by Cloudflare
(2026-05-18) and refined through the audit harness implementation.

**Reference files** (load as needed):
- `references/schemas.md` — All JSONL/JSON schemas: snippet, context pack,
  finding, chain, report. Load when specifying data formats or validating output.
- `references/implementation.md` — Full code sketches for ingestor, coordinator,
  runner, chainer, and PoC loop. Load when writing or reviewing code.

---

## Core Insight: Harness > Chat

A generic coding agent pointed at an arbitrary repo **does not work** for
security research at scale. Two hard limits:

| Limit | Why it matters |
|---|---|
| **Context** | Agents are shaped for single-hypothesis work. Vuln research is narrow and parallel. A 100k-line repo fills the context window after covering ~0.1% of surface. |
| **Throughput** | Single-stream execution serializes what should be many simultaneous hypotheses against many components. |

The solution is a harness that manages execution: pre-sliced structured context,
scoped parallel hunters, adversarial validators, deduplication, and cross-repo
tracing — following the audit harness implementation's 8-stage pipeline.

Key insights from the audit implementation:
- **Narrow scope**: One attack class per agent prevents context overload
- **Adversarial validation**: Separate agent attempts to disprove findings
- **Reachability gating**: Findings must be proven reachable from attacker input
- **Feedback loop**: Validated findings seed new hunts in related codebases

---

## Full Pipeline

Following the audit harness implementation, the pipeline consists of 8 stages:

```
┌──────────────┐
│  1.Recon     │  Map repo → emit narrow Hunt tasks (one attack class per task)
└──────┬───────┘
       │ task queue
┌──────▼───────┐
│  2.Hunt      │  One attack class per agent; compile/run PoCs
└──────┬───────┘
       │ raw findings (JSONL)
┌──────▼───────┐        ┌──────────┐
│  3.Validate  │◄──────►│ 4.Gapfill│  (inner loop)
└──────┬───────┘        └──────────┘
       │ confirmed findings
┌──────▼───────┐
│  5.Dedupe    │  Cluster by root cause
└──────┬───────┘
       │ deduped findings
┌──────▼───────┐
│  6.Trace     │  Prove attacker input reaches sink
└──────┬───────┘
       │ reachable findings
┌──────▼───────┐
│ 7.Feedback   │  Turn traces into new Hunt tasks
└──────┬───────┘
       │ new task queue
┌──────▼───────┐
│   8.Report   │  Schema-validated structured output
└──────────────┘
```

Each stage corresponds to a markdown prompt in `prompts/` + JSON Schema in `schemas/`.
The orchestrator validates every stage's output against its schema on first try.

---

## Stage 1 — Ingestor

**Goal:** convert a repo into a flat, typed snippet database that fits agents
into budget-bounded context windows, enriched with historical context.

See `references/schemas.md` → **Snippet schema** for the full field spec.
See `references/implementation.md` → **ingestor.py** for the code sketch.

### Chunking rules

- Unit: **function** for C/C++/Rust/Go; **method** for Python/Java/TS.
  Fall back to fixed 200-line windows for languages without reliable function
  boundaries.
- Hard cap: **800 tokens per snippet** (leaves ~200k budget for 250 snippets
  per agent pack). Use any `cl100k`-compatible tokenizer; the implementation
  sketch uses `tiktoken` but this is not a hard dependency.
- Large functions: split at logical boundaries, emit `continuation: true` on
  subsequent pieces so the chainer can reconstruct.
- Cross-file context: embed 3-line caller/callee stubs inline — agents need
  the call signature without fetching another snippet.

### Snippet IDs

Use short sha256 IDs for readability: `sha256:{h[:6]}:{h[-6:]}` (e.g.
`sha256:e812b9:ab0d84`). Full sha256 is unnecessarily verbose in logs and
finding references.

### Tree-sitter API Notes (v0.25+)

The tree-sitter Python binding changed in 0.25.x:

```python
from tree_sitter import Language, Parser

# Load compiled language
C_LANG = Language("build/my-languages.so", "c")

# Instantiate parser — 0.25.x uses property setter, not set_language()
parser = Parser()
parser.language = C_LANG  # NOT parser.set_language(C_LANG)

# Parse
tree = parser.parse(bytes(source, "utf8"))
```

If using pre-built wheels with the capsule API:

```python
# For 0.25.2+ with Language(capsule) constructor
from tree_sitter_c import language as c_lang
C_LANG = Language(c_lang())  # capsule, not path+name
```

Check your version: `import tree_sitter; print(tree_sitter.__version__)`.
The API between 0.22.x and 0.25.x is **not backwards compatible.

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

### Historical Context Mining (Recon Enhancement)

Following the audit harness approach, enhance the Ingestor stage by mining git history for past security patches:
- Search git log for security-related commits: `git log --grep='CVE\|security\|vuln\|sec:\|fix.*auth\|fix.*injection\|sanitize\|escape\|bypass' --oneline -50`
- For each relevant commit, identify the fixed pattern and grep the codebase for similar idioms
- Seed initial hunt tasks against unpatched copies of vulnerable patterns (sibling files)
- This adds zero cost on repositories without security history but catches cross-component bugs when present

---

## Stage 2 — Coordinator

**Goal:** build per-agent **context packs** — curated snippet subsets scoped to
one security domain — so each agent can be cold-started with no repo access.

See `references/schemas.md` → **Context pack schema** for the full field spec.

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

Following the audit harness approach, incorporate scope notes to exclude specific components or attack classes:
- Accept verbatim scope notes from operator (e.g., "Mailpit (port 1025) is test-only; ignore.")
- Append scope notes verbatim to every stage's user_input
- Have agents honor exclusions listed in scope notes during processing
- This prevents wasting resources on intentionally-loose-by-design surfaces

### Budget enforcement

Each pack must fit within **180k tokens** (leaving 20k for output). If a domain
exceeds budget, split into sub-packs by directory prefix and run multiple
instances in parallel.

### Pack size observations (zlib, ~23K LOC, 594 snippets)

| Domain | Tags | Pack size | Notes |
|---|---|---|---|
| `mem-safety` | memory, integer-arith, unsafe | ~150K tokens | Largest — most C functions touch memory |
| `ipc` | ipc, external-input | ~147K tokens | Many functions tagged external-input inflates it |
| `auth` | auth, external-input | ~128K tokens | Same inflation from external-input overlap |
| `data-flow` | external-input | ~128K tokens | Single tag, still large |
| `crypto` | crypto | ~65K tokens | Sparse in a compression library |
| `format-str` | format-string | ~15K tokens | Very few printf-family calls in zlib |

**Key takeaway:** `external-input` tag overlap inflates ipc/auth packs. In a
pure C library, mem-safety dominates. Some domains will produce honest coverage
gaps (auth, crypto, ipc) — this is normal for libraries with a narrow
functional scope. The gapfill stage should re-queue these with narrowed scope.

---

## Stage 3 — Hunter Cluster

Each agent receives its context pack and a domain-scoped system prompt following the audit harness principles:

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

Run agents in parallel. See `references/implementation.md` →
**run_agents.py** for the code sketch.

### Model Selection

Use your highest-capability model for `mem-safety`, `data-flow`, and
`crypto` — these require deep reasoning. A faster/cheaper model tier is
acceptable for `format-str` and `ipc`, which are more pattern-driven.

Implement via `MODEL_BY_DOMAIN` dict:

```python
MODEL_BY_DOMAIN = {
    "mem-safety":  "openrouter/nvidia-nemotron-nano-12b-v2-vl:free",
    "data-flow":   "openrouter/nvidia-nemotron-nano-12b-v2-vl:free",
    "crypto":      "openrouter/nvidia-nemotron-nano-12b-v2-vl:free",
    "format-str":  "openrouter/google-gemma-3-12b-it:free",
    "ipc":         "openrouter/google-gemma-3-12b-it:free",
    "auth":        "openrouter/google-gemma-3-12b-it:free",
}
```

Fall back to a shared default model for domains not in the dict.

### Sync > Async (Practical Lesson)

Use **sync urllib**, not async httpx. Key reasons from the zlib implementation:

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

- **`openrouter/free` is a routing alias** — it auto-routes to whatever
  free model is available. The actual model varies per call (nemotron,
  liquid, baidu, z-ai, gemma, etc.). This makes behavior non-deterministic.
- **Reasoning models** (e.g. `nvidia/llama-3.3-nemotron-super-49b-v1:free`)
  put their output in the `message.reasoning` field, **not** in
  `message.content`. Always concatenate both:
  ```python
  content = msg.get("content", "") or ""
  reasoning = msg.get("reasoning", "") or ""
  full_output = reasoning + " " + content
  ```
- **`fetch_model_limits()` must handle 404** — routing aliases like
  `openrouter/free` return 404 on `/v1/models/{alias}`. Fall back to
  scanning `/v1/models` for all free models and taking the minimum bounds.
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
    # Strategy 1: try JSON array parse
    try:
        data = json.loads(text)
        if isinstance(data, list):
            findings = [f for f in data if "snippet_id" in f]
            gaps = [g for g in data if "coverage_gap" in g]
            return findings, gaps
    except json.JSONDecodeError:
        pass
    # Strategy 2: line-by-line JSONL
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

Domain guidance should be injected as a `guidance` field in the context pack
(rather than a hardcoded system prompt) so it can vary per task:

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
- Implement `--model MODEL` + `--validate-model MODEL` as separate flags so
  Validate can use a different model/routing pool.
- Progress bar via `\r` updates to stderr: print pack name, model, progress,
  and finding count. Keeps the user informed without polluting JSONL output.
- Print all status/log to **stderr**, findings JSONL to **stdout**.
  This lets users pipe findings directly: `python run_agents.py > findings.jsonl`.

### Narrow Scope Principle (Core Audit Insight)

Following the audit harness implementation, each hunter agent must adhere to strict scoping:
- **One attack class per task**: Focus exclusively on the assigned attack class (e.g., `command_injection`, `sql_injection`)
- **Concrete target files**: Every finding must reference specific, verified files (validated via Read/Glob before emission)
- **Precise scope hint**: Must name the trust boundary above the sink (e.g., "HTTP POST /api/import reads `filename` from JSON body, passes to `zipfile.ZipFile.extractall()` in services/importer.py:42")
- **No generic catch-alls**: Use specific attack class names from the approved list
- **Logic chains exception**: Only multi-component chains (e.g., auth-bypass + IDOR + path traversal → RCE) may span multiple primitives, and only one chain per task

### Severity Assignment Guidelines

Assign severity conservatively based on real-world exploitability:
- **Critical**: Unauthenticated RCE, full auth bypass, arbitrary file read of secrets, fully-controlled SSRF reaching cloud-metadata/internal services
- **High**: Authenticated RCE, SQLi or path-traversal on reachable route, IDOR with sensitive data, auth-protected file overwrite
- **Medium**: Information disclosure of non-secrets, availability-degrading DoS, hardening flaws with real-but-narrow attack path
- **Low**: Defense-in-depth weaknesses not worth exploiting unless chained
- **Informational**: Notable patterns/code smells with no exploit path

### Prompt Design Patterns (Enhanced)

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

## Stage 4 — Validate + Gapfill (inner loop)

### Validate (Adversarial Re-read)

Following the audit harness implementation, the Validate stage employs an independent agent with different prompt and model to attempt to *disprove* each finding:

- **Different model requirement**: Use a different LLM model than the Hunt stage to reduce correlated biases. At minimum use a different routing pool (e.g., `openrouter/free` maps to different actual models per call, so Hunt and Validate naturally see different models).
- **Role separation critical**: Validate agent has **no ability to generate new findings** - only assess existing ones
- **Deliberate disagreement**: Two agents in disagreement >> one agent self-reviewing for accuracy
- **Output format**: Add `status` field (`confirmed` / `rejected` / `needs-more-info`) and `validate_reason` to each finding
- **Adversarial framing**: Explicitly instruct the validator: "Your job is to DISPROVE findings, not find new ones"

### Validate Implementation Pattern

Use the same sync urllib pattern as the Hunter:

```python
import urllib.request, json

def validate_finding(finding: dict, api_key: str, model: str) -> dict:
    prompt = f"""Your job is to DISPROVE this finding, not confirm it.

Finding: {json.dumps(finding)}

Be adversarial. Is there an alternative explanation? Is the call path
implausible? Is the precondition not actually attacker-controllable?
Can you construct a scenario where this is NOT exploitable?

Output: {{"status": "confirmed"/"rejected"/"needs-more-info", "reason": "..."}}
"""
    payload = {
        "model": model,
        "max_tokens": 1024,
        "messages": [
            {"role": "user", "content": prompt},
        ],
    }
    # ... urllib request same as Hunter ...
    return {**finding, "status": result["status"], "validate_reason": result["reason"]}
```

- Use `--validate-model` flag separate from `--model` so each stage can target
  a different routing pool
- Merge validation status back into the original finding (don't keep separate)
- Print progress to stderr; emit validated JSONL to stdout

### Gapfill (Coverage-Driven Re-queueing)

Following the audit harness implementation:

- Hunters' `coverage_gap` records (honest assessments of uninspectable areas) are re-queued as new scoped Hunt tasks
- Loop: Hunt → Validate → Gapfill → Hunt until queue drains
- **Coverage gaps** should specify: `{"coverage_gap":"<reason>","reason":"<detailed explanation>"}`
- Valid gap reasons: file size/complexity, lack of necessary context, time constraints
- Invalid gap reasons: laziness, disagreement with findings, desire to skip work

---

## Stage 5 — Chainer

**Goal:** detect clusters where multiple low/medium findings compose into a
higher-severity exploit chain, following the audit harness approach.

### Call-graph Algorithm (Enhanced)

Following the audit harness implementation:

1. Build call graph from `callers`/`callees` in the snippet DB.
2. For each pair `(A, B)` where `A.snippet_id` is reachable from `B.snippet_id`
   in ≤ 4 hops, emit a candidate chain.
3. Score candidates using audit's refined methodology:
    - +2 if chain crosses a trust boundary (`external-input` → sink)
    - +1 per MEDIUM / +2 per HIGH / +3 per CRITICAL finding in chain
    - +1 if chain involves recently modified files (per `git log --oneline -20`)
    - -1 if chain involves well-tested or hardened areas
4. Submit top-N chains to a **chain reasoning agent** for detailed analysis.

### Logic Chain Definition

Following audit's narrow-scoping principle with one exception:
- **Normal case**: One attack class per task (one primitive vulnerability)
- **Exception**: Logic chains (multi-component attack sequences) are allowed as ONE task
- **Chain format**: `attack_class: logic_chain` with `scope_hint` naming the specific chain
  (e.g., "X bypasses auth → Y reaches sink Z via Q")
- **Target files**: May span 2-3 files for a single logic chain task
- **Limitation**: Only one chain per task - this is the sole exception to "one attack class per task"

### PoC Confirmation Loop (Isolation Requirements)

A finding with a PoC is actionable. A finding without one is speculation.
Following audit's PoC loop requirements:

- **Isolation**: Run PoCs in isolated scratch environment with no production access
- **Live target preference**: When `--target-url` provided, reproduce against live service
- **Local fallback**: Otherwise compile/run in `$scratch_dir` using available interpreters/compilers
- **Validation**: If bug doesn't reproduce against live target, drop finding (treat as static miss)
- **Evidence capture**: Log raw request/response into `poc.code`/`poc.run_output`
- **Severity adjustment**: If PoC fails, lower severity by at least one step or drop finding
- **No external calls**: Bash usage limited to `$scratch_dir`; no network calls to external hosts (except live_target)

See `references/implementation.md` → **PoC loop** for the confirmation
pseudocode and isolation requirements.

---

## Stage 6 — Dedupe

Collapse findings sharing the same root cause to a single record. Dedupe on
root cause, not symptom — following the audit harness implementation.

### Root Cause Deduplication (Audit Approach)

Following the audit harness implementation:
- **Root cause focus**: Collapse findings sharing the same root cause to a single record
- **Not symptom-based**: The same UAF reported from 3 call paths is one bug, not three
- **Normalized key**: Embed `snippet_id` and `class` in a normalised key for comparison
- **Cluster identification**: Group findings with identical keys before surfacing to Report stage
- **Audit-specific enhancement**: Consider call stack similarity and taint propagation patterns when determining root cause equivalence

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

Keep the highest-severity variant when collapsing duplicates. In the zlib
run, 23 findings had zero duplicate keys — suggesting hunters are
not overlapping on the same functions, which is a good signal.

For deeper dedup, extend the key to `(file, class, source_lines_start)` to
catch cases where different snippet continuations report the same issue.

---

## Stage 7 — Trace

For confirmed findings in **shared libraries**: fan out one tracer agent per
consumer repository to determine reachability from each consumer's external
attack surface, following the audit harness implementation.

### Trace Agent Mission (Audit Approach)

Following the audit harness implementation:
- **Reachability proof**: Determine if attacker-controlled input can reach the vulnerable sink
- **Call path validation**: If reachable, provide the exact call path from entry point to sink
- **Consumer-specific analysis**: Analyze each consumer repository independently using its snippet DB and SECURITY_CONTEXT.md
- **Prioritization**: Unreachable findings → deprioritize; Reachable findings → escalate to Feedback stage

### Trace Agent Inputs

Tracer agent receives:
- The confirmed finding (with PoC and call path from original hunt)
- The consumer repository's snippet database
- A `SECURITY_CONTEXT.md` for the consumer (entry points, trust boundaries, etc.)
- Optional: live target URL and credentials for reproduction validation

### Trace Agent Output

Output: `reachable: true/false` with supporting evidence:
- If `reachable: true`: Include call path from consumer's external attack surface to the vulnerable sink
- If `reachable: false`: Provide reasoning why the path is blocked (missing dependencies, permission checks, etc.)
- When possible, validate reachability against live target using provided credentials

### Safety Constraints (Audit Rules)

Following audit's safety rules for trace agents:
- Network egress restricted to live target host + `127.0.0.1` when `--target-url` is set
- No calls to external hosts beyond the specified target
- Findings that don't reproduce against live target are dropped or rejected
- Credentials flow into relevant stages as needed for live validation

---

## Stage 8 — Feedback

Reachable traces become new Hunt tasks in consumer repos, closing the cross-repo
propagation loop, following the audit harness implementation.

### Feedback Mechanism (Audit Approach)

Following the audit harness implementation:
- **Trace-to-task conversion**: Each reachable trace from the Trace stage generates new Hunt tasks in consumer repositories
- **Structural identity**: Feedback tasks are structurally identical to Stage 3 hunter tasks (same format, validation rules)
- **Known entry pre-loading**: The only difference is that the originating finding is pre-loaded in the context pack as a `known_entry` rather than discovered during hunting
- **Cross-repo propagation**: This closes the loop for vulnerability discovery across related codebases

### Feedback Task Composition

Each feedback task includes:
- `task_id`: Following audit's format `t_<subsystem>_<attack_class>_<n>`
- `attack_class`: Specific vulnerability class to hunt (e.g., `command_injection`, `sql_injection`)
- `scope_hint`: Trust boundary description from the validated trace (e.g., "HTTP POST /api/import reads `filename` from JSON body...")
- `target_files`: Verified files from consumer repo where the vulnerability may exist
- `known_entry`: The validated trace finding that seeded this hunt
- `evidence_basis`: Reference to the original trace that proved reachability

### Propagation Rules (Audit Constraints)

Following audit's propagation constraints:
- **Reachability required**: Only traces proven reachable (`reachable: true`) generate feedback tasks
- **No fabrication**: Findings that don't reproduce against live targets are not propagated
- **Credential propagation**: When live targets are used, credentials flow into feedback tasks for validation
- **Scope inheritance**: Feedback tasks inherit scope notes and exclusions from the original investigation

---

## Stage 9 — Report

See `references/schemas.md` → **Report schema** for the full output spec.

### Triage buckets

| Bucket | Criteria |
|---|---|
| **Fix now** | CRITICAL individual; feasible chain score ≥ 5; HIGH + `external-input` reachable |
| **Backlog** | HIGH without external-input path; MEDIUM isolated |
| **False positive** | No plausible call path; theoretical-only; sandbox/test-only code |

The reporting agent validates its output against the schema and fixes errors
before emitting. Every `fix_now` finding must have a confirmed call path from
a known entry point (main, exported symbol, HTTP handler).

---

## Signal-to-Noise Control

**Language noise**
- C/C++ → higher FP rate; lower FP threshold for `memory` + `external-input` co-tags
- Rust → `unsafe` blocks only; safe Rust memory bugs are logic-class
- Python/JS → no memory class; focus on injection, deserialization, auth

**Model bias**
- Models find bugs whether bugs exist or not; hedged findings vastly outnumber solid ones
- Mitigations: require PoC confirmation before triage queue entry; adversarial
  Validate stage; separate exploitability from reachability agents

---

## Architecture-Level Safety Controls

Security models show emergent, inconsistent behavior: same task + different
framing can yield different outcomes, and the same request across runs is
probabilistic. A model may confirm a serious memory bug then decline the
demo exploit.

This inconsistency is a design constraint, not a reliable safety boundary.
Require architecture-level controls regardless of model behavior:
- Sandboxed PoC execution (no production access)
- Scoped API keys per stage
- Network isolation for scratch runners

---

## Patching Pipeline Warning

> Faster is not enough.

Compressing CVE-to-patch SLA without fixing the regression testing pipeline
ships new bugs. AI-generated patches fix the target bug while silently breaking
dependents. Mitigations:
- Automated regression suite must **gate** patches, not be bypassed
- Architecture-level defenses (WAF, isolation, atomic rollout) shrink the
  cost of the patch-gap window
- Parallel workstream: fix the bug AND harden the architecture around it

---

## Stage Configuration (Audit-Inspired)

Following the audit harness implementation, configure each stage with appropriate models, concurrency, and tools:

### Model Selection Strategy

Following audit's `config/stages.yaml`:
- **Recon**: High-capability model (e.g., Claude Opus 4.7) for comprehensive repo mapping
- **Hunt**: Balanced model (e.g., Claude Sonnet 4.6) for parallel vulnerability hunting
- **Validate**: High-capability model **different from Hunt** (e.g., Claude Opus 4.7) for deliberate disagreement
- **Gapfill**: Same as Hunt for efficient coverage gap processing
- **Dedupe**: Efficient model for record collapsing
- **Trace**: High-capability model (e.g., Claude Opus 4.7) as "the stage that matters most"
- **Feedback**: Same as Hunt for task generation
- **Report**: Same as Hunt for structured output generation

### Concurrency Settings

Following audit's concurrency configurations:
- **Recon**: Low concurrency (1) as it's foundational and can be lengthy
- **Hunt**: High concurrency (50) for parallel vulnerability hunting across many targets
- **Validate**: Medium concurrency (10) for validating hunt outputs
- **Gapfill/Dedupe/Feedback/Report**: Low concurrency (1) as they're sequential or lightweight
- **Trace**: Medium concurrency (10) for analyzing multiple consumer repos

### Tool Allowlists

Following audit's stage-specific tool permissions:
- **Stages with Bash**: Recon, Hunt, Trace (for PoC compilation/execution and live testing)
- **Stages without Bash**: Validate, Gapfill, Dedupe, Feedback, Report (pure analysis/stages)
- **All stages**: Read, Grep, Glob for code navigation and searching
- **Bash restrictions**: When used, limit to read-only inspection and scratch directory operations

### Bounded Loops (Cost Control)

Following audit's loop limits to prevent runaway costs:
- **Gapfill iterations**: Maximum 2 Hunt → Validate → Gapfill cycles
- **Feedback iterations**: Single feedback pass after Trace
- **Maximum tasks**: Configurable max-recon-tasks to limit initial Hunt fanout
- **Cost guards**: Per-task checks to abort cooperatively when budget exceeded

## Scaling Notes

- **Repo > 1M tokens:** shard by top-level directory; run full pipeline per
  shard; merge finding sets before chaining (call graph must be global)
- **Cost control:** Use a fast/cheap model on the full snippet DB for tagging;
  reserve your strongest model for domain agents and chaining
- **Entry-point anchoring:** post-validation stage should require every
  `fix_now` finding to have a confirmed call path from a known entry point

---

## Quick-Start

```bash
# 1. Setup
pip install tree-sitter tiktoken   # swap tiktoken for any tokenizer you prefer

# 2. Ingest — extract functions as typed snippets
python ingestor.py --root ./myrepo --out output/snippets.json

# 3. Coordinate — build per-domain context packs
python coordinator.py --db output/snippets.json --out output/packs/

# 4. Hunt — run parallel hunter agents (one per domain pack)
#    Prints findings JSONL to stdout, progress to stderr
python run_agents.py \
    --packs output/packs/ \
    --model openrouter/openrouter/free \
    --parallel 3 \
    > output/findings.jsonl

# 5. Validate — adversarial re-read of findings
python validate.py \
    --findings output/findings.jsonl \
    --validate-model openrouter/openrouter/free \
    > output/validated.jsonl

# 6. Dedupe — collapse duplicates on (snippet_id, class)
python dedupe.py --findings output/validated.jsonl > output/deduped.jsonl

# 7. Chain — build exploit chains via call-graph BFS
python chainer.py \
    --findings output/deduped.jsonl \
    --db output/snippets.json \
    --out output/chains.json

# 8. Report — structured report with triage buckets
python reporter.py \
    --findings output/deduped.jsonl \
    --chains output/chains.json \
    --repo git@github.com:org/repo.git \
    --out output/report.json

# Or run everything in one command:
python run_pipeline.py \
    --root ./myrepo \
    --model openrouter/openrouter/free \
    --validate-model openrouter/openrouter/free \
    --parallel 3
```

### Pipeline CLI flags

| Flag | Default | Description |
|---|---|---|
| `--model` | — | LLM model for Hunt stage |
| `--validate-model` | same as `--model` | Different model for Validate (recommended) |
| `--parallel` | 3 | Max concurrent packs (ThreadPoolExecutor) |
| `--max-run` | all | Debug: process only N packs |
| `--reingest` | false | Re-run ingestor even if snippets.json exists |

### Output structure

```
output/
  snippets.json     # 594 snippets for ~23K LOC repo
  packs/            # mem-safety, auth, crypto, ipc, data-flow, format-str
  findings.jsonl    # raw findings with status:"raw" + poc_confirmed:false
  validated.jsonl   # findings with updated status + validate_reason
  deduped.jsonl     # collapsed on (snippet_id, class)
  chains.json       # exploit chains with scores
  report.json       # final triaged report
```

## Practical Implementation Notes

Lessons from implementing this pipeline against zlib (C library, v1.3.2.1,
~23K LOC, 594 snippets):

### Findings Density Expectation

Not every domain produces findings. In the zlib run:

| Domain | Findings | Notes |
|---|---|---|
| mem-safety | 4 | Realistic for a mature C library |
| data-flow | 19 | Most are "library accepts external input" — library-level FP |
| auth | 0 | Coverage gap (zlib has no auth) |
| crypto | 0 | Coverage gap (zlib has no crypto) |
| ipc | 0 | Coverage gap (zlib has no IPC) |
| format-str | 0 | Coverage gap (zlib has no printf calls) |

- **Coverage gaps are honest output** from a well-behaved hunter. They mean
  the domain isn't represented in the target, not that the pipeline failed.
- **Auth/crypto/ipc packs** in a compression library will inflate on the
  `external-input` tag overlap. Consider removing `external-input` from these
  domains' tag filters when targeting a narrow-scope library.
- **data-flow findings in a library** are mostly "attacker data enters library"
  — these are reachability questions, not library bugs. They become useful in
  the Trace stage when mapped to consumer repos.

### Model Behavior Observations

- **Free-tier model quality varies wildly.** Some responses are excellent
  (correctly identifying UAF patterns); some hallucinate code that doesn't exist.
- **Reasoning models** (nemotron, deepseek) produce longer, more thorough
  analyses but take 30-60s per response on free tier.
- **Standard models** (gemma, z-ai, baidu) respond in 5-15s but miss subtle
  patterns.
- **Paid models would reduce variance** significantly. Free tier is viable
  for prototyping but not production auditing.

### Pipeline Robustness Patterns

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

### PoC Compilation Blocker

The PoC confirmation loop assumes a sandboxed compile+run environment.
For C/C++ targets, this requires:
- A compiler toolchain in the sandbox
- The target library compiled as a shared object
- A harness that links against it and triggers the finding
- Network-isolated execution

Without this infrastructure, PoC confirmation is speculative. The pipeline
still produces useful findings, but they lack the strongest evidence level.

### Entry-Point Anchoring for Library Targets

Findings in a library like zlib have no intrinsic entry point — the library
has no `main()`. Every function is callable. For `fix_now` classification:

- A library finding needs a **consumer context** to be actionable
- The Trace stage (consumer fan-out) is essential for library targets
- Until traced, library findings should default to `backlog` unless CRITICAL

---

## Checklist

- [ ] Ingestor produces typed, tagged snippet DB with caller/callee stubs
- [ ] Snippet IDs use short sha256 format (`sha256:{h[:6]}:{h[-6:]}`)
- [ ] tree-sitter 0.25+ API used: `parser.language = lang` not `set_language()`
- [ ] `SECURITY_CONTEXT.md` embedded in every context pack
- [ ] Context packs budget-capped at 180k tokens; oversized domains split
- [ ] Hunter agents scoped to one attack class × one component each
- [ ] `MODEL_BY_DOMAIN` maps strongest models to mem-safety/data-flow/crypto
- [ ] Hunter output parser handles: JSON arrays, wrapper objects, sentinel markers, free-text contamination, truncated output
- [ ] Every finding has `status: "raw"` and `poc_confirmed: false` defaults
- [ ] Reasoning model `reasoning` field concatenated with `content`
- [ ] All status/log to stderr, findings JSONL to stdout
- [ ] Sync urllib pattern (not async httpx)
- [ ] `ThreadPoolExecutor` with 3-4 workers for parallel packs
- [ ] Coverage gaps emitted by hunters, re-queued for Gapfill
- [ ] Validate agent uses different prompt + model/routing-pool, no new-finding capability
- [ ] Chainer uses call-graph traversal (BFS ≤4 hops) + scoring, not just co-occurrence
- [ ] PoC loop runs in isolated scratch environment, no production access (blocked for C/C++ without sandboxed compilation)
- [ ] Dedupe on `(snippet_id, class)` composite key, keep highest severity
- [ ] Trace fans out per consumer repo for shared library findings
- [ ] Report schema defined; agent self-validates before emitting
- [ ] Library findings default to `backlog` unless CRITICAL (untraced)
- [ ] `--max-run N` flag for debugging single packs
