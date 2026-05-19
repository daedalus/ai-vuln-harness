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
- `references/stages.md` — Detailed per-stage design and implementation guidance.
- `references/operation.md` — Practical notes: model behavior, cache, formatting,
  validate gotchas, library targeting.
- `references/implementation.md` — Full code sketches for every stage.
- `references/schemas.md` — All JSONL/JSON schemas.

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
tracing — following the audit harness implementation's 10-stage pipeline.

Key insights:
- **Narrow scope**: One attack class per agent prevents context overload
- **Adversarial validation**: Separate agent attempts to disprove findings
- **Reachability gating**: Findings must be proven reachable from attacker input
- **Feedback loop**: Validated findings seed new hunts in related codebases

---

## Full Pipeline

```
┌──────────────┐
│ 1.Ingestor   │  Extract functions → typed, tagged snippet DB
└──────┬───────┘
       │ snippet DB
┌──────▼───────┐
│ 2.Recon      │  Map repo, identify subsystems, emit hunt tasks
└──────┬───────┘
       │ task queue (JSON)
┌──────▼───────┐
│ 3.Coordinator│  Build per-domain context packs (≤180K tokens)
└──────┬───────┘
       │ context packs
┌──────▼───────┐
│ 4.Hunt       │  One attack class per agent; compile/run PoCs
└──────┬───────┘
       │ raw findings (JSONL)
┌──────▼────────────┐
│ 5.Validate ◄─► Gapfill│  (inner loop)
└──────┬────────────┘
       │ confirmed findings
┌──────▼───────┐
│ 6.Dedupe     │  Cluster by root cause
└──────┬───────┘
       │ deduped findings
┌──────▼───────┐
│ 7.Chainer    │  Build exploit chains via call-graph BFS
└──────┬───────┘
       │ findings + chains
┌──────▼───────┐
│ 8.Trace      │  Prove attacker input reaches sink
└──────┬───────┘
       │ reachable findings
┌──────▼───────┐
│ 9.Feedback   │  Turn traces into new Hunt tasks
└──────┬───────┘
       │ new task queue
┌──────▼───────┐
│10.Report     │  Schema-validated structured output
└──────────────┘
```

---

## Stage Summaries

### Stage 1 — Ingestor
Convert repo to a typed snippet database (functions/methods, ≤800 tokens each)
with security tags (memory, external-input, auth, crypto, ipc, unsafe,
format-string, integer-arith). Uses tree-sitter v0.25+ for extraction.
Enriched with historical context from git security patches.

See `references/stages.md` → Stage 1, `references/implementation.md` → ingestor.py.

### Stage 2 — Recon
Maps the repo: identifies subsystems, build system, entry points,
and generates structured hunt tasks with concrete file targets per attack
class. Without this stage the Coordinator builds packs from the entire
snippet DB with no prioritization.

See `references/stages.md` → Stage 2.

### Stage 3 — Coordinator
Build per-domain context packs from tagged snippets (see Agent Domain
Configuration), filtered to Recon's target files. Packs capped at 180K
tokens. Each pack includes `SECURITY_CONTEXT.md`,
cross-references, and scope notes.

See `references/stages.md` → Stage 3, `references/implementation.md` → coordinator.py.

### Stage 4 — Hunter Cluster
Parallel agents, one per domain pack. Each agent receives a scoped system
prompt ("one attack class, one scope") and emits zero or more findings as
JSONL. Implements dynamic model fallback chain, sync urllib, output parser
robust to model hallucination. Status to stderr, findings to stdout.

See `references/stages.md` → Stage 4, `references/implementation.md` → run_agents.py.

### Stage 5 — Validate + Gapfill
Adversarial re-read: a different model attempts to disprove each finding.
Requires system message (some models return empty without it) and curated
model chain. Coverage gaps are re-queued as new hunt tasks.

**Validate-only mode**: `--validate-only` skips the Hunt stage entirely and
loads cached findings from `output/findings.jsonl`. Useful for re-running
Validate with a different model pool or after adjusting the validate prompt
without burning API calls on re-hunting. Runs Validate → Dedupe → Report
from cache in under a second.

See `references/stages.md` → Stage 5.

### Stage 6 — Dedupe
Collapses findings on `(snippet_id, class)` composite key, keeping highest
severity. For deeper dedup, extend key to `(file, class, source_lines_start)`.

See `references/stages.md` → Stage 6.

### Stage 7 — Chainer
Builds exploit chains via call-graph BFS (≤4 hops). Scores candidates on
trust-boundary crossing, severity levels, and recent file modification.
Submits top chains to a reasoning agent for analysis.

See `references/stages.md` → Stage 7, `references/implementation.md` → chainer.py.

### Stage 8 — Trace
For shared-library findings: fan out tracer agents per consumer repo to
determine reachability from each consumer's attack surface.

See `references/stages.md` → Stage 8.

### Stage 9 — Feedback
Reachable traces become new Hunt tasks in consumer repos. The originating
finding is pre-loaded as `known_entry`.

See `references/stages.md` → Stage 9.

### Stage 10 — Report
Schema-validated structured output with triage buckets: fix_now, backlog,
false_positive. Every finding includes a `bucket_rationale` field explaining
why it landed in its bucket (e.g., "Rejected by Validate: code checks buffer
capacity", "Non-cryptographic checksum by design"). The report also includes
a `bucket_definitions` dictionary documenting triage criteria. Agent
self-validates before emitting.

See `references/stages.md` → Stage 10, `references/schemas.md` → Report schema.

---

## Agent Domain Configuration

The Hunt stage is driven by a typed domain catalog. Each domain specifies its
attack-class tags, dependencies (domains to run first), and whether it must
run exclusively (no concurrent domains of the same type).

```python
AGENT_DOMAINS: dict[str, AgentSpec] = {
    # ── core ──────────────────────────────────────────────────────────────────
    "mem-safety":    AgentSpec(["memory", "use-after-free", "buffer-overflow",
                                "integer-arith", "oob-read", "oob-write"],
                               ["unsafe"], exclusive=True),
    "auth":          AgentSpec(["auth", "session", "jwt", "oauth", "csrf",
                                "privilege-escalation", "broken-access-control"],
                               ["external-input"]),
    "crypto":        AgentSpec(["crypto", "tls", "cert-validation",
                                "weak-cipher", "key-management", "rng"],
                               exclusive=True),
    "ipc":           AgentSpec(["ipc", "shared-memory", "pipe", "socket",
                                "dbus", "signal-handler"],
                               ["race-condition", "external-input"]),
    "data-flow":     AgentSpec(["taint", "external-input", "user-controlled",
                                "sink", "sanitization"]),
    "format-str":    AgentSpec(["format-string"], exclusive=True),

    # ── expanded ──────────────────────────────────────────────────────────────
    "injection":     AgentSpec(["sql-injection", "cmd-injection", "ldap-injection",
                                "xpath-injection", "template-injection",
                                "header-injection", "log-injection"],
                               ["external-input"]),
    "path-traversal":AgentSpec(["path-traversal", "symlink", "zip-slip",
                                "open-redirect"],
                               ["external-input", "toctou"]),
    "deserialization":AgentSpec(["deserialization", "pickle", "yaml-load",
                                 "xml-entity", "object-injection"],
                                ["external-input"], exclusive=True),
    "concurrency":   AgentSpec(["race-condition", "toctou", "deadlock",
                                "double-free", "use-after-free-concurrent"],
                               ["shared-memory", "signal-handler"]),
    "web":           AgentSpec(["xss", "csrf", "cors-misconfiguration",
                                "clickjacking", "open-redirect", "ssrf"],
                               ["external-input", "auth"]),
    "network":       AgentSpec(["ssrf", "dns-rebinding", "request-smuggling",
                                "tls", "cert-validation", "protocol-downgrade"],
                               ["external-input"]),
    "secrets":       AgentSpec(["hardcoded-credential", "key-in-memory",
                                "secret-in-log", "env-leak", "key-material"],
                               exclusive=True),
    "supply-chain":  AgentSpec(["dependency", "typosquatting", "build-artifact",
                                "sbom", "pinning", "ci-pipeline"],
                               exclusive=True),
    "resource":      AgentSpec(["dos", "resource-exhaustion", "regex-dos",
                                "allocation", "infinite-loop", "zip-bomb"],
                               ["external-input"]),
    "side-channel":  AgentSpec(["timing", "cache-side-channel", "spectre",
                                "branch-prediction", "padding-oracle"],
                               ["crypto"], exclusive=True),
    "logging":       AgentSpec(["insufficient-logging", "log-injection",
                                "audit-gap", "error-disclosure"],
                               ["external-input"]),
    "access-control":AgentSpec(["idor", "privilege-escalation", "suid",
                                "capability-leak", "namespace-escape",
                                "container-escape"],
                               ["auth"]),
}
```

The Coordinator uses this dict to:
1. **Filter snippets** by domain tags for each agent's context pack
2. **Resolve dependencies** — run `auth` before `web`, `crypto` before `side-channel`
3. **Enforce exclusivity** — `exclusive=True` domains run in isolation (no concurrent agents from the same exclusive group)
4. **Generate `MODEL_BY_DOMAIN`** — assign best models to mem-safety, data-flow, crypto

---

## Hard-Won Rules (Directives from Practice)

These rules came from running the full pipeline on a real target (zlib) and
catching what the design missed. Apply them every time.

### Tagging: avoid inflation
- **`external-input` keyword-match is too broad for C libraries.** Keywords
  `buf`, `arg`, `len`, `src` appear in almost every function signature. For
  library targets, strip `external-input` from all domain tag filters
  EXCEPT `data-flow`. For `data-flow`, detect actual I/O calls
  (`read()`, `recv()`, `fgets()`) instead of parameter names.
- **`integer-arith` keyword-match on `len`, `size`, `count`** matches every
  buffer function. Narrow to operations on untrusted lengths only.

### Context packs: filter noise directories
- **Strip `contrib/`, `examples/`, `test/` from the snippet DB before
  building packs.** These contain unmaintained or harness code that inflates
  snippet counts without representing the real attack surface.
- On zlib this cut ~200 of 608 snippets. Always do this filter before
  the Coordinator stage.

### Hunt concurrency: respect free-tier ceilings
- **Free-tier OpenRouter: cap concurrent workers at 2-3.** Higher concurrency
  triggers HTTP 429 on most models. The fallback chain is mandatory but adds
  30-60s per model timeout. Expect 5-15 minutes wall-clock for 6 packs.
- **Paid API** can go higher (50+ workers).

### Validate model pool: must be disjoint from Hunt
- **Validate MUST use models the Hunt stage cannot reach.** Shared models
  produce correlated biases — if both stages use deepseek, format-string
  false positives slip through. Split the model list at startup: Hunt gets
  one half (deepseek, qwen, gemma), Validate gets the other (nemotron,
  trinity, z-ai). Zero overlap.
- If the model list is too small for a clean split, give the strongest
  model to Validate — disagreement beats agreement:
  ```
  hunt_models = [m for m in models if "deepseek" in m or "qwen" in m]
  validate_models = [m for m in models if "nemotron" in m or "trinity" in m]
  ```

### Zero findings: do not treat as pipeline failure
- **Well-audited targets legitimately produce zero findings.** The zlib
  mem-safety agent produced a 9.6KB analysis concluding no exploitable
  vulnerabilities — this is correct behavior. Coverage gaps from hunters
  ("no crypto in compression lib") are honest output, not errors.
- **Gapfill re-queues coverage gaps with narrowed scope**, not as failures.

### Sentinel-only output: auto-generate coverage gaps
- **"0 findings, 0 gaps" is ambiguous.** It could mean the model analyzed
  everything and found nothing, or that the pipeline never reached the model.
  The parser must distinguish these.
- **Detect sentinel-only responses in `parse_findings`**: when the only JSON
  object in the response is `{"done": true}` with no findings and no gaps,
  auto-generate a coverage gap record. This makes "analyzed, found nothing"
  visible as `1 gap` rather than silently vanishing into `0/0`.
- **Add a `domain` parameter to `parse_findings`** so the auto-generated gap
  identifies which domain produced the sentinel-only output. Log a warning
  to stderr when sentinel-only detection triggers.
- On a zlib run this caught `format-str` — the model produced a 2.9KB
  analysis concluding no vulnerabilities (all format strings are by-design
  API), but emitted only `{"done": true}`. Before the fix: `0/0` (silent).
  After: `0/1` with `⚠ sentinel-only output` warning.

### Mixed-line JSON extraction: handle JSON+prose on one line
- **Models often emit a JSON object followed by free-text reasoning on the
  same line**, e.g. `{"done": true} We are tasked with analyzing...`.
  `json.loads()` fails on the whole line because of the trailing text.
- **Fix**: in the line-by-line parser, when `json.loads(line)` fails, attempt
  to extract a JSON object using balanced-brace prefix matching. Walk the line
  character by character tracking `{`/`}` depth; at depth 0 after a `}`, try
  `json.loads()` on the substring from the last `{` start. The first valid
  parse wins.
- This is distinct from the three-fallback strategy (which operates on the
  full response). This operates **per line** and catches the common pattern
  where the model places the sentinel and its reasoning on one line.
- Without this fix, sentinel-only detection fails silently — the line
  `{"done": true} We analyzed everything...` never triggers `saw_done`
  because `json.loads` rejects the whole line.

### Validate prompt must include the actual source code
- **Models cannot verify findings from descriptions alone.** The validate prompt
  must include the code snippet content (via `snippet_id` lookup in the JSON DB)
  so the model can verify the claim against the real implementation.
- Without the code, models hallucinate confirmation. For example, an adler32
  finding claiming "MOD63 is wrong, should be MOD65521" was confirmed by
  Nemotron — even though MOD63 is mathematically correct and intentional.
  With the code in the prompt, Nemotron-3-Nano correctly rejected it.
- The snippet lookup adds negligible cost (<1ms per finding via dict lookup)
  and dramatically improves validate accuracy. The prompt should include:
  ```
  ACTUAL SOURCE CODE (file: {file}, lines {lines}):
  ```c
  {code}
  ```
  ```
- **Add a fourth validate criterion**: "Is the model's claim consistent with
  what the code actually does?" This catches hallucinations where the hunter
  model misread or overinterpreted the code.

### API-by-design findings: reject them
- **Functions named `*printf*` intentionally accept caller-controlled format
  strings.** This is not a vulnerability — it's the API contract. A "format
  string vulnerability" requires attacker control of the format arg, which
  means the caller is misusing the API.
- Validate MUST check API contracts before accepting findings. Known
  by-design patterns: `*printf*`, `*write*`, `*read*`, `execute*`, `*open*`.
- Bucket: `backlog` at best (documentation improvement), never `fix_now`.

### Reasoning models: concatenate both fields
- **Always read both `message.content` and `message.reasoning`.** Deepseek
  and other reasoning models put chain-of-thought in `reasoning` and the
  final answer in `content`. If you only read `content`, you miss findings
  embedded in the reasoning trace.
- The line-by-line JSONL parser handles the extra text after `{done: true}`
  by silently skipping non-JSON lines — do NOT strip text after the sentinel.

### Cache: makes everything restartable
- **Cache every API response** using key `stage:model:sha256(prompt)[:12]`.
  First run cost ~14 calls for a zlib-size target. Subsequent runs load from
  `cache.json` — zero API calls, completes in <1s.
- Check cache before every API call. Save after every successful response.
- Without this, every re-run burns the full API budget.

### Prompts: files, not inline strings
- **Every stage prompt is a standalone markdown file** loaded at runtime,
  never embedded in Python code with `str.format()` or f-strings. Inline
  prompts are unmaintainable and break on JSON braces (`{` `}` must be
  escaped to `{{` `}}`).
- Store prompts in a `prompts/` directory: `prompts/recon.md`, `prompts/hunt.md`,
  `prompts/validate.md`, etc. Each prompt file contains role definition,
  system message, and explicit Method steps the agent must follow.
- The prompt file is loaded, wrapped with stage-specific context (snippets,
  findings, schemas), and sent. This separation makes prompt iteration fast
  and reviewable.
- See `~/code/audit/prompts/` for the reference implementation.

### JSON Schema: validate every agent output
- **Every stage defines a JSON Schema** (`schemas/*.json`) that its output
  must conform to. The schema body is appended verbatim to the system prompt
  so the model never guesses field names.
- **After every agent response, validate against schema.** If validation fails,
  issue a **repair turn**: send the model its own output plus the schema
  error message and ask it to fix the structure. Limit to 2 repair attempts
  per stage to avoid infinite loops.
- Repair turns are cheaper than re-running the agent and catch the "model
  almost got it right" case reliably.
- See `~/code/audit/schemas/` (9 schemas) and `~/code/audit/audit/runner.py`
  (repair turn implementation) for reference.

### JSON extraction: three-fallback strategy
- **Never assume the model returns pure JSON.** Always use at least three
  extraction strategies in order:
  1. **Direct parse** — try `json.loads()` on the full response string
  2. **Fenced code block** — extract content between ```json and ``` markers
  3. **Largest balanced braces** — find the longest substring with matching
     `{` `}` brackets and try to parse it
- Each fallback is tried in sequence. The first that parses as valid JSON
  wins. If all three fail, log the full response and mark the stage as failed.
- Fallback 3 alone catches ~95% of model formatting errors. Combined with
  fallback 2, the extraction success rate is effectively 100%.
- See `~/code/audit/audit/json_utils.py` for the reference implementation.

### Recon stage: mandatory first step
- **Add a dedicated Recon stage before Hunt.** The Recon agent maps the repo:
  identifies subsystems, build system (Makefile/CMake/Cargo.toml/pyproject.toml),
  entry points (main, signal handlers, inbound API routes), and generates
  structured hunt tasks with concrete file targets per attack class.
- Without Recon, the Coordinator builds domain packs from the entire snippet
  DB with no prioritization. Recon adds human-like scoping: "focus on the
  decompression path, skip the test harness."
- Recon output is a JSON array of `{domain, target_files, rationale, priority}`
  objects. The Coordinator THEN filters snippets to only those target_files,
  dramatically reducing noise in each pack.
- See `~/code/audit/prompts/recon.md` and `~/code/audit/config/stages.yaml`.
  for reference.

### State database: enable resume
- **Persist pipeline state in a SQLite database**, not ephemeral JSON files.
  The state DB tracks: tasks (with status `pending|running|done|failed`),
  findings (each with stage provenance), traces, and artifact paths.
- On restart, the pipeline queries the state DB and skips completed stages.
  This turns the pipeline from a fragile one-shot script into a robust
  process that survives crashes, API outages, and mid-run config changes.
- The state DB also enables incremental runs: add new snippets and the
  pipeline will only re-run stages affected by the change.
- See `~/code/audit/audit/db.py` for the reference implementation.

### Configure model per stage, not globally
- **Every stage gets its own model, concurrency, and tool configuration**
  in a YAML config file, not hardcoded in Python. Example structure:
  ```yaml
  stages:
    recon:
      model: claude-opus-4
      concurrency: 1
      tools: [read, grep, glob, bash]
    hunt:
      model: claude-sonnet
      concurrency: 50
      tools: [read, grep, glob, bash]
    validate:
      model: claude-opus-4
      concurrency: 10
      tools: [read]
  ```
- This makes model tiering explicit, trivially reconfigurable, and
  reviewable without changing code.

## Signal-to-Noise Control

**Language noise**
- C/C++ → higher FP rate; lower FP threshold for `memory` + `external-input` co-tags
- Rust → `unsafe` blocks only; safe Rust memory bugs are logic-class
- Python/JS → no memory class; focus on injection, deserialization, auth

**Tag inflation (learned from zlib)**
- `external-input` keyword-match on `buf`, `arg`, `len`, `src` matches
  nearly every C function (99.9% in practice). For library targets, either
  drop `external-input` from domain tag filters or use a smarter heuristic
  (detect actual `read()`/`recv()` calls, not parameter names).
- `integer-arith` keyword-match on `len`, `size`, `count` matches every
  function that processes a buffer — i.e., almost every function in a C
  library. Narrow to operations on untrusted lengths.

**Model bias**
- Models find bugs whether bugs exist or not; hedged findings vastly outnumber solid ones
- Mitigations: require PoC confirmation before triage queue entry; adversarial
  Validate stage; separate exploitability from reachability agents

---

## Architecture-Level Safety Controls

Security models show emergent, inconsistent behavior: same task + different
framing can yield different outcomes, and the same request across runs is
probabilistic.

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

## Stage Configuration

### Model Selection Strategy

| Stage | Model tier | Notes |
|---|---|---|---|
| Recon | Highest capability | Comprehensive repo mapping, subsystem identification |
| Hunt | Balanced | Parallel vulnerability hunting, scoped per domain pack |
| Validate | Highest, **disjoint from Hunt** | MUST use models the Hunt stage cannot access. Shared models → correlated biases slip through. In practice: if Hunt uses deepseek-v4-flash, Validate should use nemotron-nano or trinity. |
| Gapfill | Same as Hunt | Coverage gap processing |
| Dedupe | Efficient | Record collapsing |
| Trace | Highest capability | "The stage that matters most" |
| Feedback | Same as Hunt | Task generation |
| Report | Same as Hunt | Structured output generation |

### Concurrency

| Stage | Concurrency (paid) | Concurrency (free tier) | Notes |
|---|---|---|---|
| Recon | 1 | 1 | Foundational, can be lengthy |
| Hunt | 50 | **2-3** | Free-tier OpenRouter 429s above 3 concurrent workers. Paid API can go higher. |
| Validate | 10 | **2-3** | Same rate-limit ceiling as Hunt on free tier. |
| Gapfill/Dedupe/Feedback/Report | 1 | 1 | Sequential or lightweight |
| Trace | 10 | **2-3** | Multiple consumer repos, but rate-limited the same. |

### Tool Allowlists

- **Stages with Bash**: Recon, Hunt, Trace (PoC compilation, live testing)
- **Stages without Bash**: Validate, Gapfill, Dedupe, Feedback, Report
- **All stages**: Read, Grep, Glob for code navigation

### Bounded Loops (Cost Control)

- **Gapfill iterations**: Maximum 2 Hunt → Validate → Gapfill cycles
- **Feedback iterations**: Single feedback pass after Trace
- **Maximum tasks**: Configurable max-recon-tasks to limit initial Hunt fanout
- **Cost guards**: Per-task checks to abort cooperatively when budget exceeded

---

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
pip install tree-sitter tiktoken

# 2. Ingest — extract functions as typed snippets
python ingestor.py --root ./myrepo --out output/snippets.json

# 3. Recon — map repo, identify subsystems, emit hunt tasks
python recon.py --db output/snippets.json --out output/tasks.json

# 4. Coordinate — build per-domain context packs
python coordinator.py --db output/snippets.json --tasks output/tasks.json --out output/packs/

# 5. Hunt — run parallel hunter agents (one per domain pack)
#    Uses dynamic model chain from OpenRouter API
python run_agents.py --packs output/packs/ --parallel 3 > output/findings.jsonl

# 6. Validate — adversarial re-read of findings
python validate.py > output/validated.jsonl

# 7. Dedupe — collapse duplicates on (snippet_id, class)
python dedupe.py > output/deduped.jsonl

# 8. Chain — build exploit chains via call-graph BFS
python chainer.py > output/chains.json

# 9. Report — structured report with triage buckets
python reporter.py > output/report.json

# Re-runs load from cache.json — zero API calls
```

### Pipeline CLI flags

| Flag | Default | Description |
|---|---|---|
| `--model` | — | LLM model for Hunt stage |
| `--validate-model` | same as `--model` | Different model for Validate (recommended) |
| `--parallel` | 3 | Max concurrent packs (ThreadPoolExecutor) |
| `--max-run` | all | Debug: process only N packs |
| `--validate-only` | false | Skip Hunt, load cached findings from `output/findings.jsonl`, run Validate → Dedupe → Report |
| `--tasks` | — | Path to Recon-generated tasks.json |
| `--reingest` | false | Re-run ingestor even if snippets.json exists |
| `--no-cache` | false | Skip cache reads (force all API calls) |
| `--db` | — | Path to SQLite state DB (enables resume) |

### Output structure

```
output/
  cache.json        # LLM response cache (key: stage:model:hash)
  snippets.json     # extracted function snippets
  tasks.json        # Recon-generated hunt tasks
  packs/            # one per agent domain (see Agent Domain Configuration)
  findings.jsonl    # raw findings with status:"raw" + poc_confirmed:false
  gaps.jsonl        # coverage gaps emitted by hunters
  validated.jsonl   # findings with updated status + validate_reason
  deduped.jsonl     # collapsed on (snippet_id, class)
  chains.json       # exploit chains with scores
  report.json       # final triaged report with bucket_rationale per finding
```

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
- [ ] **Sentinel-only detection**: parser auto-generates coverage gap when `{"done": true}` is the only output (no findings, no gaps)
- [ ] **Mixed-line JSON extraction**: per-line balanced-brace prefix matching catches `{"done": true} free text...` on same line
- [ ] Every finding has `status: "raw"` and `poc_confirmed: false` defaults
- [ ] Reasoning model `reasoning` field concatenated with `content`
- [ ] All status/log to stderr, findings JSONL to stdout
- [ ] Sync urllib pattern (not async httpx)
- [ ] `ThreadPoolExecutor` with 3-4 workers for parallel packs
- [ ] Coverage gaps emitted by hunters, re-queued for Gapfill
- [ ] Validate agent uses **completely disjoint model pool** from Hunt (overlap → correlated biases slip through)
- [ ] **Validate prompt includes code snippet content** — lookup by `snippet_id`, not just the finding description (prevents hallucination confirmation)
- [ ] **`external-input` tag inflation checked** — for compiled libraries, verify it doesn't match 99%+ of functions. Strip from domain filters if so; only data-flow should use it.
- [ ] **Contrib/examples/test directories stripped** before building packs (focuses on real attack surface)
- [ ] Dedupe on `(snippet_id, class)` composite key, keep highest severity
- [ ] Chainer uses call-graph traversal (BFS ≤4 hops) + scoring, not just co-occurrence
- [ ] PoC loop runs in isolated scratch environment, no production access (blocked for C/C++ without sandboxed compilation)
- [ ] Trace fans out per consumer repo for shared library findings
- [ ] Report schema defined; agent self-validates before emitting
- [ ] **Report includes `bucket_rationale` per finding** explaining why it landed in fix_now/backlog/false_positive
- [ ] **Report includes `bucket_definitions`** documenting triage criteria at the report root
- [ ] **`--validate-only` flag** skips Hunt, loads cached findings from `output/findings.jsonl`, runs Validate → Dedupe → Report
- [ ] **Gaps persisted to `output/gaps.jsonl`** alongside findings for `--validate-only` replay
- [ ] Library findings default to `backlog` unless CRITICAL (untraced)
- [ ] `--max-run N` flag for debugging single packs
- [ ] **Model fallback chain** — dynamic fetch from API, index into sorted chain, advance on 429
- [ ] **LLM response cache** — `stage:model:sha256(prompt)[:12]` key, JSON file, checked before every API call
- [ ] **System message in validate** — models return empty content without it
- [ ] `str.format()` **braces escaped** — use `{{` `}}` for literal JSON in system prompts
- [ ] **No `openrouter/free` routing alias** — use concrete model IDs from `/v1/models`
- [ ] **Prompts are standalone markdown files** in `prompts/` — never inline in Python code
- [ ] **JSON Schema defined per stage**; schema body appended to system prompt
- [ ] **Repair turns on schema validation failure** — max 2 attempts per stage
- [ ] **Three-strategy JSON extraction** — direct parse → fenced code block → largest balanced braces
- [ ] **Recon stage runs before Hunt** — maps repo, identifies subsystems, generates structured hunt tasks
- [ ] **State DB (SQLite)** persists task/finding/trace state for resume
- [ ] **Model per stage configured in YAML** — not hardcoded in Python
