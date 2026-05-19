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

Run agents in parallel (asyncio / multiprocessing). See
`references/implementation.md` → **run_agents.py** for the async runner.

**Model selection:** Use your highest-capability model for `mem-safety`,
`data-flow`, and `crypto` — these require deep reasoning. A faster/cheaper
model tier is acceptable for `format-str` and `ipc`, which are more
pattern-driven.

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

- **Different model requirement**: Use a different LLM model than the Hunt stage to reduce correlated biases
- **Role separation critical**: Validate agent has **no ability to generate new findings** - only assess existing ones
- **Deliberate disagreement**: Two agents in disagreement >> one agent self-reviewing for accuracy
- **Output format**: `confirmed` / `rejected` / `needs-more-info` per finding
- **Adversarial framing**: Explicitly instruct the validator: "Your job is to disprove this finding, not find new ones"

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
1. Same vulnerability class (e.g., `sql_injection`)
2. Same vulnerable function/snippet (same `snippet_id`)
3. Similar root cause context (equivalent taint propagation paths)
4. Same trust boundary crossing pattern

This prevents overwhelming operators with redundant reports of the same underlying issue.

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
pip install tree-sitter tiktoken   # swap tiktoken for any tokenizer you prefer
python ingestor.py --root ./myrepo --out snippets.json
python coordinator.py --db snippets.json --out packs/
python run_agents.py --packs packs/ --model <your-model-id> --out findings.jsonl
python chainer.py --findings findings.jsonl --db snippets.json --out chains.json
python validator.py --findings findings.jsonl --chains chains.json --out report.json
```

## Checklist

- [ ] Ingestor produces typed, tagged snippet DB with caller/callee stubs
- [ ] `SECURITY_CONTEXT.md` embedded in every context pack
- [ ] Context packs budget-capped at 180k tokens; oversized domains split
- [ ] Hunter agents scoped to one attack class × one component each
- [ ] Coverage gaps emitted by hunters, re-queued for Gapfill
- [ ] Validate agent uses different prompt + model, no new-finding capability
- [ ] Chainer uses call-graph traversal + scoring, not just co-occurrence
- [ ] PoC loop runs in isolated scratch environment, no production access
- [ ] Dedupe on root cause, not symptom
- [ ] Trace fans out per consumer repo for shared library findings
- [ ] Report schema defined; agent self-validates before emitting
- [ ] Regression suite gates AI-generated patches before deploy
