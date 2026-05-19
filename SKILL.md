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
(2026-05-18).

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
tracing.

---

## Full Pipeline

```
┌──────────────┐
│   Ingestor   │  Clone repo → chunk → tag → emit snippet DB
└──────┬───────┘
       │ snippet DB (JSON/SQLite)
┌──────▼───────┐
│  Coordinator │  Assign snippets by domain; write per-agent context packs
└──────┬───────┘
       │ context packs
┌──────▼──────────────────────────────────────────┐
│  Hunter cluster (parallel)                       │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ...    │
│  │MemSafety │ │  AuthN   │ │DataFlow  │         │
└──────┬───────────────────────────────────────────┘
       │ raw findings (JSONL)
┌──────▼───────┐        ┌──────────┐
│   Validate   │◄──────►│ Gapfill  │  (inner loop)
└──────┬───────┘        └──────────┘
       │ confirmed findings
┌──────▼───────┐
│   Chainer    │  Call-graph traversal → exploit path candidates + PoC loop
└──────┬───────┘
┌──────▼───────┐
│    Dedupe    │  Collapse same root cause
└──────┬───────┘
┌──────▼───────┐
│    Trace     │  Shared library findings → fan out per consumer repo
└──────┬───────┘
┌──────▼───────┐
│   Feedback   │  Reachable traces → new Hunt tasks in consumer repos
└──────┬───────┘
┌──────▼───────┐
│    Report    │  Structured output, schema-validated
└──────────────┘
```

---

## Stage 1 — Ingestor

**Goal:** convert a repo into a flat, typed snippet database that fits agents
into budget-bounded context windows.

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

### Budget enforcement

Each pack must fit within **180k tokens** (leaving 20k for output). If a domain
exceeds budget, split into sub-packs by directory prefix and run multiple
instances in parallel.

---

## Stage 3 — Hunter Cluster

Each agent receives its context pack and a domain-scoped system prompt:

```
You are a security auditor specialized in <domain>.
Rules:
1. Report only real vulnerabilities with a plausible trigger path.
2. Each finding: one JSON line (see Finding schema in references/schemas.md).
3. Coverage gaps: {"coverage_gap":"...","reason":"..."}
4. No other output. End with {"done":true}.
```

Run agents in parallel (asyncio / multiprocessing). See
`references/implementation.md` → **run_agents.py** for the async runner.

**Model selection:** Use your highest-capability model for `mem-safety`,
`data-flow`, and `crypto` — these require deep reasoning. A faster/cheaper
model tier is acceptable for `format-str` and `ipc`, which are more
pattern-driven.

**Prompt design patterns:**

| Pattern | Example |
|---|---|
| Narrow scope | `"Look for UAF in alloc_buffer() only"` |
| Trust boundaries | `"Attacker input enters at X, trust boundary at Y"` |
| Prior coverage | `"Area Z was audited in run N, skip it"` |
| Adversarial framing | `"Your job is to disprove this finding, not find new ones"` |
| Separate questions | Agent A: exploitable? Agent B: reachable from outside? |

---

## Stage 4 — Validate + Gapfill (inner loop)

### Validate

- Independent agent, **different prompt, different model if possible**
- Task: attempt to *disprove* each finding
- No ability to generate new findings (role separation is critical)
- Two agents in deliberate disagreement >> one agent self-reviewing
- Output: `confirmed` / `rejected` / `needs-more-info` per finding

### Gapfill

- Hunters' `coverage_gap` records re-queued as new scoped Hunt tasks
- Loop: Hunt → Validate → Gapfill → Hunt until queue drains

---

## Stage 5 — Chainer

**Goal:** detect clusters where multiple low/medium findings compose into a
higher-severity exploit chain.

### Call-graph algorithm

1. Build call graph from `callers`/`callees` in the snippet DB.
2. For each pair `(A, B)` where `A.snippet_id` is reachable from `B.snippet_id`
   in ≤ 4 hops, emit a candidate chain.
3. Score candidates:
   - +2 if chain crosses a trust boundary (`external-input` → sink)
   - +1 per MEDIUM / +2 per HIGH / +3 per CRITICAL finding in chain
4. Submit top-N chains to a **chain reasoning agent** (prompt in
   `references/implementation.md` → **chainer**).

### PoC confirmation loop

A finding with a PoC is actionable. A finding without one is speculation.
Asking "is this buggy?" and "can an attacker reach this from outside?" as
**separate agent tasks** produces better reasoning than combining them.

See `references/implementation.md` → **PoC loop** for the confirmation
pseudocode and isolation requirements.

---

## Stage 6 — Dedupe

Collapse findings sharing the same root cause to a single record. Dedupe on
root cause, not symptom — the same UAF reported from 3 call paths is one bug.

Implementation: embed `snippet_id` and `class` in a normalised key; cluster
findings with identical keys before surfacing to the Report stage.

---

## Stage 7 — Trace

For confirmed findings in **shared libraries**: fan out one tracer agent per
consumer repository. Determines reachability from each consumer's external
attack surface. Unreachable → deprioritize. Reachable → escalate to Feedback.

Tracer agent receives: the confirmed finding, the consumer repo's snippet DB,
and a `SECURITY_CONTEXT.md` for the consumer. Output: `reachable: true/false`
with a call path if reachable.

---

## Stage 8 — Feedback

Reachable traces become new Hunt tasks in consumer repos, closing the cross-repo
propagation loop. Feedback tasks are structurally identical to Stage 3 hunter
tasks; the only difference is the originating finding is pre-loaded in the
context pack as a `known_entry` rather than discovered during hunting.

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
