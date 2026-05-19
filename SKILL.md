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
tracing — following the audit harness implementation's 9-stage pipeline.

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
│ 2.Coordinator│  Build per-domain context packs (≤180K tokens)
└──────┬───────┘
       │ context packs
┌──────▼───────┐
│ 3.Hunt       │  One attack class per agent; compile/run PoCs
└──────┬───────┘
       │ raw findings (JSONL)
┌──────▼────────────┐
│ 4.Validate ◄─► Gapfill│  (inner loop)
└──────┬────────────┘
       │ confirmed findings
┌──────▼───────┐
│ 5.Dedupe     │  Cluster by root cause
└──────┬───────┘
       │ deduped findings
┌──────▼───────┐
│ 6.Chainer    │  Build exploit chains via call-graph BFS
└──────┬───────┘
       │ findings + chains
┌──────▼───────┐
│ 7.Trace      │  Prove attacker input reaches sink
└──────┬───────┘
       │ reachable findings
┌──────▼───────┐
│ 8.Feedback   │  Turn traces into new Hunt tasks
└──────┬───────┘
       │ new task queue
┌──────▼───────┐
│ 9.Report     │  Schema-validated structured output
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

### Stage 2 — Coordinator
Build per-domain context packs (mem-safety, auth, crypto, ipc, data-flow,
format-str) from tagged snippets. Packs capped at 180K tokens. Each pack
includes `SECURITY_CONTEXT.md`, cross-references, and scope notes.

See `references/stages.md` → Stage 2, `references/implementation.md` → coordinator.py.

### Stage 3 — Hunter Cluster
Parallel agents, one per domain pack. Each agent receives a scoped system
prompt ("one attack class, one scope") and emits zero or more findings as
JSONL. Implements dynamic model fallback chain, sync urllib, output parser
robust to model hallucination. Status to stderr, findings to stdout.

See `references/stages.md` → Stage 3, `references/implementation.md` → run_agents.py.

### Stage 4 — Validate + Gapfill
Adversarial re-read: a different model attempts to disprove each finding.
Requires system message (some models return empty without it) and curated
model chain. Coverage gaps are re-queued as new hunt tasks.

See `references/stages.md` → Stage 4.

### Stage 5 — Dedupe
Collapses findings on `(snippet_id, class)` composite key, keeping highest
severity. For deeper dedup, extend key to `(file, class, source_lines_start)`.

See `references/stages.md` → Stage 5.

### Stage 6 — Chainer
Builds exploit chains via call-graph BFS (≤4 hops). Scores candidates on
trust-boundary crossing, severity levels, and recent file modification.
Submits top chains to a reasoning agent for analysis.

See `references/stages.md` → Stage 6, `references/implementation.md` → chainer.py.

### Stage 7 — Trace
For shared-library findings: fan out tracer agents per consumer repo to
determine reachability from each consumer's attack surface.

See `references/stages.md` → Stage 7.

### Stage 8 — Feedback
Reachable traces become new Hunt tasks in consumer repos. The originating
finding is pre-loaded as `known_entry`.

See `references/stages.md` → Stage 8.

### Stage 9 — Report
Schema-validated structured output with triage buckets: fix_now, backlog,
false_positive. Agent self-validates before emitting.

See `references/stages.md` → Stage 9, `references/schemas.md` → Report schema.

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
|---|---|---|
| Recon | Highest capability | Comprehensive repo mapping |
| Hunt | Balanced | Parallel vulnerability hunting |
| Validate | Highest, different from Hunt | Deliberate disagreement |
| Gapfill | Same as Hunt | Coverage gap processing |
| Dedupe | Efficient | Record collapsing |
| Trace | Highest capability | "The stage that matters most" |
| Feedback | Same as Hunt | Task generation |
| Report | Same as Hunt | Structured output generation |

### Concurrency

| Stage | Concurrency | Notes |
|---|---|---|
| Recon | 1 | Foundational, can be lengthy |
| Hunt | 50 | Parallel hunting across many targets |
| Validate | 10 | Validating hunt outputs |
| Gapfill/Dedupe/Feedback/Report | 1 | Sequential or lightweight |
| Trace | 10 | Multiple consumer repos |

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

# 3. Coordinate — build per-domain context packs
python coordinator.py --db output/snippets.json --out output/packs/

# 4. Hunt — run parallel hunter agents (one per domain pack)
#    Uses dynamic model chain from OpenRouter API
python run_agents.py --packs output/packs/ --parallel 3 > output/findings.jsonl

# 5. Validate — adversarial re-read of findings
python validate.py > output/validated.jsonl

# 6. Dedupe — collapse duplicates on (snippet_id, class)
python dedupe.py > output/deduped.jsonl

# 7. Chain — build exploit chains via call-graph BFS
python chainer.py > output/chains.json

# 8. Report — structured report with triage buckets
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
| `--reingest` | false | Re-run ingestor even if snippets.json exists |
| `--no-cache` | false | Skip cache reads (force all API calls) |

### Output structure

```
output/
  cache.json        # LLM response cache (key: stage:model:hash)
  snippets.json     # extracted function snippets
  packs/            # mem-safety, auth, crypto, ipc, data-flow, format-str
  findings.jsonl    # raw findings with status:"raw" + poc_confirmed:false
  validated.jsonl   # findings with updated status + validate_reason
  deduped.jsonl     # collapsed on (snippet_id, class)
  chains.json       # exploit chains with scores
  report.json       # final triaged report
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
- [ ] Every finding has `status: "raw"` and `poc_confirmed: false` defaults
- [ ] Reasoning model `reasoning` field concatenated with `content`
- [ ] All status/log to stderr, findings JSONL to stdout
- [ ] Sync urllib pattern (not async httpx)
- [ ] `ThreadPoolExecutor` with 3-4 workers for parallel packs
- [ ] Coverage gaps emitted by hunters, re-queued for Gapfill
- [ ] Validate agent uses different prompt + model/routing-pool, no new-finding capability
- [ ] Dedupe on `(snippet_id, class)` composite key, keep highest severity
- [ ] Chainer uses call-graph traversal (BFS ≤4 hops) + scoring, not just co-occurrence
- [ ] PoC loop runs in isolated scratch environment, no production access (blocked for C/C++ without sandboxed compilation)
- [ ] Trace fans out per consumer repo for shared library findings
- [ ] Report schema defined; agent self-validates before emitting
- [ ] Library findings default to `backlog` unless CRITICAL (untraced)
- [ ] `--max-run N` flag for debugging single packs
- [ ] **Model fallback chain** — dynamic fetch from API, index into sorted chain, advance on 429
- [ ] **LLM response cache** — `stage:model:sha256(prompt)[:12]` key, JSON file, checked before every API call
- [ ] **System message in validate** — models return empty content without it
- [ ] `str.format()` **braces escaped** — use `{{` `}}` for literal JSON in system prompts
- [ ] **No `openrouter/free` routing alias** — use concrete model IDs from `/v1/models`
