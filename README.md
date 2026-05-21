# AI Vulnerability Research Harness

Multi-agent vulnerability discovery pipeline following the **Project Glasswing / Cloudflare methodology**. Turns LLM-assisted code audit from one-off prompts into reproducible, operational security operations.

## Overview

This pipeline implements the **Hunt → Validate → Dedupe → Trace → PoC** pattern to discover, confirm, and chain vulnerabilities in C/C++ codebases at scale. It uses dedicated agents for each stage, with adversarial validation, hallucination filtering, and automated PoC compilation under AddressSanitizer.

## Pipeline Stages

```
INGESTOR → RECON → COORDINATOR → HUNT → VALIDATE → GAPFILL → VOTING → SHIELD → SUPPRESSIONS → CHAINS → POC → TRACE → EXPOSURE → FEEDBACK → REPORT
```

| Stage | Purpose |
|---|---|
| **INGESTOR** | AST-based C/C++ chunking via tree-sitter, deterministic sha256 IDs, security tag assignment |
| **RECON** | Repository mapping, subsystem identification, entry point discovery, prioritized hunt task generation |
| **COORDINATOR** | Context pack assembly across 11 security domains (mem-safety, auth, crypto, IPC, etc.) |
| **HUNT** | Per-domain vulnerability hunter agents, multi-provider model routing |
| **VALIDATE** | Independent adversarial validation with disjoint model pool — tries to disprove each finding |
| **GAPFILL** | Re-queues domains with zero confirmed findings (max 2 iterations) |
| **VOTING** | Merges multiple hunter outputs, promotes findings appearing in ≥2 independent runs |
| **SHIELD** | Quality gates: call-path verification, KL-divergence hallucination detection, static reachability BFS |
| **SUPPRESSIONS** | Persistent false-positive registry — known FPs auto-filtered on subsequent scans |
| **CHAINS** | BFS-based exploit chain detection where multiple findings compose into higher-severity scenarios |
| **POC** | Compile + run under AddressSanitizer to confirm or reject findings |
| **TRACE** | Per-consumer reachability fan-out for shared library findings |
| **EXPOSURE** | Computes exposure window (first-seen commit to fix date) for each finding |
| **FEEDBACK** | Seeds new Hunt tasks from confirmed findings into sibling files |
| **REPORT** | Buckets findings (`fix_now` / `backlog` / `false_positive`), generates structured report |

## Usage

This is an **opencode skill**. Load it with:

```
/skill ai-vuln-harness
```

Then scaffold a new harness from the template:

```
cp -a /home/dclavijo/.opencode/skills/ai-vuln-harness/templates/v1/ ./my-harness/
```

Run the pipeline:

```
python run.py --mode full --target /path/to/repo
```

### Run Modes

| Mode | Description |
|---|---|
| `full` | Complete pipeline from ingestor through report |
| `max-run` | Full pipeline with maximum model concurrency |
| `validate-only` | Re-run validation on existing findings |
| `resume` | Resume from a cached state DB |
| `poc-only` | Compile and run PoCs without re-scanning |

## Design Philosophy

- **Never survey the target yourself** — the harness is the only authorized surveyor of the target codebase. Pre-reading the target leaks context and contaminates the eval.
- **Adversarial validation** — the Validate stage uses a different (stronger) model than Hunt and actively tries to disprove every finding.
- **Disjoint model pools** — Hunt and Validate never share a model, preventing confirmation bias.
- **Hallucination gates** — three-layer Shield filter catches hallucinated findings before they reach the chainer.
- **Reproducible PoCs** — every finding gets a compiled, ASan-instrumented test case, not just a description.

## Repository Structure

```
ai-vuln-harness/
├── GAP.md                          # Gap analysis vs. Project Glasswing / GPT-5.5-Cyber
├── SKILL.md                        # opencode skill definition
├── README.md                       # this file
├── references/                     # deep design and operational references
│   ├── stages.md                   # stage-by-stage design guidance
│   ├── operation.md                # implementation gotchas
│   ├── implementation.md           # implementation patterns
│   ├── schemas.md                  # canonical schema expectations
│   ├── logging.md                  # logging conventions
│   ├── dependencies.md             # dependency checking
│   ├── operating-defaults.md       # required operating defaults
│   └── invariants.md               # harness integrity invariants
├── schemas/
│   └── poc-schema.json             # PoC document schema
└── templates/
    └── v1/                         # scaffold template (copy, don't edit in place)
        ├── run.py                  # CLI entry point
        ├── stages/                 # 15 pipeline stage modules
        ├── prompts/                # system prompts per LLM stage
        ├── schemas/                # JSON schemas for stage contracts
        ├── config/                 # defaults, model pools, stage config
        ├── tests/                  # 31 test files (unit + adversarial + invariants)
        └── docs/                   # evaluation and operations guides
```

## Key References

- [Project Glasswing — Anthropic](https://www.anthropic.com/project/glasswing)
- [Scaling Trusted Access for Cyber with GPT-5.5 and GPT-5.5-Cyber — OpenAI](https://openai.com/index/gpt-5-5-with-trusted-access-for-cyber/)
- [`GAP.md`](./GAP.md) — gap analysis and priority roadmap
- [`references/stages.md`](./references/stages.md) — detailed stage design
- [`references/invariants.md`](./references/invariants.md) — harness integrity rules
