---
name: ai-vuln-harness
description: >
  Design and implement multi-agent vulnerability research harnesses following
  the Project Glasswing / Cloudflare methodology. Use this skill when building
  or improving Hunt/Validate/Dedupe/Trace security pipelines, reducing false
  positives in AI vuln scanning, or operationalizing large-scale LLM-assisted
  code audit workflows.
---

# AI Vulnerability Research Harness

High-level guide for building a production-style AI vulnerability harness.

## Use this skill for

- Multi-agent vulnerability discovery pipelines
- Adversarial validation workflows
- Reachability-driven triage and exploit chaining
- Hardening AI scanner signal-to-noise
- Turning one-off prompts into reproducible security operations

## Runnable scaffold (v1)

Use the executable reference scaffold at:

- `/home/runner/work/skills/skills/skills/ai-vuln-harness/templates/v1`

It includes:

- `run.py` with run modes: `full`, `max-run`, `validate-only`, `resume`
- Stage modules under `stages/` with reliability and policy defaults
- Prompt templates under `prompts/`
- Required JSON schemas under `schemas/`
- Unit tests under `tests/`
- Operator config under `config/defaults.json`

## Required operating defaults

1. Recon output drives coordinator pack generation
   - Full-DB fallback is opt-in only.
2. Library-target hardening is on by default
   - Exclude `test/`, `examples/`, `contrib/` from snippet selection.
   - Use target-aware external-input and integer-arith tagging.
3. Stage contracts are mandatory
   - Validate outputs against schemas before stage handoff.
   - Apply bounded repair turns for malformed outputs.
4. Validate/Trace quality gates
   - Validate prompts must include source code looked up by `snippet_id`.
   - API-by-design patterns are rejected or downgraded.
   - Library findings require Trace confirmation before `fix_now`.
5. Reliability and reproducibility are first-class
   - Sync model request path as default.
   - Disjoint Hunt and Validate model pools.
   - Persistent cache + resumable state DB.

## Evaluation and operator guidance

- Track KPIs: precision@top-N, reject rate, duplicate rate, gap-closure rate, time/cost per stage.
- Maintain benchmark corpus + regression gate for prompt/model updates.
- Keep troubleshooting playbooks for 429 storms, empty model outputs, schema repair loops, and auth key nesting.

## Deep references

- `references/stages.md` — stage-by-stage design guidance
- `references/operation.md` — implementation gotchas and operational notes
- `references/implementation.md` — implementation sketches and patterns
- `references/schemas.md` — canonical schema expectations
