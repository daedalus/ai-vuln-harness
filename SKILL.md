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

## Canonical pipeline stages

`INGESTOR → RECON → COORDINATOR → HUNT → VALIDATE → GAPFILL → VOTING → SHIELD → SUPPRESSIONS → CHAINS → POC → TRACE → EXPOSURE → FEEDBACK → REPORT`

See `stages/contracts.py` → `PIPELINE_STAGES` for the ordered list and `run.py` docstring for the overview.

## Critical: never survey the target yourself

The harness is the **only** authorized surveyor of the target codebase.
**Do not** read, explore, grep, or analyze the target repo yourself.
The harness's INGESTOR and RECON stages handle this. Pre-reading the target
contaminates the eval by leaking context that should only flow through
the pipeline.

## Runnable scaffold (v1)

Template root: `/home/dclavijo/.opencode/skills/ai-vuln-harness/templates/v1/`

**IMPORTANT: Never edit the template in place.** Before making changes,
copy the entire `templates/v1/` directory to your working directory first:

```
cp -a /home/dclavijo/.opencode/skills/ai-vuln-harness/templates/v1/ ./my-harness/
```

Then edit the copy. The template includes `run.py`, `stages/`, `prompts/`,
`schemas/`, `tests/`, and `config/`. See `run.py` docstring for CLI flags.

## Dependency checking

See `run.py` → `_check_deps()` and `references/dependencies.md`.

## Required operating defaults

See `config/defaults.json` + stage docstrings and `references/operating-defaults.md`.

## Progress tracking

Maintain a live `todowrite` task list throughout the session with states
`pending` / `in_progress` / `completed`. Mark completed only after verification.

## Logging facilities

See `stages/runtime.py` docstring (dual-channel stderr/stdout, log levels,
stage entry/exit, model call timing, bad model tracking, parallel progress)
and `references/logging.md`.

## Harness integrity

See `stages/contracts.py` docstring for stage contracts, `tests/test_invariants.py`
for enforced invariants, and `references/invariants.md` for the full list.

## Evaluation and operator guidance

- Track KPIs: precision@top-N, reject rate, duplicate rate, gap-closure rate, time/cost per stage (see `run.py` docstring).
- Maintain benchmark corpus + regression gate for prompt/model updates.
- Keep troubleshooting playbooks for 429 storms, empty model outputs, schema repair loops, auth key nesting, and truncated validate responses.

## Deep references

- `references/stages.md` — stage-by-stage design guidance
- `references/operation.md` — implementation gotchas and operational notes
- `references/implementation.md` — implementation sketches and patterns
- `references/schemas.md` — canonical schema expectations
- `references/logging.md` — logging conventions and setup
- `references/dependencies.md` — dependency checking and startup verification
- `references/operating-defaults.md` — required operating defaults
- `references/invariants.md` — harness integrity invariants (pass/fail)
