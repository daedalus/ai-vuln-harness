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

## Canonical pipeline stages:
- INGESTOR → RECON → COORDINATOR → HUNT → VALIDATE → GAPFILL → VOTING → SHIELD → SUPPRESSIONS → CHAINS → POC → TRACE → EXPOSURE → FEEDBACK → REPORT

## Critical: never survey the target yourself

The harness is the **only** authorized surveyor of the target codebase.
**Do not** read, explore, grep, or analyze the target repository yourself.
The harness's INGESTOR and RECON stages handle this — they parse the repo
through tree-sitter, build snippet databases, and construct context packs.

If you pre-read the target, you contaminate the eval: you leak context to
yourself that should only flow through the harness pipeline. It also means
you're forming opinions before the pipeline runs, which defeats the purpose
of a blind, reproducible multi-agent pipeline.

**Rule**: If you need to understand the target, run the harness. Never read
it directly, even to "help" or "verify" something.

## Runnable scaffold (v1)

The executable reference scaffold lives at:

- `/home/dclavijo/.opencode/skills/ai-vuln-harness/templates/v1`.

**IMPORTANT: Never edit the template in place.** Before making any changes,
copy the entire `templates/v1/` directory to your working directory first:

```
cp -a /home/dclavijo/.opencode/skills/ai-vuln-harness/templates/v1/ ./my-harness/
```

Then edit the copy (`./my-harness/`). This preserves the reference template
for reuse and multiple projects.

It includes:

- `run.py` with run modes: `full`, `max-run`, `validate-only`, `resume`, `diff`, `all`
  - `--auth-json PATH` — override auth.json location (default: script-relative, then `~/.local/share/opencode/auth.json`)
  - `--kl-threshold FLOAT` — KL-divergence cutoff for hallucination detection (default: 5.0)
  - `--cosine-threshold FLOAT` — cosine similarity cutoff for semantic dedup (default: 0.85)
  - `--base-commit REF` — base commit/ref for diff-driven scanning (required with `--mode diff`; optional with `--mode all`)
  - `--head-commit REF` — head commit/ref for diff-driven scanning (default: `HEAD`)
  - `all` mode runs every other mode in sequence and returns a deduplicated merged report; `diff` is included only when `--base-commit` is provided
- Stage modules under `stages/` with reliability and policy defaults
  - `stages/poc.py` — auto-generates C PoCs, compiles, runs under AddressSanitizer, and produces verdicts
  - `stages/diff.py` — incremental / diff-driven scanning: re-scans only functions whose line ranges overlap with `git diff BASE HEAD`
- Prompt templates under `prompts/`
- Required JSON schemas under `schemas/`
  - `schemas/poc-schema.json` — schema for reproducible PoC JSON output
- Unit tests under `tests/`
- Operator config under `config/defaults.json`

## Dependency checking

See `references/dependencies.md` — required packages (`tree-sitter`,
`tree-sitter-c`, `tiktoken`), external binary (`gcc`), `_check_deps()`
startup verification, config validation, output directory probe, API
auth check, and dependency invariants.

## Required operating defaults

See `references/operating-defaults.md` — 15 required defaults covering
ingestor, recon, library-target hardening, stage contracts, quality gates,
reliability, model health, multi-provider routing, auth, proxy, PoC
confirmation, coordinator domains, chain graph key resolution, and cross-run
regression analysis.

## Progress tracking

Maintain a live `todowrite` task list throughout the session. Every step —
auditing, fixing, testing, updating docs — must be tracked. Use three states:
`pending`, `in_progress`, `completed`. Mark `completed` only after the work
is verified (code written, test passes, file saved). This prevents forgotten
half-finished tasks when context switches or interruptions occur.

## Logging facilities

See `references/logging.md` — dual-channel stderr/stdout, logger setup,
level conventions, stage entry/exit pattern, model call timing, bad model
tracking, and parallel worker progress.

## Harness integrity (strict creation rules)

See `references/invariants.md` — 7 invariant groups (structural, ingestor,
coordinator, chain, pipeline, model, quality gates) with pass/fail enforcement.
The template at `templates/v1/` is the reference implementation that satisfies
all invariants.

## Evaluation and operator guidance

- Track KPIs: precision@top-N, reject rate, duplicate rate, gap-closure rate, time/cost per stage.
- Maintain benchmark corpus + regression gate for prompt/model updates.
- Keep troubleshooting playbooks for 429 storms, empty model outputs, schema repair loops, auth key nesting, and truncated validate responses.

## Deep references

- `references/stages.md` — stage-by-stage design guidance
- `references/operation.md` — implementation gotchas and operational notes
- `references/implementation.md` — implementation sketches and patterns
- `references/schemas.md` — canonical schema expectations
- `references/logging.md` — logging conventions and setup
- `references/dependencies.md` — dependency checking and startup verification
- `references/operating-defaults.md` — 14 required operating defaults
- `references/invariants.md` — harness integrity invariants (pass/fail)
