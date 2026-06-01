---
name: ai-vuln-harness
description: >
  Design and implement multi-agent vulnerability research harnesses following
  the Project Glasswing / Cloudflare methodology. Use this skill when building
  or improving Hunt/Validate/Dedupe/Trace security pipelines, reducing false
  positives in AI vuln scanning, or operationalizing large-scale LLM-assisted
  code audit workflows.
version: "1.0.0"
entry_point: "src/ai_vuln_harness"
mcp_server: "ai-vuln-harness-mcp"
---

# AI Vulnerability Research Harness

High-level guide for building a production-style AI vulnerability harness.

## Use this skill for

- Multi-agent vulnerability discovery pipelines
- Adversarial validation workflows
- Reachability-driven triage and exploit chaining
- Hardening AI scanner signal-to-noise
- Turning one-off prompts into reproducible security operations
- MCP-native integration with AI IDEs (Cursor, VS Code Claude extension)

## Canonical pipeline stages

`INGESTOR → RECON → COORDINATOR → HUNT → LOCALIZATION → VALIDATE → FUZZ_ORCHESTRATOR → GAPFILL → VOTING → SHIELD → SUPPRESSIONS → CHAINS → POC → TRACE → EXPOSURE → FEEDBACK → REPORT`

See `stages/contracts.py` → `PIPELINE_STAGES` for the ordered list and `run.py` docstring for the overview.

## Critical: never survey the target yourself

The harness is the **only** authorized surveyor of the target codebase.
**Do not** read, explore, grep, or analyze the target repo yourself.
The harness's INGESTOR and RECON stages handle this. Pre-reading the target
contaminates the eval by leaking context that should only flow through
the pipeline.

## Installation

```bash
pip install -e ".[all]"
```

## CLI usage

```bash
# Full pipeline
python run.py --mode full --target /path/to/repo

# Run tests
python -m pytest tests/ -q

# Format
ruff format src/ai_vuln_harness/ tests/

# Lint + type check
prospector --with-tool ruff --with-tool mypy --with-tool pylint src/ai_vuln_harness/
```

## MCP server

The harness ships an MCP (Model Context Protocol) stdio server that exposes
the pipeline as tools consumable from any MCP-compatible IDE or agent framework
(Cursor, VS Code Claude extension, Claude Desktop, etc.):

```bash
# Start the MCP server (reads JSON-RPC 2.0 from stdin, writes to stdout)
ai-vuln-harness-mcp

# Or directly
python -m ai_vuln_harness.mcp_server
```

Exposed tools: `scan_repo`, `get_findings`, `get_report`, `list_run_modes`.

Configure in your IDE's MCP settings as a stdio server with command
`ai-vuln-harness-mcp` (no arguments needed).

## Programmatic skill metadata

```python
from ai_vuln_harness.skill_loader import load_skill_metadata
meta = load_skill_metadata()
# {'name': 'ai-vuln-harness', 'description': '...', 'version': '1.0.0', ...}
```

## Dependency checking

See `run.py` → `_check_deps()` and `docs/dependencies.md`.

## Required operating defaults

See `config/defaults.json` + stage docstrings and `docs/operating-defaults.md`.

## Progress tracking

Maintain a live `todowrite` task list throughout the session with states
`pending` / `in_progress` / `completed`. Mark completed only after verification.

## Logging facilities

See `stages/runtime.py` docstring (dual-channel stderr/stdout, log levels,
stage entry/exit, model call timing, bad model tracking, parallel progress)
and `docs/logging.md`.

## Harness integrity

See `stages/contracts.py` docstring for stage contracts, `tests/test_invariants.py`
for enforced invariants, and `docs/invariants.md` for the full list.

## Evaluation and operator guidance

- Track KPIs: precision@top-N, reject rate, duplicate rate, gap-closure rate, time/cost per stage (see `run.py` docstring).
- Maintain benchmark corpus + regression gate for prompt/model updates.
- Keep troubleshooting playbooks for 429 storms, empty model outputs, schema repair loops, auth key nesting, and truncated validate responses.

## Deep references

- `docs/stages.md` — stage-by-stage design guidance
- `docs/operation.md` — implementation gotchas and operational notes
- `docs/implementation.md` — implementation sketches and patterns
- `docs/schemas.md` — canonical schema expectations
- `docs/logging.md` — logging conventions and setup
- `docs/dependencies.md` — dependency checking and startup verification
- `docs/operating-defaults.md` — required operating defaults
- `docs/invariants.md` — harness integrity invariants (pass/fail)
