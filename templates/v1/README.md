# AI Vuln Harness Template (v1)

Runnable scaffold for a 10-stage AI vulnerability harness.

## Layout

- `run.py` — CLI entrypoint with run modes (`full`, `max-run`, `validate-only`, `resume`)
- `stages/` — stage implementations and shared runtime utilities
- `prompts/` — versioned prompt templates
- `schemas/` — required JSON schemas for stage outputs
- `tests/` — parser and stage contract tests
- `config/defaults.json` — default operator profile

## Quick start

```bash
cd /home/runner/work/skills/skills/skills/ai-vuln-harness/templates/v1
python -m unittest discover -s tests -p 'test_*.py'
python run.py --mode full --repo /path/to/repo
```

## Design defaults

- Library target hardening: default directory exclusion and target-aware tags
- Recon-driven Coordinator: no full DB fallback unless `--allow-full-db-fallback`
- Strict contracts: schema validation + bounded repair turns
- Reliability: sync path default, disjoint hunt/validate pools, JSON cache, SQLite state DB
- Validate/Trace policy: code-in-prompt and trace-required promotion for library targets
- Validate runtime check: C/C++ `vulnerable_to_see` snippets can be recompiled and executed (optionally via container/qemu wrapper) to capture real PoC signals
