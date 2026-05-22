# AI Vuln Harness Template (v1)

Runnable scaffold for a 15-stage AI vulnerability harness.

## Layout

- `run.py` — CLI entrypoint with run modes (`full`, `max-run`, `validate-only`, `resume`, `diff`, `all`, `poc-only`, `benchmark`)
- `stages/` — stage implementations and shared runtime utilities
- `prompts/` — versioned prompt templates
- `schemas/` — required JSON schemas for stage outputs
- `tests/` — parser and stage contract tests
- `config/defaults.json` — default operator profile
- `config/benchmark_corpus.json` — fixed benchmark corpus targets
- `config/benchmark_thresholds.json` — KPI regression thresholds
- `config/benchmark_baselines.json` — per-profile benchmark baselines

## Quick start

```bash
cd ai-vuln-harness
python -m unittest discover -s tests -p 'test_*.py'
python run.py --mode full --repo /path/to/repo
```

## Benchmark regression gate

Run benchmark mode to compare KPI deltas against stored per-profile baselines:

```bash
python -m ai_vuln_harness.run \
  --mode benchmark \
  --repo /path/to/repo \
  --benchmark-corpus src/ai_vuln_harness/config/benchmark_corpus.json \
  --benchmark-baseline src/ai_vuln_harness/config/benchmark_baselines.json \
  --benchmark-thresholds src/ai_vuln_harness/config/benchmark_thresholds.json \
  --benchmark-output output/benchmark_regression_report.json
```

If no baseline exists (or you intentionally want to accept a new baseline), run:

```bash
python -m ai_vuln_harness.run --mode benchmark --repo /path/to/repo --update-benchmark-baseline
```

The output artifact includes both machine-readable comparison fields and a human summary in `summary_markdown`.

## Design defaults

- Library target hardening: default directory exclusion and target-aware tags
- Recon-driven Coordinator: no full DB fallback unless `--allow-full-db-fallback`
- Strict contracts: schema validation + bounded repair turns
- Reliability: sync path default, disjoint hunt/validate pools, JSON cache, SQLite state DB
- Validate/Trace policy: code-in-prompt and trace-required promotion for library targets
- Validate runtime check: C/C++ `unvalidated_vulnerable_snippet` snippets can be recompiled and executed (optionally via container/qemu wrapper) to capture real PoC signals
