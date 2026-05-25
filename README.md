# ai-vuln-harness

[![Python](https://img.shields.io/pypi/pyversions/ai-vuln-harness.svg)](https://pypi.org/project/ai-vuln-harness/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/master/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

Multi-agent vulnerability research harness — 15-stage pipeline from repo ingestion to structured security report, following the Project Glasswing / Cloudflare methodology.

## Install

```bash
pip install ai-vuln-harness
```

## Usage

```bash
python -m ai_vuln_harness --mode full --repo /path/to/repo
```

```python
from ai_vuln_harness import run, run_all

# Single mode
report = run("full", "/path/to/repo")

# All modes merged
report = run_all("/path/to/repo")
```

## Pipeline

```
INGESTOR → RECON → COORDINATOR → HUNT → VALIDATE → GAPFILL → VOTING →
SHIELD → SUPPRESSIONS → CHAINS → POC → TRACE → EXPOSURE → FEEDBACK → REPORT
```

Only HUNT and VALIDATE call LLMs — all other stages are deterministic logic.

## Design defaults

- **Library target hardening**: default directory exclusion and target-aware tags
- **Recon-driven Coordinator**: no full DB fallback unless `--allow-full-db-fallback`
- **Strict contracts**: schema validation + bounded repair turns
- **Reliability**: sync path default, disjoint hunt/validate pools, JSON cache, SQLite state DB
- **Validate/Trace policy**: code-in-prompt and trace-required promotion for library targets
- **Validate runtime check**: C/C++ snippets can be recompiled and executed (optionally via container/qemu wrapper) to capture real PoC signals

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

## Development

```bash
git clone https://github.com/daedalus/ai-vuln-harness.git
cd ai-vuln-harness
pip install -e ".[test]"

# run tests
pytest

# format
ruff format src/ tests/

# lint + type check
prospector --with-tool ruff --with-tool mypy --with-tool pylint src/ai_vuln_harness/
semgrep --config=auto --severity=ERROR src/ai_vuln_harness/

# dead code detection
vulture --min-confidence 90 src/ai_vuln_harness/ --exclude src/ai_vuln_harness/.vulture_whitelist.py
```

## API

| Symbol | Description |
|--------|------------|
| `run(mode, repo, **kwargs)` | Run a single pipeline mode |
| `run_all(repo, **kwargs)` | Run all modes and merge reports |
| `main()` | CLI entry point |

## CLI

```bash
python -m ai_vuln_harness --help
```
