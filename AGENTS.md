# AGENTS.md — ai-vuln-harness

## Overview

Multi-agent vulnerability research harness following the Project Glasswing / Cloudflare methodology. 15-stage pipeline from repo ingestion to structured security report.

## Commands

| Command | Description |
|---------|------------|
| `python run.py --mode full --target /path/to/repo` | Run full pipeline |
| `python -m pytest tests/ -q` | Run test suite |
| `ruff format src/ai_vuln_harness/ tests/` | Format code |
| `prospector --with-tool ruff --with-tool mypy --with-tool pylint src/ai_vuln_harness/` | Lint + type check |
| `semgrep --config=auto --severity=ERROR src/` | Security scanning |
| `vulture --min-confidence 90 src/` | Dead code detection |

## Development

```bash
pip install -e ".[test]" --quiet
pytest -v
ruff format src/ai_vuln_harness/ tests/
prospector --with-tool ruff --with-tool mypy --with-tool pylint src/ai_vuln_harness/
```

## Testing

- ~730 tests across 30+ test files in `tests/`
- Tests use `unittest.TestCase` with `unittest.mock.patch` for LLM calls
- No external dependencies required for tests (all LLM calls mocked)
- Run with: `python -m pytest tests/ -q`

## Code Style

- Format: `ruff format` (line-length 88, py311 target)
- Lint + Type check: `prospector` (ruff check + mypy)
- No `# noqa` without a documented reason
- Google-style docstrings enforced by ruff

## Pipeline Stages

```
INGESTOR → RECON → COORDINATOR → HUNT → LOCALIZATION → VALIDATE →
FUZZ_ORCHESTRATOR → GAPFILL → VOTING → SHIELD → SUPPRESSIONS → CHAINS →
POC → TRACE → EXPOSURE → FEEDBACK → REPORT
```

Only HUNT and VALIDATE call LLMs. All other stages are deterministic logic.

## Key Principles

- Never survey the target repo directly — the pipeline's INGESTOR and RECON are the only authorized surveyors
- Track KPIs: precision@top-N, reject rate, duplicate rate, gap-closure rate
- Maintain a benchmark corpus + regression gate for prompt/model updates
