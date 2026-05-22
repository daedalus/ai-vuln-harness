# AGENTS.md — ai-vuln-harness

## Overview

Multi-agent vulnerability research harness following the Project Glasswing / Cloudflare methodology. 15-stage pipeline from repo ingestion to structured security report. Designed to be copied as a template (`templates/v1/`) and pointed at any C/C++ codebase.

## Commands

| Command | Description |
|---------|------------|
| `cd templates/v1 && python run.py --mode full --target /path/to/repo` | Run full pipeline |
| `cd templates/v1 && python -m pytest tests/ -q` | Run test suite |
| `cd templates/v1 && ruff format stages/ run.py` | Format code |
| `cd templates/v1 && prospector --with-tool ruff --with-tool mypy .` | Lint + type check |
| `cd templates/v1 && semgrep --config=auto --severity=ERROR .` | Security scanning |
| `cd templates/v1 && vulture --min-confidence 90 .` | Dead code detection |

## Development

```bash
cd templates/v1
pip install -e ".[test]" --quiet
pytest -v
ruff format stages/ run.py
prospector --with-tool ruff --with-tool mypy .
```

## Testing

- ~730 tests across 30+ test files in `templates/v1/tests/`
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
INGESTOR → RECON → COORDINATOR → HUNT → VALIDATE → GAPFILL → VOTING →
SHIELD → SUPPRESSIONS → CHAINS → POC → TRACE → EXPOSURE → FEEDBACK → REPORT
```

Only HUNT and VALIDATE call LLMs. All other stages are deterministic logic.

## Key Principles

- Never survey the target repo directly — the pipeline's INGESTOR and RECON are the only authorized surveyors
- Never edit the template in place — copy it first: `cp -a templates/v1/ ./my-harness/`
- Track KPIs: precision@top-N, reject rate, duplicate rate, gap-closure rate
- Maintain a benchmark corpus + regression gate for prompt/model updates
