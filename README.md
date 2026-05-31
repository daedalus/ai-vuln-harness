# ai-vuln-harness

[![Python](https://img.shields.io/pypi/pyversions/ai-vuln-harness.svg)](https://pypi.org/project/ai-vuln-harness/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/master/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/daedalus/ai-vuln-harness)

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
INGESTOR → RECON → COORDINATOR → HUNT → LOCALIZATION → VALIDATE →
FUZZ_ORCHESTRATOR → GAPFILL → VOTING → SHIELD → SUPPRESSIONS → CHAINS →
POC → TRACE → EXPOSURE → FEEDBACK → REPORT
```

Only HUNT and VALIDATE call LLMs — all other stages are deterministic logic.

## Design defaults

- **Library target hardening**: default directory exclusion and target-aware tags
- **Recon-driven Coordinator**: no full DB fallback unless `--allow-full-db-fallback`
- **Strict contracts**: schema validation + bounded repair turns
- **Reliability**: sync path default, disjoint hunt/validate pools, JSON cache, SQLite state DB
- **Validate/Trace policy**: code-in-prompt and trace-required promotion for library targets
- **Validate runtime check**: C/C++ snippets can be recompiled and executed (optionally via container/qemu wrapper and valgrind in fuzz orchestrator) to capture real PoC signals

## CVE corpus

The harness builds a corpus of known CVEs to serve as negative examples — the HUNT stage is instructed not to report them as new findings. Three sources feed into the corpus:

1. **Manual corpus** — JSON file passed via `--cve-corpus path/to/cves.json`. Each entry requires a `cve_id` field; `class`, `description`, `file`, `function`, `severity` are optional.
2. **OSV.dev auto-fetch** — enabled by default. Scans manifest files (`package.json`, `Cargo.toml`, `go.mod`, `requirements.txt`, `Gemfile`, etc.) and raw import statements for dependency names, queries the [OSV.dev batch API](https://osv.dev) for known vulnerabilities, and maps CVE classes to domains via a 31-class taxonomy.
3. **Git history scan** — enabled by default in git repos. Scans all commits via `git log --all` and all branches via `git branch -a` for CVE references (e.g. `CVE-2024-1234`), extracts the full diff/patch for matching commits, and hydrates entries with `commit_hash`, `commit_message`, `commit_author`, `commit_date`, `branch`, and `diff` fields.

Control with CLI flags:

| Flag | Effect |
|------|--------|
| `--cve-corpus PATH` | Load a manual corpus JSON file |
| `--no-fetch-cves` | Skip OSV.dev auto-fetch (use only manual corpus + git scan) |
| `--no-scan-git-cves` | Skip git history scan (use only manual corpus + OSV) |

Cached corpus entries use a SHA-256 fingerprint of the dependency list as cache key with a 24-hour TTL, so re-runs on unchanged repos hit the cache.

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
