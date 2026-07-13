# AGENTS.md — ai-vuln-harness

## Overview

Multi-agent vulnerability research pipeline following the Project Glasswing / Cloudflare methodology. 15-stage pipeline from repo ingestion to structured security report.

## Commands

| Command | Description |
|---------|------------|
| `python run.py --mode full --target /path/to/dir` | Run full pipeline on a directory (non-git) |
| `python run.py --mode full --repo /path/to/repo` | Run full pipeline on a git repo |
| `python run.py --mode full --repo /path --repo-head N` | Scan last N+1 commits only (0=HEAD) |
| `python -m pytest tests/ -q` | Run test suite |
| `ruff format src/ai_vuln_harness/ tests/` | Format code |
| `prospector --with-tool ruff --with-tool mypy --with-tool pylint src/ai_vuln_harness/` | Lint + type check |
| `semgrep --config=auto --severity=ERROR src/` | Security scanning |
| `vulture --min-confidence 90 src/` | Dead code detection |
| `lizard src/ --CCN=15` | Code complexity analysis |

## Pipeline Stages

INGESTOR → RECON → COORDINATOR → HUNT → LOCALIZATION → VALIDATE → FUZZ_ORCHESTRATOR → GAPFILL → VOTING → SHIELD → SUPPRESSIONS → [INDEPENDENT_VERIFY] → CHAINS → POC → TRACE → EXPOSURE → FEEDBACK → REPORT

`INDEPENDENT_VERIFY` is optional (enabled via `--enable-independent-verify`). When enabled, fresh agents verify every factual claim in confirmed findings against actual source code after suppressions and before chain synthesis.

## Recent Changes

- **Independent Verification Phase** (`--enable-independent-verify`): New optional stage between SUPPRESSIONS and CHAINS. Fresh agents verify file paths, line numbers, function names, execution payloads, and remediation code against source code. Catches blind spots that adversarial VALIDATE misses.
- **Prior-Run Awareness** (`--prior-findings PATH`): Load existing findings.json from prior runs. Hunters skip known findings and target coverage gaps. Can be specified multiple times.
- **12 Hunting Methodology Principles** (`hunt.md`): Added attacker-thinking framework (sad path, boundaries, component assumptions, wrong order, concurrent ops, parser disagreement, round-trip, config, privilege, leaked context, parameter overrides, unverified claims).
- **User-Agent fix** (`runtime.py:637`): Added `User-Agent: vuln-harness/1.0` header to LLM API calls. opencode.ai/Cloudflare blocks the default `Python-urllib/3.x` UA with HTTP 403.
- **cache indicator** (`run.py:801`): Hunt log lines now show `cache=HIT` or `cache=MISS` per pack.
- **`--repo-head N`** (`run.py:2498`): Limit scan to last N+1 commits. `0` = HEAD only, `1` = HEAD~1..HEAD. Converts to `base_commit="HEAD~{N+1}"` and reuses the existing diff filter.
- **`--target PATH`** (`run.py:2492`): Scan a directory directly, ignoring git structure. Sets `target_mode=True` which skips git diff filtering and CVE git scanning. Alternative to `--repo`; mutually exclusive.
- **CVE fetcher fix** (`cve_fetcher.py`): Fixed `NoneType` crash when OSV API returns `"vulns": null` — uses `entry.get("vulns") or []`.

## Key CLI Flags

- `--model "zen:nemotron-3-ultra-free"` — use opencode.ai free tier for HUNT
- `--validate-model "openrouter:nvidia/nemotron-3-super-120b-a12b:free"` — separate validate model
- `--max-run N` — limit hunt to N context packs
- `--load-packs-cache` — skip coordinator, reuse cached packs
- `--skip-health` — skip LLM health check on startup
- `--no-fetch-cves` — skip OSV.dev CVE fetching
- `--repo-head N` — limit to recent N+1 git commits
- `--enable-independent-verify` — enable independent verification phase
- `--prior-findings PATH` — load prior findings.json (repeatable)

## Model Providers

- `zen:` prefix → `https://opencode.ai/zen/v1` (free tier, auth key `"public"`)
- `openrouter:` prefix → OpenRouter API
- Auth via `auth.json` in script dir or env vars (`ZEN_API_KEY`, `OPENROUTER_API_KEY`, etc.)
