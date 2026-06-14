# ai-vuln-harness

[![Python](https://img.shields.io/pypi/pyversions/ai-vuln-harness.svg)](https://pypi.org/project/ai-vuln-harness/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/master/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/daedalus/ai-vuln-harness)

Multi-agent vulnerability research harness — 15-stage pipeline from repo ingestion to structured security report, following the Project Glasswing / Cloudflare methodology.

## Install

```bash
pip install ai-vuln-harness

# With search/embeddings support
pip install "ai-vuln-harness[search]"
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

## CVE corpus & semantic suppression

The harness builds a corpus of known CVEs to serve as negative examples. Findings matching known CVEs are automatically suppressed — they're not zero days.

### Sources

1. **Manual corpus** — JSON file passed via `--cve-corpus path/to/cves.json`
2. **OSV.dev auto-fetch** — scans manifest files for known vulnerabilities
3. **Git history scan** — scans commits for CVE references

### Semantic suppression (6-layer)

The `suppress_known_cves()` function uses embedding cosine similarity to detect findings describing the same vulnerability as a known CVE, even when wording differs:

| Layer | What | How |
|-------|------|-----|
| 1. Exact CVE ID | Fast path | String match, no embeddings |
| 2. Two-pass matching | Class-prefilter → semantic | Build class→indices map, FAISS within class |
| 3. Class-match boost | Same-class = easier match | Threshold 0.45 (same) vs 0.85 (diff) |
| 4. Rich encoding | CWE + file + function | Includes all fields for embedding |
| 5. Hard negatives | Different file/function → skip | Prevents false suppressions |
| 6. Confidence scoring | 0.0–1.0 with boosts | Auto-suppress ≥0.9, flag-review ≥0.7 |

### Control flags

| Flag | Effect |
|------|--------|
| `--cve-corpus PATH` | Load a manual corpus JSON file |
| `--no-fetch-cves` | Skip OSV.dev auto-fetch |
| `--no-scan-git-cves` | Skip git history scan |

## Zero-day hunting mode

Optimize the pipeline for discovering novel vulnerabilities:

```bash
python -m ai_vuln_harness --mode full --repo /path/to/repo --zero-day
```

`--zero-day` disables features that bias toward known bugs or add noise:

| Disabled | Why |
|----------|-----|
| Exposure tracking | Time-to-fix irrelevant for discovery |
| Feedback loop | Cross-run regression is for known bugs |
| RAG KB enrichment | CWE pattern matching → known weaknesses |
| Evidence collection | Metadata overhead, no find-rate impact |

`--zero-day` **keeps**: gapfill, chains, shield, suppressions, CVE corpus (as negatives).

Individual flags for fine-grained control:

| Flag | Effect |
|------|--------|
| `--no-gapfill` | Skip gapfill loop |
| `--no-chains` | Skip chain synthesis |
| `--no-exposure` | Skip exposure tracking |
| `--no-feedback` | Skip feedback loop |
| `--no-cve-corpus` | Skip CVE corpus loading |
| `--no-rag-kb` | Skip RAG KB enrichment |
| `--no-evidence` | Skip evidence collection |

## Semantic dedup in voting

When `--enable-embeddings` is set, the VOTING stage merges semantically similar findings across hunter runs using embedding cosine similarity:

```bash
python -m ai_vuln_harness --mode full --repo /path --enable-embeddings
```

Two findings describing the same vulnerability at different lines merge into one, even if their surface keys differ.

## FTS5-backed suppressions

Enable fuzzy matching for suppressions that survive line-number shifts:

```bash
python -m ai_vuln_harness --mode full --repo /path --enable-fts-suppressions
```

## Findings database

Persistent, queryable findings DB for cross-run search:

```bash
python -m ai_vuln_harness --mode full --repo /path \
  --enable-findings-db output/findings.db \
  --persist-findings --historical-context
```

## Output content review gate

Blocks weaponizable exploit content (shellcode, reverse shells, ROP chains) from reports:

```bash
python -m ai_vuln_harness --mode full --repo /path --enable-output-review
python -m ai_vuln_harness --mode full --repo /path --enable-output-review --output-review-risk-level strict
```

## CVE-to-exploit synthesis

Generate exploit templates from CVE IDs:

```python
from ai_vuln_harness.stages.cve_exploit_synthesis import synthesize_and_write
from pathlib import Path

record = synthesize_and_write(
    "CVE-2024-12345",
    Path("output/exploit"),
    cwe="CWE-120",
    severity="HIGH",
)
```

Supported classes: buffer overflow, format string, command injection, SQL injection, path traversal, and more.

## Model refusal handling

The harness detects and retries on LLM refusals:

- **Detection**: 16 regex patterns covering OpenAI, Anthropic, generic, and Chinese model refusals
- **Retry**: Up to 2 retries with exponential backoff (5s, 10s)
- **Prompt mutation**: Each retry rewrites the prompt with a security-research framing preamble
- **Logging**: Refusals logged at WARNING level with per-model counters

## Benchmark regression gate

```bash
python -m ai_vuln_harness.run \
  --mode benchmark \
  --repo /path/to/repo \
  --benchmark-corpus src/ai_vuln_harness/config/benchmark_corpus.json \
  --benchmark-baseline src/ai_vuln_harness/config/benchmark_baselines.json \
  --benchmark-thresholds src/ai_vuln_harness/config/benchmark_thresholds.json \
  --benchmark-output output/benchmark_regression_report.json
```

## Optional dependency groups

| Group | Packages | Purpose |
|-------|----------|---------|
| `search` | sentence-transformers, faiss-cpu, scikit-learn | Semantic dedup, fuzzy suppressions, CVE suppression |
| `solver` | z3-solver | Formal verification in VALIDATE |
| `sandbox` | llm-sandbox[mcp-docker] | Docker-isolated PoC execution |
| `cst` | tree-sitter + language grammars | Multi-language AST parsing |
| `pbt` | hypothesis | Property-based testing |

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

## Skill metadata discovery

```python
from ai_vuln_harness.skill_loader import discover_skills, load_skill_metadata

meta = load_skill_metadata()
skills = discover_skills()
custom = load_skill_metadata(name="my-skill")
```

`discover_skills()` returns the bundled skill plus any user-defined skills found
under `~/.ai-vuln-harness/skills/**/SKILL.md`. `load_skill_metadata(name=...)`
loads a discovered skill by its front matter `name`.

## CLI

```bash
python -m ai_vuln_harness --help
```
