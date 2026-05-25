# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **PATCH stage** (`stages/patch.py`): deterministic remediation co-pilot that generates structured `PatchCandidate` records for every confirmed finding. Each record carries a class-driven fix strategy, CWE identifier, the vulnerable code region, and a PoC-based verification plan. Addresses the "remediation bottleneck" highlighted by the Project Glasswing initial update — where >99% of discovered vulnerabilities remained unpatched weeks after disclosure.
- `--run-patch` CLI flag and `run_patch_enabled` parameter for `run()` / `run_all()` to enable the PATCH stage.
- Patch candidates are persisted to `output/patch_candidates.jsonl` and included in the pipeline report under `patch_candidates`.

## [0.1.0] - 2026-05-21

### Added
- Initial release
- 15-stage pipeline: INGESTOR → RECON → COORDINATOR → HUNT → VALIDATE → GAPFILL → VOTING → SHIELD → SUPPRESSIONS → CHAINS → POC → TRACE → EXPOSURE → FEEDBACK → REPORT
- AST-based C/C++ chunking via tree-sitter
- Multi-provider LLM routing with model pool
- Adversarial validation with disjoint model pools
- KL-divergence hallucination detection and cosine similarity dedup
- Static call-graph reachability (BFS)
- Exploit chain synthesis
- Automated PoC compilation under AddressSanitizer
- Exposure window computation from git history
- Persistent false-positive suppression registry
- 730+ tests across 30+ test files

[0.1.0]: https://github.com/daedalus/ai-vuln-harness/releases/tag/v0.1.0
