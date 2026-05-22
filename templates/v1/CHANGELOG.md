# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-05-22

### Added
- Initial release: 15-stage AI vulnerability research pipeline
- Multi-agent Hunt/Validate architecture with LLM-based vulnerability discovery
- Ingestor, Recon, Coordinator, Gapfill, Voting, Shield, Suppressions, Chains, PoC, Trace, Exposure, Feedback, Report stages
- Deterministic (non-LLM) stages for deduplication, prioritization, and report generation
- Full test suite with ~730 tests (>75% coverage)
- Linting and type checking via prospector (ruff + mypy + pylint)

[0.1.0]: https://github.com/daroclj/ai-vuln-harness/releases/tag/v0.1.0
