# Harness Integrity (Strict Creation Rules)

A harness built with this skill is not valid unless all of the following hold.
These are pass/fail checks, not recommendations.

See `tests/test_invariants.py` for the automated test suite and each stage
module docstring (in `stages/`) for the canonical rationale.

## Structural invariants

- Every stage is a standalone module under `stages/` with a clean import path.
- `run.py` is the only entry point. It imports stages, it does not implement them.
- `config/defaults.json` drives all model/provider/output-path configuration.
- `prompts/` has one markdown file per stage that makes LLM calls.
- `schemas/` contains JSON schemas. Every stage validates output against schema.
- `tests/` has at least one test per stage module.
- `_check_deps()` is the first statement in `main()`, before argparse.

## Ingestor invariants

See `stages/ingestor.py` docstring:
- Deterministic sha256 IDs (no `hash()`, `id()`, `uuid.uuid4()`, `random`).
- C/C++: function-level via tree-sitter AST. Regex forbidden.
- Every snippet includes: `id`, `file`, `language`, `kind`, `name`, `lines`,
  `content`, `tags`, `token_count`, `callees`, `continuation`.
- Self-calls filtered from callee list.
- Multi-line function declarations detected (child_by_field_name fallback).

## Coordinator invariants

See `stages/coordinator.py` docstring:
- Exactly 11 domains with `DOMAIN_ORDER` and `exclusive` flag.
- `SECURITY_CONTEXT.md` embedded in every pack.
- 85% budget enforcement.

## Chain invariants

See `stages/chains.py` docstring:
- `build_chains()` resolves `snippet_id → function name` before BFS.
- `filter_unreachable()` accepts `snippet_db` parameter.
- Call graph keyed on lowercase function names, not snippet IDs.
- `call_path` must be `list[str]` before Shield stage.

## Pipeline invariants

- Pipeline stages follow the canonical order (`PIPELINE_STAGES` in `contracts.py`).
- Gapfill loop exists (2 iterations max) with model rotation + rephrased prompt.
- `output/validated.jsonl` written after Validate.
- `--validate-only` loads cached findings + gaps.

## Model invariants

See `stages/runtime.py` docstring:
- Hunt and Validate use disjoint model pools. Strongest model → Validate.
- `MODEL_BY_DOMAIN` populated from `config/defaults.json` at runtime.
- Health check before first API call. Dead models removed.
- `--skip-health` flag for cached re-runs.

## Quality gates

See `stages/shield.py` docstring:
- Every finding passes Shield before Chainer: call-path verification,
  hallucination detection, static reachability.
- `call_path_verified: true` required for chaining.
- `hallucination_detected: true` findings not reported.
- `static_reachability: unreachable` not reported for library targets
  (unless CRITICAL).

## Enforcement

Any harness violating any of the above is not an ai-vuln-harness and must
be rewritten. The template at `templates/v1/` is the reference implementation.
When in doubt, diff against it.
