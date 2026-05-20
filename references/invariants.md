# Harness Integrity (Strict Creation Rules)

A harness built with this skill is not valid unless all of the following hold.
These are pass/fail checks, not recommendations.

## Structural invariants

- Every stage is a standalone module under `stages/` with a clean import path.
  No mega-scripts. No logic hidden in `run.py`.
- `run.py` is the only entry point. It imports stages, it does not implement them.
- `config/defaults.json` exists and drives all model/provider/output-path configuration.
  Zero hardcoded model IDs in `.py` files. Zero hardcoded output paths in `.py` files.
- `prompts/` contains one markdown file per stage that makes LLM calls
  (hunt, recon, validate, trace, report at minimum).
- `schemas/` contains JSON schemas for snippet, finding, context-pack, recon-task,
  and report. Every stage validates its output against the corresponding schema.
- `tests/` exists with at least one test per stage module.
- `_check_deps()` is called as the first statement in `main()`, before
  argparse or any import of optional packages. If it is not, the harness
  is invalid: silent failures on missing `gcc`, broken config, or unwritable
  output directories will corrupt runs at stage 4+ after minutes of API cost.

## Ingestor invariants

- Every snippet has a deterministic ID: `sha256:{sha256(file:name:line)[:6]}:{sha256(file:name:line)[-6:]}`.
  Zero uses of `hash()`, `id()`, `uuid.uuid4()`, or `random` in snippet ID generation.
- C/C++ files produce **function-level** snippets via tree-sitter AST.
  Regex-based brace-depth matching is forbidden. Flat file-level snippets
  are never emitted for C-family languages.
- Every function snippet includes a `callees` list extracted from the function body.
- Self-calls (function name appearing in its own declaration) are filtered from callees.
- Multi-line function declarations (`static int\nauth_password(...)`) are detected.
  A single regex for `type_keyword.*name(` is insufficient.
- Every snippet includes: `id`, `file`, `language`, `kind`, `name`, `lines`, `content`,
  `tags`, `token_count`, `callees`, `continuation`.

## Coordinator invariants

- Exactly 11 domains: `mem-safety`, `auth`, `crypto`, `ipc`, `data-flow`, `format-str`,
  `injection`, `path-traversal`, `concurrency`, `resource`, `secrets`.
  Any fewer is a regression. Count them at runtime.
- `DOMAIN_ORDER` exists and is used for deterministic pack iteration.
- Each domain has an `exclusive` boolean. Exclusive domains receive only
  tag-matching snippets. Non-exclusive domains receive tag-matching snippets
  plus any untagged snippet from the full DB.
- `SECURITY_CONTEXT.md` is loaded and embedded in every pack.

## Chain invariants

- `build_chains()` resolves `snippet_id → function name` before BFS.
  If any finding uses a `sha256:` key in the graph lookup, the chainer is wrong.
- `filter_unreachable()` accepts a `snippet_db` parameter and uses it to
  resolve finding `snippet_id` values to function names for graph reachability.
- The call graph is keyed on lowercase function names, not snippet IDs.

## Pipeline invariants

- Pipeline stages are ordered: Ingestor → Recon → Coordinator → Hunt →
  Validate → Voting → Shield → Chainer → PoC → Trace → Report.
- Gapfill loop exists (2 iterations max) after Validate. Without it, coverage
  gaps from the first hunt pass are silently lost.
- `output/validated.jsonl` is written after Validate. The file is consumed by
  `--validate-only` and `--resume` modes.
- `--validate-only` loads cached findings from `output/findings.jsonl` and
  cached gaps from `output/gaps.jsonl`, skipping the Hunt stage entirely.
- `output/snippet_db.json`, `output/recon_tasks.json`, `output/context_packs.json`
  are persisted at stage boundaries for debug and resume.

## Model invariants

- Hunt and Validate use disjoint model pools. No model appears in both.
  If the pool is too small for a clean split, the strongest model goes to Validate.
- `MODEL_BY_DOMAIN` is populated from `config/defaults.json` at runtime, never
  hardcoded in Python.
- Model health check runs before the first API call. Dead models are removed
  from the chain before any work begins.
- `--skip-health` flag is provided for cached re-runs.

## Quality gates

- Every finding passes through Shield before reaching the Chainer.
  Shield checks: call-path validity against the call graph, hallucination risk
  (≥60% desc-token overlap threshold), static reachability from entry points.
- Findings without `call_path_verified: true` are not chained.
- Findings with `hallucination_detected: true` are not reported.
- Findings marked `static_reachability: unreachable` are not reported for
  library targets unless severity is CRITICAL.

## Enforcement

Any harness that violates any of the above is not an ai-vuln-harness and must
be rewritten. The template at `templates/v1/` is the reference implementation
that satisfies all invariants. When in doubt, diff against it.
