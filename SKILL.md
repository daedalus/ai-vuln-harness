---
name: ai-vuln-harness
description: >
  Design and implement multi-agent vulnerability research harnesses following
  the Project Glasswing / Cloudflare methodology. Use this skill when building
  or improving Hunt/Validate/Dedupe/Trace security pipelines, reducing false
  positives in AI vuln scanning, or operationalizing large-scale LLM-assisted
  code audit workflows.
---

# AI Vulnerability Research Harness

High-level guide for building a production-style AI vulnerability harness.

## Use this skill for

- Multi-agent vulnerability discovery pipelines
- Adversarial validation workflows
- Reachability-driven triage and exploit chaining
- Hardening AI scanner signal-to-noise
- Turning one-off prompts into reproducible security operations

## Runnable scaffold (v1)

Use the executable reference scaffold at:

- `/home/dclavijo/.opencode/skills/ai-vuln-harness/templates/v1`.

It includes:

- `run.py` with run modes: `full`, `max-run`, `validate-only`, `resume`, `poc-only`
- Stage modules under `stages/` with reliability and policy defaults
  - `stages/poc.py` — auto-generates C PoCs, compiles, runs under AddressSanitizer, and produces verdicts
- Prompt templates under `prompts/`
- Required JSON schemas under `schemas/`
  - `schemas/poc-schema.json` — schema for reproducible PoC JSON output
- Unit tests under `tests/`
- Operator config under `config/defaults.json`

## Dependency checking

The harness requires exactly two non-stdlib Python packages (`tree-sitter`,
`tiktoken`) and one external binary (`gcc`). All must be verified at startup
before any stage runs. A harness that silently degrades on missing deps
is invalid — it will produce wrong results or waste API calls.

### Required packages

| Package | Version | Purpose | Failure mode if missing |
|---|---|---|---|
| `tree-sitter` | ≥ 0.25 | AST-level function extraction for C/C++ | Cannot use regex fallback — regex brace-matching misses type-anchored re-exports (e.g., `int ZEXPORT inflate(...)`) and nested-scope functions; every such miss is a silent coverage gap |
| `tree-sitter-c` | matching | C language grammar for tree-sitter | Same as above |
| `tiktoken` | any | Accurate per-snippet token counting for budget enforcement | `len//4` overestimates C code by 30-40%, inflating pack sizes and exceeding 180k budget |

Install:

```shell
pip install tree-sitter tree-sitter-c tiktoken
```

Note: tree-sitter ≥ 0.25 has a **breaking API change** from 0.22.
Verify your version at runtime (see `_check_deps()` below).

### External binary

| Binary | Required if | Purpose |
|---|---|---|
| `gcc` | `stages/poc.py` exists | Compile and run PoCs under AddressSanitizer |

### Startup check

Every harness must call `_check_deps()` at the top of `main()`, before any
arguments are parsed or API calls are made. It must verify all required
packages and binaries, and `sys.exit()` with a clear message if anything
is missing:

```python
import importlib, shutil, sys

def _check_deps():
    """Pass/fail dependency check at startup."""
    if sys.version_info < (3, 9):
        sys.exit('fatal: Python >= 3.9 required')

    missing = []
    for pkg in ('tree_sitter', 'tiktoken'):
        if importlib.util.find_spec(pkg) is None:
            missing.append(pkg)

    # tree-sitter language grammars: check at least one
    try:
        from tree_sitter_c import language as c_lang
        c_lang()
    except Exception:
        missing.append('tree-sitter-c')

    if missing:
        sys.exit(f'fatal: missing packages: {", ".join(missing)}. '
                 f'Run: pip install tree-sitter tree-sitter-c tiktoken')

    # Verify tree-sitter API version (0.25+, not 0.22)
    import tree_sitter
    parts = tuple(int(x) for x in tree_sitter.__version__.split('.')[:2])
    if parts < (0, 25):
        sys.exit(f'fatal: tree-sitter {tree_sitter.__version__} detected, '
                 f'>= 0.25 required (0.22 API is incompatible)')

    # Compiler check (PoC stage)
    poc_stage_exists = (Path(__file__).parent / 'stages/poc.py').exists()
    if poc_stage_exists and not shutil.which('gcc'):
        sys.exit('fatal: gcc not found — PoC stage requires a C compiler')

    _log.info('[deps] python=%s tree-sitter=%s tiktoken=%s gcc=%s',
              sys.version.split()[0],
              tree_sitter.__version__,
              importlib.metadata.version('tiktoken') if importlib.util.find_spec('tiktoken') else 'NOT FOUND',
              shutil.which('gcc') or 'NOT FOUND')
```

### Config file check

Before any stage runs, verify that `config/defaults.json` exists and is
valid JSON:

```python
def _check_config(path: Path) -> dict:
    if not path.exists():
        sys.exit(f'fatal: config not found at {path}')
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as e:
        sys.exit(f'fatal: config parse error: {e}')
```

### Output directory permissions

Before writing any files, verify the output directory is writable:

```python
output_dir = Path(__file__).parent / 'output'
output_dir.mkdir(parents=True, exist_ok=True)
probe = output_dir / '.write_test'
try:
    probe.write_text('ok')
    probe.unlink()
except OSError as e:
    sys.exit(f'fatal: output dir not writable: {e}')
```

### API auth check

Before making any API calls, verify that at least one auth key is available:

```python
def _check_auth() -> None:
    has_key = False
    for provider in ('openrouter', 'groq', 'cerebras'):
        key = os.environ.get(f'{provider.upper()}_API_KEY')
        if not key:
            for p in [Path(__file__).parent / 'auth.json',
                      Path.home() / '.local/share/opencode/auth.json']:
                if p.exists():
                    data = json.loads(p.read_text())
                    key = data.get(provider)
                    break
        if key:
            has_key = True
            break
    if not has_key:
        _log.warning('[auth] no API keys found — pipeline will fail at Hunt stage')
```

### Dependency invariants (harness integrity)

- All three Python packages (`tree-sitter`, `tree-sitter-c`, `tiktoken`) are
  **required** at module level. No guarded imports. No fallbacks. If a package
  is missing, `_check_deps()` must `sys.exit()` before any work begins.
- `gcc` must be checked at startup if PoC stage is present.
- `config/defaults.json` must be validated before first use.
- Auth key absence must produce a warning, not a silent failure.
- Output directory must be probed for write access before stage 1.

## Required operating defaults

1. Ingestor must produce function-level snippets for C/C++ with deterministic IDs
   - Extract functions via tree-sitter AST. Regex-based brace-depth matching
     is forbidden — it misses type-anchored re-exports and nested-scope
     functions, creating silent coverage gaps.
   - IDs must be deterministic across runs: `sha256({file}:{func_name}:{line})`.
   - Non-deterministic `hash()` or `id()` breaks cache, state DB, and finding traceability.
   - Include callee extraction for call-graph construction; filter out the function's own name from its callee list.
   - Handle multi-line function declarations where return type and name are on separate lines.

2. Recon output drives coordinator pack generation
   - Full-DB fallback is opt-in only.

3. Library-target hardening is on by default
   - Exclude `test/`, `examples/`, `contrib/` from snippet selection.
   - Use target-aware external-input and integer-arith tagging.

4. Stage contracts are mandatory
   - Validate outputs against schemas before stage handoff.
   - Apply bounded repair turns for malformed outputs.

5. Validate/Trace quality gates
   - Validate prompts must include source code looked up by `snippet_id`.
   - API-by-design patterns are rejected or downgraded.
   - Library findings require Trace confirmation before `fix_now`.

6. Reliability and reproducibility are first-class
   - Sync model request path as default.
   - Disjoint Hunt and Validate model pools.
   - Persistent cache + resumable state DB.

7. Model health check before every run
   - Probe each model with a small ping before using it.
   - Remove DEAD models from the chain so the pipeline doesn't waste time on them.
   - Cache health check results for fast resume (invalidate on config change).
   - Include `--skip-health` flag for cached runs.

8. Multi-provider routing
   - Prefix model IDs with provider name: `openrouter:...`, `groq:...`, `cerebras:...`
   - `call_llm()` resolves the prefix to the right base URL, auth key, and headers.
   - This allows mixing providers in a single flat model chain with no code changes per provider.

9. Auth files: check project-relative path first, fall back to global
   - `./auth.json` (next to the harness) takes priority.
   - `~/.local/share/opencode/auth.json` is the global fallback.
   - Support env vars (`OPENROUTER_API_KEY`, `GROQ_API_KEY`, `CEREBRAS_API_KEY`) as override.

10. Proxy support through environment variables
    - Set `http_proxy`/`https_proxy` at startup before any API calls.
    - urllib's default `ProxyHandler` picks them up transparently.
    - `--proxy` CLI flag or `proxy` field in config.

11. PoC confirmation is a first-class pipeline stage
    - Auto-generate targeted C (or language-appropriate) PoCs from findings.
    - Compile with AddressSanitizer and run under sanitized conditions.
    - Populate `actual` fields on each test case, compare against `expected`.
    - Produce a `poc_verdict` (`confirmed` / `rejected` / `needs-more-info`)
      that annotates the original finding in the final report.
    - Schema-validate PoC JSON at every stage for reproducibility.
    - `--poc <id|all>` during a normal run; `--poc-only` for zero-API-cost replay.

12. Coordinator must use 11 security domains with DOMAIN_ORDER
    - `mem-safety`, `auth`, `crypto`, `ipc`, `data-flow`, `format-str`,
      `injection`, `path-traversal`, `concurrency`, `resource`, `secrets`.
    - Use `DOMAIN_ORDER` for deterministic pack building order.
    - Each domain has an `exclusive` flag: exclusive domains only get snippets
      matching their own tags; non-exclusive domains get snippets matching
      their tags AND any snippet from the full DB that lacks tags.

13. Chain graph key resolution is mandatory
    - Call graph is keyed on lowercase function names, but findings reference
      snippet IDs. The chainer MUST resolve `snippet_id → function name` before
      BFS traversal or chains will be empty.
    - `shield.filter_unreachable()` must also accept a `snippet_db` parameter
      to resolve snippet IDs to function names for reachability analysis.

14. Cross-run regression analysis prevents silent functionality loss
    - After every target or architecture change, do a diff audit across the last
      3-5 runs. Check: ingestor extraction depth, config size, stage count,
      output files, domain count.
    - Run9 lost 2 catastrophic features (ingestor function extraction, deterministic
      IDs) and 3 major features (11 domains, security context, config-driven models)
      relative to run7/run8. These were caught by cross-run audit, not noticed
      during development.

## Progress tracking

Maintain a live `todowrite` task list throughout the session. Every step —
auditing, fixing, testing, updating docs — must be tracked. Use three states:
`pending`, `in_progress`, `completed`. Mark `completed` only after the work
is verified (code written, test passes, file saved). This prevents forgotten
half-finished tasks when context switches or interruptions occur.

## Logging facilities

See `references/logging.md` — dual-channel stderr/stdout, logger setup,
level conventions, stage entry/exit pattern, model call timing, bad model
tracking, and parallel worker progress.

## Harness integrity (strict creation rules)

A harness built with this skill is not valid unless all of the following hold.
These are pass/fail checks, not recommendations.

### Structural invariants

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

### Ingestor invariants

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

### Coordinator invariants

- Exactly 11 domains: `mem-safety`, `auth`, `crypto`, `ipc`, `data-flow`, `format-str`,
  `injection`, `path-traversal`, `concurrency`, `resource`, `secrets`.
  Any fewer is a regression. Count them at runtime.
- `DOMAIN_ORDER` exists and is used for deterministic pack iteration.
- Each domain has an `exclusive` boolean. Exclusive domains receive only
  tag-matching snippets. Non-exclusive domains receive tag-matching snippets
  plus any untagged snippet from the full DB.
- `SECURITY_CONTEXT.md` is loaded and embedded in every pack.

### Chain invariants

- `build_chains()` resolves `snippet_id → function name` before BFS.
  If any finding uses a `sha256:` key in the graph lookup, the chainer is wrong.
- `filter_unreachable()` accepts a `snippet_db` parameter and uses it to
  resolve finding `snippet_id` values to function names for graph reachability.
- The call graph is keyed on lowercase function names, not snippet IDs.

### Pipeline invariants

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

### Model invariants

- Hunt and Validate use disjoint model pools. No model appears in both.
  If the pool is too small for a clean split, the strongest model goes to Validate.
- `MODEL_BY_DOMAIN` is populated from `config/defaults.json` at runtime, never
  hardcoded in Python.
- Model health check runs before the first API call. Dead models are removed
  from the chain before any work begins.
- `--skip-health` flag is provided for cached re-runs.

### Quality gates

- Every finding passes through Shield before reaching the Chainer.
  Shield checks: call-path validity against the call graph, hallucination risk
  (≥60% desc-token overlap threshold), static reachability from entry points.
- Findings without `call_path_verified: true` are not chained.
- Findings with `hallucination_detected: true` are not reported.
- Findings marked `static_reachability: unreachable` are not reported for
  library targets unless severity is CRITICAL.

### Enforcement

Any harness that violates any of the above is not an ai-vuln-harness and must
be rewritten. The template at `templates/v1/` is the reference implementation that satisfy all invariants.
When in doubt, diff against them.

## Evaluation and operator guidance

- Track KPIs: precision@top-N, reject rate, duplicate rate, gap-closure rate, time/cost per stage.
- Maintain benchmark corpus + regression gate for prompt/model updates.
- Keep troubleshooting playbooks for 429 storms, empty model outputs, schema repair loops, auth key nesting, and truncated validate responses.

## Deep references

- `references/stages.md` — stage-by-stage design guidance
- `references/operation.md` — implementation gotchas and operational notes
- `references/implementation.md` — implementation sketches and patterns
- `references/schemas.md` — canonical schema expectations
- `references/logging.md` — logging conventions and setup
