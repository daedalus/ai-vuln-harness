# Required Operating Defaults

These defaults are enforced by the harness. See each stage's docstring in
`stages/` for the canonical rationale. This file documents what each
default guards against.

## 1. Ingestor: function-level snippets via tree-sitter AST

- `stages/ingestor.py` docstring — tree-sitter ≥ 0.25 required, regex forbidden,
  deterministic sha256 IDs, multi-line declaration fallback, callee extraction,
  tag inflation mitigation.

## 2. Recon: output drives coordinator pack generation

## 3. Library-target hardening (on by default)

Exclude `test/`, `examples/`, `contrib/`; use target-aware tag heuristics.

## 4. Stage contracts (mandatory)

Validate outputs against schemas before handoff. See `stages/contracts.py`.

## 5. Validate/Trace quality gates

Validate prompts include source code by `snippet_id`; API-by-design rejected;
library findings need Trace confirmation for `fix_now`.

## 6. Reliability and reproducibility

Sync urllib (not async); disjoint Hunt/Validate pools; persistent cache +
resumable state DB. See `stages/runtime.py`.

## 7. Model health check before every run

Probe each model; remove DEAD before use; cache results; `--skip-health` flag.

## 8. Multi-provider routing

Model IDs prefixed with `provider:` — `call_llm()` resolves prefix to
base URL, auth key, headers. See `stages/runtime.py`.

## 9. Auth file resolution

Env var → script-relative `auth.json` → `~/.local/share/opencode/auth.json`.
Never `./auth.json` or `os.getcwd()`. See `stages/runtime.py` docstring.

## 10. Proxy support via environment variables

Set `http_proxy`/`https_proxy` at startup; urllib picks up transparently.

## 11. PoC confirmation as pipeline stage

Auto-generate, compile under ASan, run, verdict. See `stages/poc.py`.

## 12. Coordinator: 11 security domains

`stages/coordinator.py` docstring — domain table, exclusive flag, DOMAIN_ORDER,
85% budget enforcement, tag inflation note.

## 13. Chain graph key resolution

Findings reference snippet IDs; call graph keyed on function names.
Resolver must convert before BFS. See `stages/chains.py` docstring.

## 14. Cross-run regression analysis

Diff-audit across last 3–5 runs after every target/architecture change.
Check: extraction depth, config size, stage count, domain count, output files.

## 15. Model limits from provider endpoint

Fetch from provider `/models` endpoint at startup — never hardcode.
Cache to `models.dev`, refresh if >24h old or `--refresh-models` flag set.
