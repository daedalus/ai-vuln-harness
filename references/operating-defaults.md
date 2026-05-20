# Required Operating Defaults

## Ingestor

1. Ingestor must produce function-level snippets for C/C++ with deterministic IDs
   - Extract functions via tree-sitter AST. Regex-based brace-depth matching
     is forbidden — it misses type-anchored re-exports and nested-scope
     functions, creating silent coverage gaps.
   - IDs must be deterministic across runs: `sha256({file}:{func_name}:{line})`.
   - Non-deterministic `hash()` or `id()` breaks cache, state DB, and finding traceability.
   - Include callee extraction for call-graph construction; filter out the function's own name from its callee list.
   - Handle multi-line function declarations where return type and name are on separate lines.

## Recon

2. Recon output drives coordinator pack generation
   - Full-DB fallback is opt-in only.

## Library-target hardening

3. Library-target hardening is on by default
   - Exclude `test/`, `examples/`, `contrib/` from snippet selection.
   - Use target-aware external-input and integer-arith tagging.

## Stage contracts

4. Stage contracts are mandatory
   - Validate outputs against schemas before stage handoff.
   - Apply bounded repair turns for malformed outputs.

## Validate/Trace quality gates

5. Validate/Trace quality gates
   - Validate prompts must include source code looked up by `snippet_id`.
   - API-by-design patterns are rejected or downgraded.
   - Library findings require Trace confirmation before `fix_now`.

## Reliability and reproducibility

6. Reliability and reproducibility are first-class
   - Sync model request path as default.
   - Disjoint Hunt and Validate model pools.
   - Persistent cache + resumable state DB.

## Model health check

7. Model health check before every run
   - Probe each model with a small ping before using it.
   - Remove DEAD models from the chain so the pipeline doesn't waste time on them.
   - Cache health check results for fast resume (invalidate on config change).
   - Include `--skip-health` flag for cached runs.

## Multi-provider routing

8. Multi-provider routing
   - Prefix model IDs with provider name: `openrouter:...`, `groq:...`, `cerebras:...`, `google:...`, `zen:...`
   - `call_llm()` resolves the prefix to the right base URL, auth key, and headers.
   - This allows mixing providers in a single flat model chain with no code changes per provider.

## Auth file resolution

9. Auth files: resolve relative to the script directory (`run.py`), not `cwd`
   - `Path(__file__).parent / 'auth.json'` is the primary path. Never `./auth.json`
     or `os.getcwd() + '/auth.json'` — those break when the harness is invoked
     from a different directory.
   - `~/.local/share/opencode/auth.json` is the global fallback.
   - Support env vars (`OPENROUTER_API_KEY`, `GROQ_API_KEY`, `CEREBRAS_API_KEY`,
     `GOOGLE_API_KEY`, `ZEN_API_KEY`) as override.
   - Resolution order: env var → script-dir `auth.json` → global fallback.
     First non-empty value wins.

## Proxy support

10. Proxy support through environment variables
    - Set `http_proxy`/`https_proxy` at startup before any API calls.
    - urllib's default `ProxyHandler` picks them up transparently.
    - `--proxy` CLI flag or `proxy` field in config.

## PoC confirmation

11. PoC confirmation is a first-class pipeline stage
    - Auto-generate targeted C (or language-appropriate) PoCs from findings.
    - Compile with AddressSanitizer and run under sanitized conditions.
    - Populate `actual` fields on each test case, compare against `expected`.
    - Produce a `poc_verdict` (`confirmed` / `rejected` / `needs-more-info`)
      that annotates the original finding in the final report.
    - Schema-validate PoC JSON at every stage for reproducibility.
    - `--poc <id|all>` during a normal run; `--poc-only` for zero-API-cost replay.

## Coordinator domains

12. Coordinator must use 11 security domains with DOMAIN_ORDER
    - `mem-safety`, `auth`, `crypto`, `ipc`, `data-flow`, `format-str`,
      `injection`, `path-traversal`, `concurrency`, `resource`, `secrets`.
    - Use `DOMAIN_ORDER` for deterministic pack building order.
    - Each domain has an `exclusive` flag: exclusive domains only get snippets
      matching their own tags; non-exclusive domains get snippets matching
      their tags AND any snippet from the full DB that lacks tags.

## Chain graph key resolution

13. Chain graph key resolution is mandatory
    - Call graph is keyed on lowercase function names, but findings reference
      snippet IDs. The chainer MUST resolve `snippet_id → function name` before
      BFS traversal or chains will be empty.
    - `shield.filter_unreachable()` must also accept a `snippet_db` parameter
      to resolve snippet IDs to function names for reachability analysis.

## Cross-run regression analysis

14. Cross-run regression analysis prevents silent functionality loss
    - After every target or architecture change, do a diff audit across the last
      3-5 runs. Check: ingestor extraction depth, config size, stage count,
      output files, domain count.
    - Run9 lost 2 catastrophic features (ingestor function extraction, deterministic
      IDs) and 3 major features (11 domains, security context, config-driven models)
      relative to run7/run8. These were caught by cross-run audit, not noticed
      during development.

## Model limits from endpoint

15. Model limits must be fetched from the provider's models endpoint or a
    `models.dev` manifest — never hardcoded
    - Hardcoded context window sizes go stale when providers update models
      (OpenRouter renames models, Groq bumps limits, etc.). A stale limit
      either wastes budget (underestimating capacity) or causes 400 errors
      (overestimating capacity).
    - On startup, query the provider's `/models` endpoint for each model in
      the chain. Extract `context_length` (or equivalent) and use it for the
      85% budget calculation.
    - Cache results to a `models.dev` file next to the harness. On subsequent
      runs, use the cache unless `--refresh-models` is passed or the cache
      is >24h old.
    - If a provider has no models endpoint (or auth limits requests), ship a
      `models.dev` with known limits and a `last_updated` timestamp. Log a
      warning that limits are static.
    - `models.dev` format: JSON dict keyed on `provider:model` — each entry
      has `context_window`, `max_output_tokens`, `last_updated`.
    - Model context window discovery must complete before any pack is built.
      Packs assembled against wrong limits produce incorrect budgets for all
      downstream stages.
