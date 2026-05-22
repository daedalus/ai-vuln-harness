# SPEC.md — ai-vuln-harness

## Purpose

Multi-agent vulnerability research harness following the Project Glasswing / Cloudflare methodology. Turns LLM-assisted code audit from one-off prompts into a reproducible, operational pipeline with adversarial validation, hallucination filtering, and automated PoC compilation.

## Scope

### What IS in scope

- 15-stage pipeline: INGESTOR → RECON → COORDINATOR → HUNT → VALIDATE → GAPFILL → VOTING → SHIELD → SUPPRESSIONS → CHAINS → POC → TRACE → EXPOSURE → FEEDBACK → REPORT
- AST-based C/C++ snippet extraction via tree-sitter
- Deterministic sha256-based snippet IDs
- Multi-provider LLM routing with model pool (hunt/validate disjoint pools)
- Adversarial validation (model tries to disprove findings)
- Hallucination detection via KL-divergence + cosine similarity
- Static call-graph reachability analysis
- Exploit chain synthesis (BFS over findings)
- Automated PoC compilation under AddressSanitizer
- Exposure window computation from git history
- Persistent false-positive suppression registry
- JSONL output per stage + structured final report
- Model health checks with automatic dead-model removal
- Per-mode execution (full, max-run, validate-only, resume, diff, all, poc-only)

### What is NOT in scope

- Fuzzing or dynamic analysis outside PoC compilation
- SAST tool integration
- CI/CD integration (scaffold is standalone)
- Web UI or dashboard
- Vulnerability database export (e.g. VEX, CVE)

## Public API / Interface

### CLI — `run.py`

```
python run.py --mode <mode> --target <path> [options]
```

Modes:
- `full` — full pipeline
- `max-run` — full pipeline capped at `N` snippets via `--max-run`
- `validate-only` — skip hunt, validate existing findings
- `resume` — resume from cached state
- `diff` — diff mode (base-commit vs head-commit)
- `all` — iterate over all single modes and merge reports
- `poc-only` — only compile PoCs for existing findings

### Key Functions (internal stage helpers)

| Function | File | Args | Returns |
|---|---|---|---|
| `run(mode, repo, ...)` | `run.py` | `str, Path, **kwargs` | `dict` — final report |
| `load_repo_snippets(repo)` | `stages/ingestor.py` | `Path` | `list[dict]` |
| `build_recon_tasks(snippets)` | `stages/recon.py` | `list[dict], **kwargs` | `list[dict]` |
| `build_context_packs(snippets, ...)` | `stages/coordinator.py` | `list[dict], **kwargs` | `list[dict]` |
| `parse_findings(raw, ...)` | `stages/parser.py` | `str, **kwargs` | `list[dict]` |
| `call_llm(model, prompt, ...)` | `stages/runtime.py` | `str, str, **kwargs` | `str` |
| `repair_json_output(raw)` | `stages/runtime.py` | `str` | `tuple[dict\|list\|None, bool]` |
| `merge_hunter_outputs(results)` | `stages/voting.py` | `list[list[dict]]` | `tuple[list[dict], list[dict]]` |
| `standardize_finding(finding)` | `stages/contracts.py` | `dict` | `dict` |
| `build_report(repo, findings, ...)` | `stages/report.py` | `str, list[dict], **kwargs` | `dict` |

### Data Formats

**Snippet:**
```json
{
  "id": "sha256:abc123:def456",
  "file": "src/foo.c",
  "language": "c",
  "kind": "function",
  "name": "bar",
  "lines": [42, 85],
  "content": "...",
  "imports": ["stdio.h"],
  "callees": ["malloc", "free"],
  "callers": [],
  "token_count": 142,
  "continuation": false
}
```

**Finding:**
```json
{
  "id": "sha256:...",
  "snippet_id": "sha256:...",
  "class": "buffer-overflow",
  "severity": "HIGH",
  "desc": "...",
  "status": "raw",
  "poc_confirmed": false,
  "bucket_rationale": "",
  "call_path": []
}
```

**Report:**
```json
{
  "repo": "path/to/repo",
  "findings": [...],
  "summary": {"fix_now": N, "backlog": N, "false_positive": N, "chains_feasible": N},
  "chains": [...],
  "gaps": [...]
}
```

### Error Behavior

- `call_llm`: raises `RuntimeError` on model pool exhaustion, `JSONDecodeError` on unparseable response
- `repair_json_output`: never raises, returns `(None, False)` on failure
- `load_repo_snippets`: skips unreadable files (logs OSError), never raises
- `standardize_finding`: never raises (sets defaults for missing keys)
- `validate_subset_schema`: returns `list[str]` of error messages, never raises

## Edge Cases

1. Empty repository → empty snippet list, empty findings, report with zero counts
2. Single-function file → extracted as one snippet, no callers/callees
3. Non-C targets (Python, JS, Go, Rust, TS) → regex-based extraction fallback
4. Malformed JSON from LLM → `repair_json_output` retries truncated braces
5. All models dead → pipeline continues with original model chain (logged warning)
6. Corrupted pickle cache → `load_packs_pickle` returns empty list
7. Missing snippet for a finding → `build_validate_prompt` generates generic prompt
8. Disjoint pool with single model → all models assigned to validate
9. Max cost exceeded → `RuntimeError` raised before pipeline starts
10. Snapshot file not found → treated as empty, fresh pipeline run

## Performance & Constraints

- No forbidden dependencies (stdlib fallbacks for tiktoken, tree-sitter)
- ThreadPoolExecutor for parallel model calls (hunt/validate workers)
- Token counting via tiktoken (cl100k_base), character estimate `len//4` as fallback
- Context packs capped at 85% of minimum model token limit
- Snapshot pickle cache for context packs (avoids re-splitting on resume)
- StateDB via SQLite for cost tracking and run metadata
