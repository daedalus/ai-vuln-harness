# Dependency Checking

The harness requires exactly two non-stdlib Python packages (`tree-sitter`,
`tiktoken`) and one external binary (`gcc`). All must be verified at startup
before any stage runs.

See `run.py` → `_check_deps()` for the startup checker implementation.

## Required packages

| Package | Version | Purpose | Failure mode if missing |
|---|---|---|---|
| `tree-sitter` | ≥ 0.25 | AST-level function extraction for C/C++ | Cannot use regex fallback — regex brace-matching misses type-anchored re-exports (e.g., `int ZEXPORT inflate(...)`) and nested-scope functions; every such miss is a silent coverage gap |
| `tree-sitter-c` | matching | C language grammar for tree-sitter | Same as above |
| `tiktoken` | any | Accurate per-snippet token counting for budget enforcement | `len//4` overestimates C code by 30-40%, inflating pack sizes and exceeding the 85% context budget |

Install: `pip install tree-sitter tree-sitter-c tiktoken`

Note: tree-sitter ≥ 0.25 has a **breaking API change** from 0.22.
`_check_deps()` verifies the version at runtime.

## External binary

| Binary | Required if | Purpose |
|---|---|---|
| `gcc` | `stages/poc.py` exists | Compile and run PoCs under AddressSanitizer |

## Startup checks in code

- **Config**: `_check_config()` verifies `config/defaults.json` exists and is valid JSON.
- **Output dir**: mkdir + probe-write before any stage runs.
- **Auth**: `_check_auth()` resolves env var → script-relative `auth.json` → `~/.local/share/opencode/auth.json`; warns if none found.

## Dependency invariants

- All three Python packages are **required** at module level. No guarded imports. No fallbacks.
- `gcc` checked at startup if PoC stage is present.
- `config/defaults.json` validated before first use.
- Auth key absence produces a warning, not silent failure.
- Output directory probed for write access before stage 1.
