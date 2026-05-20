# Dependency Checking

The harness requires exactly two non-stdlib Python packages (`tree-sitter`,
`tiktoken`) and one external binary (`gcc`). All must be verified at startup
before any stage runs. A harness that silently degrades on missing deps
is invalid — it will produce wrong results or waste API calls.

## Required packages

| Package | Version | Purpose | Failure mode if missing |
|---|---|---|---|
| `tree-sitter` | ≥ 0.25 | AST-level function extraction for C/C++ | Cannot use regex fallback — regex brace-matching misses type-anchored re-exports (e.g., `int ZEXPORT inflate(...)`) and nested-scope functions; every such miss is a silent coverage gap |
| `tree-sitter-c` | matching | C language grammar for tree-sitter | Same as above |
| `tiktoken` | any | Accurate per-snippet token counting for budget enforcement | `len//4` overestimates C code by 30-40%, inflating pack sizes and exceeding the 85% context budget |

Install:

```shell
pip install tree-sitter tree-sitter-c tiktoken
```

Note: tree-sitter ≥ 0.25 has a **breaking API change** from 0.22.
Verify your version at runtime (see `_check_deps()` below).

## External binary

| Binary | Required if | Purpose |
|---|---|---|
| `gcc` | `stages/poc.py` exists | Compile and run PoCs under AddressSanitizer |

## Startup check

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

## Config file check

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

## Output directory permissions

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

## API auth check

Before making any API calls, verify that at least one auth key is available:

```python
def _check_auth() -> None:
    has_key = False
    for provider in ('openrouter', 'groq', 'cerebras', 'google', 'zen'):
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

## Dependency invariants

- All three Python packages (`tree-sitter`, `tree-sitter-c`, `tiktoken`) are
  **required** at module level. No guarded imports. No fallbacks. If a package
  is missing, `_check_deps()` must `sys.exit()` before any work begins.
- `gcc` must be checked at startup if PoC stage is present.
- `config/defaults.json` must be validated before first use.
- Auth key absence must produce a warning, not a silent failure.
- Output directory must be probed for write access before stage 1.
