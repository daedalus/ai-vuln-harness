from __future__ import annotations

import re
import subprocess
import tempfile
from pathlib import Path

API_BY_DESIGN_PATTERNS = [
    r'.*printf.*',
    r'.*write.*',
    r'.*read.*',
    r'.*open.*',
    r'.*execute.*',
]


def build_validate_prompt(finding: dict, snippet: dict) -> str:
    return f"""Your job is to DISPROVE this vulnerability finding, not confirm it.

Finding:
- snippet_id: {finding.get('snippet_id', '?')}
- class: {finding.get('class', '?')}
- description: {finding.get('desc', '')}
- call_path: {finding.get('call_path', [])}

ACTUAL SOURCE CODE (file: {snippet.get('file', '?')}, lines {snippet.get('lines', '?')}):
```c
{snippet.get('content', '')}
```

Output ONLY JSON: {{"status": "confirmed|rejected|needs-more-info", "reason": "..."}}
"""


def is_api_by_design(finding: dict, snippet: dict) -> bool:
    name = str(snippet.get('name', '')).lower()
    clazz = str(finding.get('class', '')).lower()
    desc = str(finding.get('desc', '')).lower()

    if 'format-string' in clazz and 'printf' in name:
        return True
    if 'by design' in desc:
        return True
    return any(re.match(p, name) for p in API_BY_DESIGN_PATTERNS)


def requires_trace_before_fix_now(is_library_target: bool, trace_confirmed: bool) -> bool:
    return is_library_target and not trace_confirmed


_C_SUFFIXES = {'.c'}
_CPP_SUFFIXES = {'.cc', '.cpp', '.cxx', '.c++'}
_VULN_MARKERS = (
    'addresssanitizer',
    'undefinedbehaviorsanitizer',
    'heap-buffer-overflow',
    'stack-buffer-overflow',
    'use-after-free',
    'stack smashing detected',
    'segmentation fault',
    'sigsegv',
)


def _is_c_or_cpp(snippet: dict) -> bool:
    language = str(snippet.get('language', '')).lower()
    if language in {'c', 'cpp', 'c++'}:
        return True
    suffix = Path(str(snippet.get('file', ''))).suffix.lower()
    return suffix in (_C_SUFFIXES | _CPP_SUFFIXES)


def _extract_vulnerable_to_see_snippet(finding: dict) -> str:
    for key in ('vulnerable_to_see', 'vulnerable_to_see_snippet'):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ''


def _compiler_for(snippet: dict) -> str:
    suffix = Path(str(snippet.get('file', ''))).suffix.lower()
    if suffix in _CPP_SUFFIXES or str(snippet.get('language', '')).lower() in {'cpp', 'c++'}:
        return 'g++'
    return 'gcc'


def _contains_vuln_signal(run_output: str, exit_code: int) -> bool:
    text = run_output.lower()
    if exit_code != 0:
        return True
    return any(marker in text for marker in _VULN_MARKERS)


def recompile_and_run_vulnerable_to_see(
    finding: dict,
    snippet: dict,
    *,
    timeout_seconds: int = 10,
    sandbox_prefix: list[str] | None = None,
) -> dict:
    """Compile and execute a C/C++ vulnerable_to_see snippet in an isolated workspace.

    `sandbox_prefix` allows callers to wrap execution in an isolated runner,
    e.g. a container or qemu command prefix.
    """
    source = _extract_vulnerable_to_see_snippet(finding)
    result = {
        'compile_attempted': False,
        'compile_succeeded': False,
        'run_attempted': False,
        'run_succeeded': False,
        'vulnerability_observed': False,
        'exit_code': None,
        'stdout': '',
        'stderr': '',
        'error': '',
    }

    if not source or not _is_c_or_cpp(snippet):
        return result

    sandbox_prefix = sandbox_prefix or []
    ext = '.cpp' if _compiler_for(snippet) == 'g++' else '.c'
    compiler = _compiler_for(snippet)

    with tempfile.TemporaryDirectory(prefix='ai-vuln-harness-') as td:
        tmp = Path(td)
        src = tmp / f'vulnerable_to_see{ext}'
        bin_path = tmp / 'vulnerable_to_see.bin'
        src.write_text(source, encoding='utf-8')

        result['compile_attempted'] = True
        compile_proc = subprocess.run(
            [compiler, str(src), '-O0', '-g', '-o', str(bin_path)],
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        result['stdout'] = compile_proc.stdout
        result['stderr'] = compile_proc.stderr
        result['compile_succeeded'] = compile_proc.returncode == 0

        if not result['compile_succeeded']:
            result['error'] = 'compile_failed'
            return result

        result['run_attempted'] = True
        run_cmd = [*sandbox_prefix, str(bin_path)]
        run_proc = subprocess.run(
            run_cmd,
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        result['stdout'] = run_proc.stdout
        result['stderr'] = run_proc.stderr
        result['exit_code'] = run_proc.returncode
        result['run_succeeded'] = True
        result['vulnerability_observed'] = _contains_vuln_signal(
            f'{run_proc.stdout}\n{run_proc.stderr}', run_proc.returncode
        )
        return result
