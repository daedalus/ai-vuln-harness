"""Validate stage — adversarial re-read of findings by an independent agent.

Goal: DISPROVE each finding, not confirm it. Uses a different model than Hunt
to avoid correlated biases. The agent receives the actual source code (looked
up by ``snippet_id`` from the snippet DB) so it can verify the model's claims
against what the code actually does.

API-by-design detection: functions like ``*printf*(format, ...)`` and
``*write*(buf, len)`` intentionally accept caller-controlled parameters — that
is a consumer misuse, not a library bug. These are rejected or downgraded.

From the zlib run: DeepSeek V4 Flash (Hunt) reported ``gzprintf`` as a HIGH
format-string finding; Nemotron Nano (Validate) correctly rejected it as
API-by-design. This confirms the critical requirement: Validate must use a
**disjoint model pool** from Hunt (no model in common across both stages).
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

_API_BY_DESIGN_NAMES = frozenset(
    {
        "printf",
        "fprintf",
        "dprintf",
        "sprintf",
        "snprintf",
        "vprintf",
        "vfprintf",
        "vsprintf",
        "vsnprintf",
        "gzprintf",
        "write",
        "read",
        "open",
        "pread",
        "pwrite",
        "readv",
        "writev",
        "send",
        "recv",
        "accept",
        "execute",
    },
)


def build_validate_prompt(finding: dict, snippet: dict) -> str:
    return f"""Your job is to DISPROVE this vulnerability finding, not confirm it.

Finding:
- snippet_id: {finding.get("snippet_id", "?")}
- class: {finding.get("class", "?")}
- description: {finding.get("desc", "")}
- call_path: {finding.get("call_path", [])}

ACTUAL SOURCE CODE (file: {snippet.get("file", "?")}, lines {snippet.get("lines", "?")}):
```c
{snippet.get("content", "")}
```

Output ONLY JSON: {{"status": "confirmed|rejected|needs-more-info", "reason": "..."}}
"""


def is_api_by_design(finding: dict, snippet: dict) -> bool:
    name = str(snippet.get("name", "")).lower()
    clazz = str(finding.get("class", "")).lower()
    desc = str(finding.get("desc", "")).lower()

    if "format-string" in clazz and "printf" in name:
        return True
    if "by design" in desc:
        return True
    return name in _API_BY_DESIGN_NAMES


def requires_trace_before_fix_now(
    is_library_target: bool,
    trace_confirmed: bool,
) -> bool:
    return is_library_target and not trace_confirmed


_C_SUFFIXES = {".c"}
_CPP_SUFFIXES = {".cc", ".cpp", ".cxx", ".c++"}
_VULN_MARKERS = (
    "addresssanitizer",
    "undefinedbehaviorsanitizer",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "stack smashing detected",
    "segmentation fault",
    "sigsegv",
)


def _is_c_or_cpp(snippet: dict) -> bool:
    language = str(snippet.get("language", "")).lower()
    if language in {"c", "cpp", "c++"}:
        return True
    suffix = Path(str(snippet.get("file", ""))).suffix.lower()
    return suffix in (_C_SUFFIXES | _CPP_SUFFIXES)


def _extract_unvalidated_vulnerable_snippet(finding: dict) -> str:
    for key in ("unvalidated_vulnerable_snippet",):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return ""


def _compiler_for(snippet: dict) -> str:
    suffix = Path(str(snippet.get("file", ""))).suffix.lower()
    if suffix in _CPP_SUFFIXES or str(snippet.get("language", "")).lower() in {
        "cpp",
        "c++",
    }:
        return "g++"
    return "gcc"


def _contains_vuln_signal(run_output: str, exit_code: int) -> bool:
    text = run_output.lower()
    if exit_code < 0:
        return True
    return any(marker in text for marker in _VULN_MARKERS)


def recompile_and_run_unvalidated_vulnerable_snippet(
    finding: dict,
    snippet: dict,
    *,
    timeout_seconds: int = 10,
    sandbox_prefix: list[str] | None = None,
) -> dict:
    source = _extract_unvalidated_vulnerable_snippet(finding)
    result = {
        "compile_attempted": False,
        "compile_succeeded": False,
        "run_attempted": False,
        "run_succeeded": False,
        "vulnerability_observed": False,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "error": "",
    }

    if not source or not _is_c_or_cpp(snippet):
        return result

    sandbox_prefix = sandbox_prefix or []
    ext = ".cpp" if _compiler_for(snippet) == "g++" else ".c"
    compiler = _compiler_for(snippet)

    with tempfile.TemporaryDirectory(prefix="ai-vuln-harness-") as td:
        tmp = Path(td)
        src = tmp / f"unvalidated_vulnerable_snippet{ext}"
        bin_path = tmp / "unvalidated_vulnerable_snippet.bin"
        src.write_text(source, encoding="utf-8")

        result["compile_attempted"] = True
        compile_proc = subprocess.run(
            [compiler, str(src), "-O0", "-g", "-o", str(bin_path)],
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        result["stdout"] = compile_proc.stdout
        result["stderr"] = compile_proc.stderr
        result["compile_succeeded"] = compile_proc.returncode == 0

        if not result["compile_succeeded"]:
            result["error"] = "compile_failed"
            return result

        result["run_attempted"] = True
        run_cmd = [*sandbox_prefix, str(bin_path)]
        run_proc = subprocess.run(
            run_cmd,
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )
        result["stdout"] = run_proc.stdout
        result["stderr"] = run_proc.stderr
        result["exit_code"] = run_proc.returncode
        result["run_succeeded"] = True
        result["vulnerability_observed"] = _contains_vuln_signal(
            f"{run_proc.stdout}\n{run_proc.stderr}",
            run_proc.returncode,
        )
        return result
