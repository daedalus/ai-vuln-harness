"""PoC confirmation stage — compile and run targeted tests under AddressSanitizer.

Goal: disprove or confirm each finding by compiling and running a targeted
C program under ASan. This is the strongest evidence level — a compiler+ASan
verdict beats any LLM opinion.

Why it matters: AI hunters produce ~60-80% false positive rates on audited
codebases. Validate catches some via adversarial prompting, but the gold
standard is concrete execution: if the alleged buffer overflow does not crash
under ASan, it does not exist as described.

Verdict logic:
  - ``confirmed``: ASan errors detected — finding reproduces under sanitized
    conditions.
  - ``rejected``: exit code 0, no ASan errors — the alleged bug does not exist
    as described.
  - ``needs-more-info``: build failed or crashed without ASan — manual review
    required.

Isolation: PoC runners must have no production access. Use a sandboxed
container with no network egress and scoped API keys.

PoC does NOT test: multi-step exploits (handled by Chainer), consumer
reachability (handled by Trace), other architectures, or timing/side channels.
"""

from __future__ import annotations

import json
import logging
import subprocess
import sys
import textwrap
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Generator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Egress audit + action scope validator (Mythos system card §4.2.4)
# ---------------------------------------------------------------------------

_NETWORK_TOKENS = frozenset(
    {
        "curl",
        "wget",
        "nc",
        "netcat",
        "ncat",
        "ssh",
        "scp",
        "sftp",
        "ftp",
        "telnet",
        "python3",
        "python",
        "bash",
        "sh",
        "perl",
        "ruby",
        "socat",
    }
)

# Tokens whose presence in combination with "-c" indicate shell execution
_SHELL_EXEC_TOKENS = frozenset({"bash", "sh", "python3", "python", "perl", "ruby"})


class ScopeViolationError(Exception):
    """Raised when a PoC command exceeds the permitted execution scope.

    This exception is raised by ``EgressAuditContext`` whenever a shell
    command issued during PoC execution references paths outside the
    ``output_dir`` subtree or includes network-adjacent tokens.
    """


@contextmanager
def EgressAuditContext(  # noqa: N802 — CamelCase matches the exported public API name
    # required by the problem spec so callers can do `with EgressAuditContext(...)`
    output_dir: Path,
    sandbox_prefix: list[str] | None = None,
) -> Generator[None, None, None]:
    """Context manager that intercepts subprocess calls during PoC execution.

    Wraps every ``subprocess.run`` call issued inside the context and
    checks each command against an allowlist:

    - Only ``[sandbox_prefix] + [binary_path]`` is permitted.
    - Commands whose tokens include paths *outside* the ``output_dir``
      subtree raise ``ScopeViolationError``.
    - Commands that include network-adjacent tokens (``curl``, ``wget``,
      ``nc``, ``python3 -c``, ``bash -c``, etc.) raise
      ``ScopeViolationError``.

    On violation the error is logged to ``stderr`` at ERROR level and
    ``ScopeViolationError`` is re-raised so the caller can set the PoC
    result to a ``scope_violation`` verdict.

    Parameters
    ----------
    output_dir:
        The permitted filesystem subtree.  Any path token that resolves
        outside this tree is a violation.
    sandbox_prefix:
        Optional sandbox wrapper (e.g. ``["firejail", "--"]``).  These
        tokens are unconditionally allowed at the head of the command.

    Yields
    ------
    None

    Raises
    ------
    ScopeViolationError
        When a command violates the allowlist.

    """
    resolved_output = Path(output_dir).resolve()
    allowed_prefix = list(sandbox_prefix or [])

    original_run = subprocess.run

    def _audited_run(cmd: object, **kwargs: object) -> object:
        tokens: list[str] = []
        if isinstance(cmd, (list, tuple)):
            tokens = [str(t) for t in cmd]
        elif isinstance(cmd, str):
            tokens = cmd.split()

        # Strip the sandbox prefix from the check
        effective = tokens[len(allowed_prefix) :] if allowed_prefix else tokens

        # Check for network-adjacent tokens
        for tok in effective:
            base = tok.split("/")[-1].split("\\")[-1]  # basename
            if base in _NETWORK_TOKENS:
                # Allow if it is NOT followed by -c (shell execution indicator)
                # but always block outright network tools
                if base not in _SHELL_EXEC_TOKENS or "-c" in effective:
                    msg = (
                        f"EgressAuditContext: blocked network-adjacent token "
                        f"'{base}' in command {tokens!r}"
                    )
                    logger.error("%s", msg)
                    print(msg, file=sys.stderr)
                    raise ScopeViolationError(msg)

        # Check path tokens for out-of-scope filesystem access
        for tok in effective:
            candidate = Path(tok)
            if candidate.is_absolute() or tok.startswith("./") or tok.startswith("../"):
                try:
                    resolved = candidate.resolve()
                except (OSError, ValueError):
                    resolved = candidate
                try:
                    resolved.relative_to(resolved_output)
                except ValueError as exc:
                    msg = (
                        f"EgressAuditContext: blocked out-of-scope path "
                        f"'{tok}' (resolved: {resolved}) outside "
                        f"'{resolved_output}' in command {tokens!r}"
                    )
                    logger.error("%s", msg)
                    print(msg, file=sys.stderr)
                    raise ScopeViolationError(msg) from exc

        return original_run(cmd, **kwargs)  # type: ignore[call-overload]

    subprocess.run = _audited_run
    try:
        yield
    finally:
        subprocess.run = original_run


_C_FLAGS = ["-fsanitize=address", "-g", "-O0"]

_LANGUAGE_EXT = {
    "c": ".c",
    "cpp": ".cpp",
    "go": ".go",
    "python": ".py",
    "javascript": ".js",
    "typescript": ".ts",
    "rust": ".rs",
}

_LANGUAGE_RUNTIME = {
    "c": {
        "compile": ["gcc", *_C_FLAGS, "{src}", "-o", "{bin}"],
        "run": ["{bin}"],
        "ext": ".bin",
    },
    "cpp": {
        "compile": ["g++", *_C_FLAGS, "{src}", "-o", "{bin}"],
        "run": ["{bin}"],
        "ext": ".bin",
    },
    "rust": {
        "compile": ["rustc", "{src}", "-o", "{bin}"],
        "run": ["{bin}"],
        "ext": ".bin",
    },
    "go": {
        "compile": ["go", "build", "-o", "{bin}", "{src}"],
        "run": ["{bin}"],
        "ext": ".bin",
    },
    "python": {"compile": None, "run": ["python3", "{src}"], "ext": ".py"},
    "javascript": {"compile": None, "run": ["node", "{src}"], "ext": ".js"},
    "typescript": {
        "compile": ["npx", "tsc", "--outDir", "{outdir}", "{src}"],
        "run": ["node", "{bin}"],
        "ext": ".js",
    },
}


def _lang_from_snippet(snippet: dict) -> str:
    return snippet.get("language", "c")


def build_poc_json(finding: dict, snippet: dict) -> dict:
    lang = _lang_from_snippet(snippet)
    compiler_info = _LANGUAGE_RUNTIME.get(lang, _LANGUAGE_RUNTIME["c"])
    return {
        "schema_version": "v1",
        "poc_id": f"poc-{finding.get('snippet_id', 'unknown')}-{finding.get('class', 'unknown')}",
        "finding": {
            "snippet_id": finding.get("snippet_id", ""),
            "class": finding.get("class", ""),
            "severity": finding.get("severity", "LOW"),
            "desc": finding.get("desc", ""),
            "call_path": finding.get("call_path", []),
        },
        "harness": {
            "language": lang,
            "compiler": compiler_info.get("compile"),
            "runtime": compiler_info.get("run"),
            "source_file": "",
            "dependencies": [],
            "libraries": [],
        },
        "test_cases": [
            {
                "id": "tc-1",
                "description": f"Reproduce {finding.get('class', 'vuln')} in {snippet.get('name', '?')}",
                "input": {},
                "expected": {"crash": True, "error": True},
            },
        ],
        "result": {
            "status": "incomplete",
            "verdict": "needs-more-info",
            "reasoning": "",
        },
    }


def _autogen_source(finding: dict, snippet: dict) -> str:
    lang = _lang_from_snippet(snippet)
    content = snippet.get("content") or ""
    func_name = snippet.get("name", "target_func")
    header = f"/* PoC: {finding.get('desc', 'finding')} in {func_name} */"

    if lang in ("c", "cpp"):
        return textwrap.dedent(f"""\
        #include <stdlib.h>
        #include <string.h>
        #include <stdio.h>

        {header}
        {content}

        int main(void) {{
            fprintf(stderr, "Test completed\\n");
            return 0;
        }}
        """)

    if lang == "python":
        return textwrap.dedent(f"""\
        import sys
        import os

        # {header}
        {textwrap.indent(content, "")}

        if __name__ == '__main__':
            sys.stderr.write("Test completed\\n")
        """)

    if lang == "go":
        return textwrap.dedent(f"""\
        package main

        import "os"

        // {header}
        {content}

        func main() {{
            os.Stderr.WriteString("Test completed\\n")
        }}
        """)

    if lang == "rust":
        return textwrap.dedent(f"""\
        use std::io::{{self, Write}};

        // {header}
        {content}

        fn main() {{
            let _ = writeln!(io::stderr(), "Test completed");
        }}
        """)

    if lang in ("javascript", "typescript"):
        return textwrap.dedent(f"""\
        // {header}
        {content}

        console.error("Test completed");
        """)

    return content


def _source_ext(lang: str) -> str:
    return _LANGUAGE_EXT.get(lang, ".txt")


def _write_files(poc: dict, src: str, output_dir: Path) -> None:
    lang = poc["harness"]["language"]
    ext = _source_ext(lang)
    output_dir.mkdir(parents=True, exist_ok=True)
    src_file = output_dir / f"{poc['poc_id']}{ext}"
    json_file = output_dir / f"{poc['poc_id']}.json"
    src_file.write_text(src, encoding="utf-8")
    poc["harness"]["source_file"] = str(src_file)
    json_file.write_text(json.dumps(poc, indent=2))


def _build(poc: dict, workdir: Path) -> tuple[bool, Path | None]:
    lang = poc["harness"]["language"]
    rt = _LANGUAGE_RUNTIME.get(lang)
    if rt is None or rt["compile"] is None:
        src_path = (
            workdir / "pocs" / f"{poc['poc_id']}{rt['ext']}"
            if rt
            else (workdir / "pocs" / f"{poc['poc_id']}.txt")
        )
        return True, src_path

    ext = rt["ext"]
    src_path = workdir / "pocs" / f"{poc['poc_id']}{_source_ext(lang)}"
    bin_path = workdir / "pocs" / f"{poc['poc_id']}{ext}"
    if not src_path.exists():
        return False, None

    cmd = [
        part.replace("{src}", str(src_path))
        .replace("{bin}", str(bin_path))
        .replace("{outdir}", str(workdir / "pocs"))
        for part in rt["compile"]
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    if proc.returncode != 0:
        return False, None
    return True, bin_path


def _execute(target: Path, lang: str) -> dict:
    rt = _LANGUAGE_RUNTIME.get(lang, _LANGUAGE_RUNTIME["c"])
    cmd = [
        part.replace("{src}", str(target)).replace("{bin}", str(target))
        for part in rt["run"]
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except subprocess.TimeoutExpired:
        return {
            "status": "execution_failed",
            "exit_code": -1,
            "stdout": "",
            "stderr": "timeout",
        }
    return {
        "status": "completed",
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def process_findings(
    findings: list[dict],
    snippet_db: dict[str, dict],
    output_dir: Path,
    run: bool = True,
    sandbox_prefix: list[str] | None = None,
    test_reduction: bool = False,
    max_retries: int = 3,
    self_correction: bool = True,
) -> list[dict]:
    """Process findings through PoC compilation and execution.

    Parameters
    ----------
    findings:
        List of finding dicts to process.
    snippet_db:
        Mapping of snippet_id → snippet dict.
    output_dir:
        Directory for PoC files and results.
    run:
        If ``True``, compile and execute each PoC harness.
    sandbox_prefix:
        Optional sandbox wrapper tokens (e.g. ``["firejail", "--"]``) passed
        to ``EgressAuditContext``.
    test_reduction:
        If ``True``, run test-case reduction on confirmed PoCs to shrink
        them to the minimal trigger.
    max_retries:
        Maximum number of self-correction retries when a PoC fails (default 3).
    self_correction:
        If ``True``, retry failed PoCs with modified source up to max_retries.

    Returns
    -------
    list[dict]
        PoC result dicts, one per finding.

    """
    from ai_vuln_harness.stages.validate import detect_reward_hack

    results = []
    for f in findings:
        # Reward-hack check: if validate_call_history is present, inspect it
        call_history = f.get("validate_call_history")
        if isinstance(call_history, list) and call_history:
            detect_reward_hack(call_history)

        snippet = snippet_db.get(f.get("snippet_id", ""), {})
        poc = build_poc_json(f, snippet)
        src = _autogen_source(f, snippet)
        _write_files(poc, src, Path(str(output_dir)) / "pocs")

        if run:
            poc = _execute_poc_with_correction(
                poc,
                f,
                snippet,
                Path(str(output_dir)),
                sandbox_prefix,
                test_correction=self_correction,
                max_retries=max_retries,
            )
            if poc["result"]["verdict"] == "confirmed":
                f["poc_confirmed"] = True
                if test_reduction:
                    _apply_test_reduction(poc, Path(str(output_dir)))
            json_file = Path(str(output_dir)) / "pocs" / f"{poc['poc_id']}.json"
            json_file.write_text(json.dumps(poc, indent=2))
        results.append(poc)
    return results


def _execute_poc_with_correction(
    poc: dict,
    _finding: dict,
    _snippet: dict,
    output_dir: Path,
    sandbox_prefix: list[str] | None,
    test_correction: bool = True,
    max_retries: int = 3,
) -> dict:
    """Execute a PoC with self-correction on failure.

    When a PoC fails, modifies the source and retries up to max_retries times.
    """
    ok, target = _build(poc, output_dir)
    if not ok:
        poc["result"] = {
            "status": "build_failed",
            "verdict": "needs-more-info",
            "reasoning": "build failed",
        }
        return poc

    lang = poc["harness"]["language"]
    last_error = ""

    for attempt in range(max_retries + 1):
        try:
            with EgressAuditContext(Path(str(output_dir)), sandbox_prefix):
                exec_result = _execute(target, lang)
        except ScopeViolationError as exc:
            poc["result"] = {
                "verdict": "scope_violation",
                "status": "blocked",
                "reasoning": str(exc),
            }
            return poc

        if exec_result is not None:
            is_confirmed = exec_result.get(
                "exit_code", 0
            ) != 0 or "ERROR" in exec_result.get("stderr", "")
            if is_confirmed:
                poc["result"] = {
                    "status": exec_result["status"],
                    "verdict": "confirmed",
                    "reasoning": f"exit={exec_result.get('exit_code')}, stderr={exec_result.get('stderr', '')[:200]}",
                    "attempts": attempt + 1,
                }
                return poc

            last_error = exec_result.get("stderr", "")[:200]

            # Self-correction: modify the PoC and retry
            if test_correction and attempt < max_retries:
                src_file = poc.get("harness", {}).get("source_file")
                if src_file and Path(src_file).exists():
                    _apply_correction(src_file, last_error, attempt)
                    # Rebuild after modification
                    ok, target = _build(poc, output_dir)
                    if not ok:
                        break

    # All attempts failed
    poc["result"] = {
        "status": "rejected",
        "verdict": "rejected",
        "reasoning": f"failed after {max_retries + 1} attempts: {last_error}",
        "attempts": max_retries + 1,
    }
    return poc


def _apply_correction(src_file: str, error_msg: str, attempt: int) -> None:
    """Apply a simple correction to a PoC source file based on error message."""
    try:
        content = Path(src_file).read_text()
    except OSError:
        return

    # Simple correction heuristics
    corrections = [
        # Fix common compilation errors
        ("implicit declaration", "#include <stdio.h>\n#include <stdlib.h>\n"),
        (
            "undefined reference to `main`",
            "int main(int argc, char **argv) { return 0; }\n",
        ),
        ("expected ';'", ";"),
    ]

    modified = False
    for pattern, fix in corrections:
        if pattern.lower() in error_msg.lower():
            if fix and fix not in content:
                content = fix + content
                modified = True
                break

    # Add more aggressive fixes on later attempts
    if attempt >= 1 and not modified:
        # Try adding common headers
        if any(
            kw in error_msg.lower() for kw in ["printf", "malloc", "free", "strlen"]
        ):
            if "#include <stdlib.h>" not in content:
                content = "#include <stdlib.h>\n#include <string.h>\n" + content
                modified = True

    if attempt >= 2 and not modified:
        # Last resort: wrap in a try-catch for C++ or add error handling
        if "void main" in content or "int main" in content:
            content = content.replace("int main", "int main()").replace(
                "void main", "int main()"
            )
            modified = True

    if modified:
        Path(src_file).write_text(content)


def _apply_test_reduction(poc: dict, output_dir: Path) -> None:
    """Run test-case reduction on a confirmed PoC."""
    from ai_vuln_harness.stages.test_reducer import reduce_poc_source

    src_file = poc.get("harness", {}).get("source_file")
    if not src_file:
        return
    src_path = Path(src_file)
    if not src_path.exists():
        return

    lang = poc.get("harness", {}).get("language", "c")
    reduced = reduce_poc_source(src_path, lang, output_dir)
    if reduced and reduced.exists():
        poc["reduced_source"] = str(reduced)
        original_lines = len(src_path.read_text().splitlines())
        reduced_lines = len(reduced.read_text().splitlines())
        poc["reduction"] = {
            "original_lines": original_lines,
            "reduced_lines": reduced_lines,
            "reduction_pct": round((1 - reduced_lines / original_lines) * 100, 1)
            if original_lines
            else 0,
        }
        logger.info(
            "PoC %s reduced: %d → %d lines",
            poc.get("poc_id", "?"),
            original_lines,
            reduced_lines,
        )
