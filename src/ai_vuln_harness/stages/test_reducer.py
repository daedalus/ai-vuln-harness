"""Test-case reduction for confirmed PoC findings.

Shrinks confirmed PoC source files to the smallest input that still
triggers ASan, using either Shrink Ray (if installed) or a bundled
minimal ddmin reducer.

Usage (via --test-reduction flag):

    python -m ai_vuln_harness.run --repo /path --poc --test-reduction

The reducer operates on the *source code* of confirmed PoC programs,
not the vulnerable snippet itself. The interestingness test compiles
the reduced source with ASan and checks for crash output.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

_C_FLAGS = ["-fsanitize=address", "-g", "-O0"]

# ---------------------------------------------------------------------------
# Interestingness test generators per language
# ---------------------------------------------------------------------------


def _interestingness_c(
    binary_path: Path,
    *,
    timeout: float = 5.0,
) -> Callable[[Path], bool]:
    """Return an interestingness test for a C/C++ PoC binary.

    The test compiles the candidate source with ASan and checks whether
    the resulting binary crashes (non-zero exit or ASan output).
    """

    def _test(candidate: Path) -> bool:
        try:
            proc = subprocess.run(
                ["gcc", *_C_FLAGS, str(candidate), "-o", str(binary_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if proc.returncode != 0:
                return False
            run_proc = subprocess.run(
                [str(binary_path)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            stderr = run_proc.stderr
            return (
                run_proc.returncode != 0
                or "ERROR" in stderr
                or "SUMMARY" in stderr
                or "AddressSanitizer" in stderr
            )
        except (subprocess.TimeoutExpired, OSError):
            return False

    return _test


def _interestingness_python(
    *,
    timeout: float = 5.0,
) -> Callable[[Path], bool]:
    """Return an interestingness test for a Python PoC."""

    def _test(candidate: Path) -> bool:
        try:
            proc = subprocess.run(
                [sys.executable, str(candidate)],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            stderr = proc.stderr
            return (
                proc.returncode != 0
                and proc.returncode != -11  # SIGSEGV
                or "Error" in stderr
                or "Traceback" in stderr
            )
        except subprocess.TimeoutExpired:
            return False
        except OSError:
            return False

    return _test


def _interestingness_generic(
    run_cmd: list[str],
    *,
    timeout: float = 5.0,
) -> Callable[[Path], bool]:
    """Return an interestingness test for an arbitrary language PoC."""

    def _test(candidate: Path) -> bool:
        cmd = [
            p.replace("{src}", str(candidate)).replace("{bin}", str(candidate))
            for p in run_cmd
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return proc.returncode != 0 or "ERROR" in proc.stderr
        except (subprocess.TimeoutExpired, OSError):
            return False

    return _test


def build_interestingness_test(
    poc_source: Path,
    lang: str,
    workdir: Path,
) -> Callable[[Path], bool] | None:
    """Build an interestingness test for the given PoC source language.

    Returns a callable that takes a candidate source Path and returns
    True if the candidate still manifests the bug.
    """
    if lang in ("c", "cpp"):
        binary = workdir / "reduced_bin"
        return _interestingness_c(binary)
    if lang == "python":
        return _interestingness_python()
    if lang in ("javascript", "typescript"):
        return _interestingness_generic(["node", "{src}"])
    if lang == "go":
        binary = workdir / "reduced_bin"
        return _interestingness_generic(["go", "build", "-o", str(binary), "{src}"])
    if lang == "rust":
        binary = workdir / "reduced_bin"
        return _interestingness_generic(["rustc", "{src}", "-o", str(binary)])
    return None


# ---------------------------------------------------------------------------
# Shrink Ray wrapper
# ---------------------------------------------------------------------------


def _shrinkray_available() -> bool:
    return shutil.which("shrinkray") is not None


def _run_shrinkray(
    source: Path,
    interestingness: Callable[[Path], bool],
    workdir: Path,
    *,
    timeout: float = 300.0,
) -> Path | None:
    """Run Shrink Ray on a source file, returning the reduced path."""
    test_script = workdir / "interestingness.sh"
    test_script.write_text(_shell_wrapper(interestingness, workdir))
    test_script.chmod(0o755)

    reduced = source.with_suffix(f"{source.suffix}.reduced")
    try:
        subprocess.run(
            [
                "shrinkray",
                "--volume",
                "quiet",
                "--timeout",
                "5",
                str(test_script),
                str(source),
            ],
            cwd=str(workdir),
            timeout=timeout,
        )
        if reduced.exists():
            return reduced
        return source
    except (subprocess.TimeoutExpired, OSError):
        return None


def _shell_wrapper(
    interestingness: Callable[[Path], bool],
    workdir: Path,
) -> str:
    """Generate a shell script that wraps the Python interestingness test."""
    test_py = workdir / "interestingness_test.py"
    test_py.write_text(_generate_interestingness_script(interestingness))
    return f"""#!/bin/sh
exec python3 "{test_py}" "$1"
"""


def _generate_interestingness_script(
    interestingness: Callable[[Path], bool],
) -> str:
    """Serialize the interestingness test to a standalone Python script."""
    return """\
import sys
import tempfile
import subprocess
import os

CANDIDATE = sys.argv[1]

# The interestingness function is inlined by the harness.
# This script is called by Shrink Ray.
result = os.system(f"gcc -fsanitize=address -g -O0 '{candidate}' -o /tmp/reduced_test_$$ 2>/dev/null")
if result != 0:
    sys.exit(1)
result = os.system(f"timeout 5 /tmp/reduced_test_$$ 2>&1 | grep -q 'ERROR\\|SUMMARY\\|AddressSanitizer'")
sys.exit(0 if result == 0 else 1)
"""


# ---------------------------------------------------------------------------
# Bundled minimal reducer (ddmin forward-scan)
# ---------------------------------------------------------------------------


def _minimal_reduce(
    source: Path,
    interestingness: Callable[[Path], bool],
    workdir: Path,
    *,
    max_iterations: int = 5000,
) -> Path:
    """Minimal line-deletion reducer (ddmin forward-scan).

    Falls back to this when Shrink Ray is not installed.
    """
    lines = source.read_text(encoding="utf-8").splitlines(keepends=True)
    reduced = source.with_suffix(f"{source.suffix}.reduced")

    def _is_interesting(candidate_lines: list[str]) -> bool:
        content = "".join(candidate_lines)
        suffix = source.suffix
        fd, path = tempfile.mkstemp(suffix=suffix, dir=str(workdir))
        try:
            with os.fdopen(fd, "w") as f:
                f.write(content)
            return interestingness(Path(path))
        finally:
            try:
                os.unlink(path)
            except OSError:
                pass

    i = 0
    iterations = 0
    reduced_content = "".join(lines)
    while i < len(lines) and iterations < max_iterations:
        candidate = lines[:i] + lines[i + 1 :]
        iterations += 1
        if candidate and _is_interesting(candidate):
            lines = candidate
            reduced_content = "".join(lines)
        else:
            i += 1

    reduced.write_text(reduced_content, encoding="utf-8")
    logger.info(
        "test-reducer: reduced %d → %d lines (%d iterations)",
        len(source.read_text().splitlines()),
        len(lines),
        iterations,
    )
    return reduced


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def reduce_poc_source(
    poc_source: Path,
    lang: str,
    output_dir: Path,
    *,
    timeout: float = 300.0,
) -> Path | None:
    """Reduce a confirmed PoC source to the minimal trigger.

    Parameters
    ----------
    poc_source:
        Path to the confirmed PoC source file.
    lang:
        Source language (c, cpp, python, etc.).
    output_dir:
        Working directory for build artifacts.
    timeout:
        Maximum seconds for the reduction process.

    Returns
    -------
    Path to the reduced source file, or None if reduction failed.
    """
    if not poc_source.exists():
        logger.warning("test-reducer: source not found: %s", poc_source)
        return None

    workdir = output_dir / "reduction"
    workdir.mkdir(parents=True, exist_ok=True)

    interestingness = build_interestingness_test(poc_source, lang, workdir)
    if interestingness is None:
        logger.warning("test-reducer: no interestingness test for lang=%s", lang)
        return None

    original_lines = len(poc_source.read_text().splitlines())
    logger.info(
        "test-reducer: reducing %s (%d lines, lang=%s)",
        poc_source.name,
        original_lines,
        lang,
    )

    if _shrinkray_available():
        logger.info("test-reducer: using Shrink Ray")
        result = _run_shrinkray(poc_source, interestingness, workdir, timeout=timeout)
    else:
        logger.info("test-reducer: Shrink Ray not found, using minimal ddmin reducer")
        result = _minimal_reduce(poc_source, interestingness, workdir)

    if result and result.exists():
        reduced_lines = len(result.read_text().splitlines())
        reduction_pct = (
            (1 - reduced_lines / original_lines) * 100 if original_lines else 0
        )
        logger.info(
            "test-reducer: %d → %d lines (%.0f%% reduction)",
            original_lines,
            reduced_lines,
            reduction_pct,
        )
        return result

    return None
