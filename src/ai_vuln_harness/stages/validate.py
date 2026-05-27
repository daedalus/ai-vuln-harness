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

import math
import re
import string
import subprocess
import tempfile
from collections import Counter
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
    """Build the adversarial validation prompt for a finding.

    Note:
        Before calling this in a multi-attempt loop, run
        ``detect_reward_hack(call_history)`` to check whether repeated identical
        reasoning is masking reward-hacking behaviour (Mythos system card §4.2.2).
    """
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
    "valgrind",
    "invalid read of size",
    "invalid write of size",
    "use of uninitialised value",
    "definitely lost:",
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


def _extract_binary_path(finding: dict, snippet: dict) -> str:
    for candidate in (
        finding.get("binary_path"),
        snippet.get("binary_path"),
    ):
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
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
    binary_path = _extract_binary_path(finding, snippet)
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

    sandbox_prefix = sandbox_prefix or []

    if binary_path:
        bin_path = Path(binary_path)
        if not bin_path.exists() or not bin_path.is_file():
            result["error"] = "binary_not_found"
            return result
        result["run_attempted"] = True
        run_cmd = [*sandbox_prefix, str(bin_path)]
        run_proc = subprocess.run(
            run_cmd,
            cwd=bin_path.parent,
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

    if not source or not _is_c_or_cpp(snippet):
        return result

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


# ---------------------------------------------------------------------------
# Reward-hack / grind detector (Mythos system card §4.2.2)
# ---------------------------------------------------------------------------

_PUNCT_RE = re.compile(r"[" + re.escape(string.punctuation) + r"]")
_WS_RE = re.compile(r"\s+")


def _normalise_reason(text: str) -> str:
    """Lowercase, strip punctuation, collapse whitespace."""
    text = text.lower()
    text = _PUNCT_RE.sub(" ", text)
    return _WS_RE.sub(" ", text).strip()


def _bigram_counter(text: str) -> Counter[str]:
    """Character bigram Counter for TF-IDF cosine similarity (stdlib only)."""
    return Counter(text[i : i + 2] for i in range(len(text) - 1))


def _cosine_similarity(a: Counter[str], b: Counter[str]) -> float:
    """Cosine similarity between two Counter vectors."""
    if not a or not b:
        return 0.0
    dot = sum(a[k] * b[k] for k in a if k in b)
    mag_a = math.sqrt(sum(v * v for v in a.values()))
    mag_b = math.sqrt(sum(v * v for v in b.values()))
    if mag_a == 0.0 or mag_b == 0.0:
        return 0.0
    return dot / (mag_a * mag_b)


_SIMILARITY_THRESHOLD = 0.92
_MIN_IDENTICAL_CALLS = 3


def detect_reward_hack(call_history: list[dict]) -> bool:
    """Detect reward-hacking / grind behaviour in a validate call history.

    Inspects the ``reason`` text of each call dict.  If at least
    ``_MIN_IDENTICAL_CALLS`` (3) calls are structurally identical
    (pairwise cosine similarity of TF-IDF character bigrams >
    ``_SIMILARITY_THRESHOLD``) **and** the finding flipped from
    ``rejected`` to ``confirmed`` across those calls, the finding is
    annotated in-place with ``"reward_hacked": True`` and its status is
    downgraded to ``"needs-more-info"``.

    Parameters
    ----------
    call_history:
        List of dicts, each representing one validate call.  Expected keys:
        ``"reason"`` (str) and ``"status"`` (str, one of
        ``confirmed|rejected|needs-more-info``).

    Returns
    -------
    bool
        ``True`` when reward-hacking is detected and the finding has been
        mutated; ``False`` otherwise.

    """
    if len(call_history) < _MIN_IDENTICAL_CALLS:
        return False

    norms = [_normalise_reason(str(c.get("reason", ""))) for c in call_history]
    bigrams = [_bigram_counter(n) for n in norms]

    # Count how many call pairs are structurally identical
    identical_count = 0
    for i in range(len(bigrams)):
        for j in range(i + 1, len(bigrams)):
            if _cosine_similarity(bigrams[i], bigrams[j]) > _SIMILARITY_THRESHOLD:
                identical_count += 1

    # Need at least C(min_identical, 2) pairs for min_identical identical calls
    min_pairs = (_MIN_IDENTICAL_CALLS * (_MIN_IDENTICAL_CALLS - 1)) // 2
    if identical_count < min_pairs:
        return False

    # Check for status flip: rejected → confirmed
    statuses = [str(c.get("status", "")) for c in call_history]
    has_rejected = "rejected" in statuses
    has_confirmed = "confirmed" in statuses
    if not (has_rejected and has_confirmed):
        return False

    # Annotate all call dicts and return True
    for c in call_history:
        c["reward_hacked"] = True
        c["status"] = "needs-more-info"
    return True


# ---------------------------------------------------------------------------
# Confabulation cascade guard (Mythos system card §4.3.3)
# ---------------------------------------------------------------------------


def build_negation_probe_prompt(finding: dict, snippet: dict) -> str:
    """Build a negation-probe prompt to expose confabulation risk.

    Asks the validator to argue the *opposite* position — that the finding
    is NOT a vulnerability.  If the model agrees with both the original
    prompt and this negation, ``confabulation_risk`` will flag it.

    Parameters
    ----------
    finding:
        The finding dict (same as passed to ``build_validate_prompt``).
    snippet:
        The source snippet dict (same as passed to ``build_validate_prompt``).

    Returns
    -------
    str
        A prompt string requesting the strongest false-positive argument.

    """
    return (
        f"Assume the opposite: this is NOT a vulnerability because "
        f"'{finding.get('class', 'unknown')}' does not apply here.\n\n"
        f"Finding:\n"
        f"- snippet_id: {finding.get('snippet_id', '?')}\n"
        f"- class: {finding.get('class', '?')}\n"
        f"- description: {finding.get('desc', '')}\n\n"
        f"ACTUAL SOURCE CODE (file: {snippet.get('file', '?')}, "
        f"lines {snippet.get('lines', '?')}):\n"
        f"```c\n{snippet.get('content', '')}\n```\n\n"
        "Provide the strongest argument that this finding is a false positive.\n\n"
        'Output ONLY JSON: {"status": "plausible_fp|implausible_fp", "reason": "..."}'
    )


def confabulation_risk(validate_result: dict, negation_result: dict) -> bool:
    """Return True when the model agreed with both the finding and its negation.

    This indicates a confabulation cascade: the model produced two confident,
    mutually contradictory assessments without surfacing the contradiction
    (Mythos system card §4.3.3).

    Parameters
    ----------
    validate_result:
        Result dict from the standard validate prompt.  Expected key:
        ``"status"`` (str).
    negation_result:
        Result dict from the negation probe prompt.  Expected key:
        ``"status"`` (str).

    Returns
    -------
    bool
        ``True`` iff ``validate_result["status"] == "confirmed"`` **and**
        ``negation_result["status"] == "plausible_fp"``.

    """
    return (
        str(validate_result.get("status", "")) == "confirmed"
        and str(negation_result.get("status", "")) == "plausible_fp"
    )
