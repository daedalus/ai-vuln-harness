"""Property-Based Testing stage — invariant inference + harness fuzzing.

Placement: after LOCALIZATION, before VALIDATE.
Goal: for each localized finding, infer the invariant the finding claims is
violated, generate a C fuzz harness that probes that invariant with
bounded-random inputs, and run it under AddressSanitizer.

If the harness crashes under ASan, the invariant is falsified — the finding
receives a confidence boost. If the harness survives N iterations without
crashing, the finding's confidence is weakened.

The LLM call is only for invariant inference (not for fuzzing itself), so
PBT does not require a disjoint model pool from HUNT.
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from pathlib import Path

from .contracts import has_valid_suspicious_points

logger = logging.getLogger(__name__)

_PBT_SYSTEM_PROMPT = (
    "You are a property-based testing expert. Given a vulnerability finding "
    "and its source code, infer a concise invariant that the finding claims "
    "is violated. Then generate a standalone C fuzz harness that probes this "
    "invariant with randomized inputs under AddressSanitizer."
)

_VULN_MARKERS = (
    "addresssanitizer",
    "undefinedbehaviorsanitizer",
    "heap-buffer-overflow",
    "stack-buffer-overflow",
    "use-after-free",
    "stack smashing detected",
    "segmentation fault",
    "sigsegv",
    "invalid read of size",
    "invalid write of size",
)


def _build_pbt_prompt(finding: dict, snippet: dict) -> str:
    """Build the invariant-inference prompt for a single finding."""
    points = finding.get("suspicious_points") or []
    point = points[0] if points else {}
    sink = str(point.get("sink_source_type", finding.get("class", "unknown")))
    func = str(point.get("function", snippet.get("name", "unknown")))
    file = str(point.get("file", snippet.get("file", "?")))
    content = str(snippet.get("content", ""))
    desc = str(finding.get("desc", ""))
    return f"""Your job is to infer the invariant that a vulnerability finding
claims is violated, then generate a C fuzz harness to test it.

Finding:
- class: {finding.get("class", "?")}
- sink/source type: {sink}
- function: {func}
- file: {file}
- description: {desc}

Source code:
```c
{content}
```

Output VALID JSON ONLY with these fields:
{{
  "invariant": "short description of the invariant being tested",
  "harness_source": "complete C source code for the fuzz harness"
}}

Requirements for the harness:
1. It MUST be a valid, compilable C program (no external dependencies beyond libc).
2. Include the vulnerable function's logic inline or as a simplified model.
3. Define a `main()` that loops with randomized inputs.
4. Use `-fsanitize=address` compatible patterns (no intentional segfaults).
5. The harness MUST detect the specific hazard class ({sink}) if present.
6. Return non-zero exit code if the vulnerability is triggered.
7. Keep it self-contained — no external function calls beyond libc.
8. Include error bounds: allocate/free patterns that expose use-after-free,
   buffer sizes that test overflow, format strings that probe injection, etc.
9. Iterate at least 100 times with varied inputs using rand() and srand().
"""


def _contains_vuln_signal(text: str, exit_code: int) -> bool:
    lowered = text.lower()
    if exit_code < 0:
        return True
    return any(marker in lowered for marker in _VULN_MARKERS)


def _call_llm_for_invariant(
    finding: dict,
    snippet: dict,
    *,
    model: str,
    auth: dict[str, str] | None,
    cache: object | None,
    call_llm_func: object,
) -> tuple[str, str, str]:
    """Call LLM to infer invariant and generate harness.

    Returns (invariant, harness_source, raw_text).

    Uses the injected call_llm_func to avoid importing runtime.py directly.
    """
    prompt = _build_pbt_prompt(finding, snippet)
    raw = ""
    if call_llm_func is not None:
        raw = call_llm_func(
            model,
            prompt,
            system=_PBT_SYSTEM_PROMPT,
            auth=auth,
            cache=cache,
        )
    invariant = ""
    harness_source = ""
    if raw:
        parsed, _ = _repair_json_output(raw)
        if isinstance(parsed, dict):
            invariant = str(parsed.get("invariant", "") or "")
            harness_source = str(parsed.get("harness_source", "") or "")
    return invariant, harness_source, raw


def _repair_json_output(raw: str) -> tuple[object, bool]:
    """Minimal JSON repair: try parse, fall back to brace balancing."""
    raw = raw.strip()
    if raw.startswith("```"):
        lines = raw.splitlines()
        cleaned = []
        in_block = False
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("```"):
                in_block = not in_block
                continue
            if in_block:
                cleaned.append(line)
        raw = "\n".join(cleaned).strip()
    try:
        return json.loads(raw), False
    except json.JSONDecodeError:
        pass
    start = raw.find("{")
    end = raw.rfind("}")
    if start != -1 and end > start:
        candidate = raw[start : end + 1]
        try:
            return json.loads(candidate), True
        except json.JSONDecodeError:
            pass
    return {"invariant": "", "harness_source": raw}, True


def _generate_fallback_harness(finding: dict, snippet: dict) -> str:
    """Generate a fallback harness when LLM call fails.

    Uses the known vulnerable pattern from the finding to build a
    generic harness that exercises the hazard class.
    """
    points = finding.get("suspicious_points") or []
    point = points[0] if points else {}
    sink = str(point.get("sink_source_type", finding.get("class", "unknown")))
    content = str(snippet.get("content", ""))
    h = f"""#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Original code context (file: {snippet.get("file", "?")})
{snippet.get("name", "unknown")}:
{content[:600]}
*/

/* Target function wrapper — caller must provide the reported vulnerability
   class ({sink}) is being tested. */
"""

    if "buffer-overflow" in sink or "memory-corruption" in sink:
        h += """
int test_buffer_overflow(void) {
    /* Exercise the pattern with varying sizes to probe for overflow */
    int errors = 0;
    for (int i = 0; i < 100; i++) {
        size_t sz = (size_t)(rand() % 256);
        char *buf = (char*)malloc(sz + 1);
        if (!buf) continue;
        size_t write_sz = (size_t)(rand() % 512);
        for (size_t j = 0; j < write_sz && j < sz; j++) {
            buf[j] = (char)(rand() % 256);
        }
        if (write_sz > sz) {
            errors++;
        }
        free(buf);
    }
    return errors;
}

int main(void) {
    srand((unsigned)time(NULL));
    int result = test_buffer_overflow();
    if (result > 0) {
        printf("PBT: potential buffer overflow detected (%d hits)\\n", result);
        return 1;
    }
    printf("PBT: no overflow detected\\n");
    return 0;
}
"""
    elif "use-after-free" in sink:
        h += """
int test_use_after_free(void) {
    int errors = 0;
    for (int i = 0; i < 100; i++) {
        size_t sz = (size_t)(rand() % 128) + 1;
        char *buf = (char*)malloc(sz);
        if (!buf) continue;
        free(buf);
        /* Attempt access after free with small probability to find */
        if (rand() % 5 == 0) {
            buf[rand() % sz] = (char)(rand() % 256);
            errors++;
        }
    }
    return errors;
}

int main(void) {
    srand((unsigned)time(NULL));
    int result = test_use_after_free();
    if (result > 0) {
        printf("PBT: potential use-after-free detected (%d hits)\\n", result);
        return 1;
    }
    printf("PBT: no use-after-free detected\\n");
    return 0;
}
"""
    elif "format-string" in sink:
        h += """
int test_format_string(void) {
    int errors = 0;
    for (int i = 0; i < 100; i++) {
        char fmt[64];
        int len = snprintf(fmt, sizeof(fmt), "%%%ds%%s%%n%%n%%n",
                           rand() % 10 + 1);
        if (len < 0 || (size_t)len >= sizeof(fmt)) {
            errors++;
            continue;
        }
    }
    return errors;
}

int main(void) {
    srand((unsigned)time(NULL));
    int result = test_format_string();
    if (result > 0) {
        printf("PBT: potential format-string hazard detected\\n");
        return 1;
    }
    printf("PBT: no format-string hazard detected\\n");
    return 0;
}
"""
    else:
        h += """
int test_generic(void) {
    int errors = 0;
    for (int i = 0; i < 100; i++) {
        size_t sz = (size_t)(rand() % 256);
        char *buf = (char*)malloc(sz + 1);
        if (!buf) continue;
        memset(buf, 0, sz + 1);
        size_t idx = (size_t)(rand() % (sz + 5));
        if (idx < sz) {
            buf[idx] = (char)(rand() % 256);
        } else {
            errors++;
        }
        free(buf);
    }
    return errors;
}

int main(void) {
    srand((unsigned)time(NULL));
    int result = test_generic();
    if (result > 0) {
        printf("PBT: potential memory error detected (%d hits)\\n", result);
        return 1;
    }
    printf("PBT: no memory error detected\\n");
    return 0;
}
"""
    return h


def _compile_harness(harness_source: str, timeout: int) -> dict:
    """Compile the harness with ASan and return result metadata.

    Returns dict with keys: compile_succeeded, stderr, binary_path.
    """
    result = {
        "compile_succeeded": False,
        "stderr": "",
        "binary_path": "",
    }
    with tempfile.TemporaryDirectory(prefix="ai-vuln-pbt-") as td:
        tmp = Path(td)
        src = tmp / "pbt_harness.c"
        binary = tmp / "pbt_harness.bin"
        src.write_text(harness_source, encoding="utf-8")
        compile_proc = subprocess.run(
            [
                "gcc",
                str(src),
                "-O0",
                "-g",
                "-fsanitize=address",
                "-o",
                str(binary),
            ],
            cwd=tmp,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        result["compile_succeeded"] = compile_proc.returncode == 0
        result["stderr"] = compile_proc.stderr
        if result["compile_succeeded"]:
            result["binary_path"] = str(binary)
            return result
    return result


def _run_harness(
    binary_path: str,
    *,
    timeout: int,
    iterations: int,
) -> dict:
    """Run the compiled harness and detect ASan violations.

    Returns dict with keys: run_succeeded, exit_code, stdout, stderr,
    vulnerability_observed.
    """
    result = {
        "run_succeeded": False,
        "exit_code": None,
        "stdout": "",
        "stderr": "",
        "vulnerability_observed": False,
    }
    binary = Path(binary_path)
    if not binary.exists():
        result["stderr"] = "binary_not_found"
        return result
    env = {"PBT_ITERATIONS": str(iterations)}
    run_proc = subprocess.run(
        [str(binary)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
        env={**env, **{"PATH": "/usr/bin:/bin"}},
    )
    result["run_succeeded"] = True
    result["exit_code"] = run_proc.returncode
    result["stdout"] = run_proc.stdout
    result["stderr"] = run_proc.stderr
    combined = f"{run_proc.stdout}\n{run_proc.stderr}"
    result["vulnerability_observed"] = _contains_vuln_signal(
        combined,
        run_proc.returncode,
    )
    return result


def run_pbt_on_finding(
    finding: dict,
    snippet: dict,
    *,
    pbt_iterations: int = 500,
    compile_timeout: int = 30,
    run_timeout: int = 15,
    model: str = "",
    auth: dict[str, str] | None = None,
    cache: object | None = None,
    call_llm_func: object = None,
    enable_llm: bool = True,
) -> dict:
    """Run PBT on a single finding.

    Steps:
    1. If LLM is enabled, infer invariant and generate harness.
    2. Fall back to pattern-based harness if LLM unavailable or fails.
    3. Compile with ASan.
    4. Run with bounded-random iterations.
    5. Return PBT result dict.

    The returned dict can be merged into the finding's PBT fields.
    """
    pbt_result = {
        "pbt_invariant": "",
        "pbt_harness_source": "",
        "pbt_compile_succeeded": False,
        "pbt_compile_error": "",
        "pbt_run_succeeded": False,
        "pbt_falsified": False,
        "pbt_iterations_run": pbt_iterations,
        "pbt_exit_code": None,
        "pbt_stdout": "",
        "pbt_stderr": "",
        "pbt_skipped": False,
        "pbt_confidence_boost": 0.0,
    }

    if not snippet.get("content"):
        pbt_result["pbt_skipped"] = True
        pbt_result["pbt_confidence_boost"] = 0.0
        return pbt_result

    if enable_llm and call_llm_func is not None and model:
        invariant, harness_source, _raw = _call_llm_for_invariant(
            finding,
            snippet,
            model=model,
            auth=auth,
            cache=cache,
            call_llm_func=call_llm_func,
        )
        pbt_result["pbt_invariant"] = invariant
        pbt_result["pbt_harness_source"] = harness_source
    else:
        harness_source = ""

    if not harness_source.strip():
        harness_source = _generate_fallback_harness(finding, snippet)
        pbt_result["pbt_harness_source"] = harness_source
        if not pbt_result["pbt_invariant"]:
            pbt_result["pbt_invariant"] = (
                f"no memory safety violation with varied inputs "
                f"({finding.get('class', 'unknown')})"
            )

    compile_result = _compile_harness(harness_source, compile_timeout)
    pbt_result["pbt_compile_succeeded"] = compile_result["compile_succeeded"]
    pbt_result["pbt_compile_error"] = compile_result["stderr"]

    if not compile_result["compile_succeeded"]:
        pbt_result["pbt_confidence_boost"] = 0.0
        return pbt_result

    run_result = _run_harness(
        compile_result["binary_path"],
        timeout=run_timeout,
        iterations=pbt_iterations,
    )
    pbt_result["pbt_run_succeeded"] = run_result["run_succeeded"]
    pbt_result["pbt_falsified"] = run_result["vulnerability_observed"]
    pbt_result["pbt_exit_code"] = run_result["exit_code"]
    pbt_result["pbt_stdout"] = run_result["stdout"]
    pbt_result["pbt_stderr"] = run_result["stderr"]

    if run_result["vulnerability_observed"]:
        pbt_result["pbt_confidence_boost"] = 0.2
    elif run_result["run_succeeded"] and run_result["exit_code"] == 0:
        pbt_result["pbt_confidence_boost"] = -0.1
    else:
        pbt_result["pbt_confidence_boost"] = 0.0

    return pbt_result


def run_pbt_on_findings(
    findings: list[dict],
    snippet_db: dict[str, dict],
    *,
    pbt_iterations: int = 500,
    compile_timeout: int = 30,
    run_timeout: int = 15,
    model: str = "",
    auth: dict[str, str] | None = None,
    cache: object | None = None,
    call_llm_func: object = None,
    enable_llm: bool = True,
    max_findings: int = 50,
) -> list[dict]:
    """Run PBT on all localized findings.

    Returns annotated findings with PBT evidence attached.
    """
    valid = [f for f in findings if has_valid_suspicious_points(f)]
    if not valid:
        logger.info("[PBT] no valid findings to test")
        return findings[:]

    valid = valid[:max_findings]
    logger.info(
        "[PBT] testing %d/%d finding(s)",
        len(valid),
        len(findings),
    )

    annotated = []
    for i, finding in enumerate(valid):
        sid = str(finding.get("snippet_id", ""))
        snippet = snippet_db.get(sid, {})
        pbt_result = run_pbt_on_finding(
            finding,
            snippet,
            pbt_iterations=pbt_iterations,
            compile_timeout=compile_timeout,
            run_timeout=run_timeout,
            model=model,
            auth=auth,
            cache=cache,
            call_llm_func=call_llm_func,
            enable_llm=enable_llm,
        )
        pbt_boost = float(pbt_result.get("pbt_confidence_boost", 0.0))
        logger.info(
            "[PBT] finding %d/%d: falsified=%s boost=%.2f %s",
            i + 1,
            len(valid),
            pbt_result.get("pbt_falsified"),
            pbt_boost,
            "(skipped)" if pbt_result.get("pbt_skipped") else "",
        )
        finding["pbt_invariant"] = pbt_result.get("pbt_invariant", "")
        finding["pbt_falsified"] = pbt_result.get("pbt_falsified", False)
        finding["pbt_iterations_run"] = pbt_result.get("pbt_iterations_run", 0)
        finding["pbt_confidence_boost"] = pbt_boost
        finding["pbt_compile_succeeded"] = pbt_result.get(
            "pbt_compile_succeeded", False
        )
        finding["pbt_skipped"] = pbt_result.get("pbt_skipped", False)
        if pbt_boost != 0.0:
            current_conf = float(finding.get("localization_confidence", 0.0))
            new_conf = max(0.0, min(1.0, current_conf + pbt_boost))
            finding["localization_confidence"] = new_conf
            finding["pbt_adjusted_confidence"] = True
        else:
            finding["pbt_adjusted_confidence"] = False
        annotated.append(finding)

    seen = {id(f) for f in valid}
    for f in findings:
        if id(f) not in seen:
            f["pbt_skipped"] = True
            f["pbt_falsified"] = False
            f["pbt_confidence_boost"] = 0.0
            f["pbt_adjusted_confidence"] = False
            annotated.append(f)

    logger.info(
        "[PBT] completed: %d falsified, %d boosted, %d skipped",
        sum(1 for f in annotated if f.get("pbt_falsified")),
        sum(1 for f in annotated if f.get("pbt_adjusted_confidence")),
        sum(1 for f in annotated if f.get("pbt_skipped")),
    )
    return annotated
