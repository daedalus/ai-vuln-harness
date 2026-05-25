"""Patch candidate generation — remediation co-pilot stage.

For each confirmed or poc_confirmed finding, builds a structured
``PatchCandidate`` record that describes:

- The recommended fix strategy (class-driven, deterministic).
- The minimal code region to change (extracted from the snippet).
- CWE and severity metadata re-used from the finding.
- A verification plan: re-run the PoC against the patched artefact.

This stage is **deterministic** — it does not call any LLM.  Its output
feeds an optional LLM-driven diff generation step that can be added later
(analogous to how ``run_poc_enabled`` guards the PoC stage).

Glasswing context: Project Glasswing's initial update revealed that the
bottleneck in vulnerability management has shifted from *finding* bugs to
*patching* them.  Across Glasswing's first campaign, >10 000 high/critical
vulnerabilities were discovered; fewer than 1% had been patched within
weeks of disclosure.  This stage directly addresses that gap by structuring
fix guidance for every confirmed finding so that human or LLM patch authors
have a clear starting point.
"""

from __future__ import annotations

_FIX_STRATEGIES: dict[str, str] = {
    "buffer-overflow": (
        "Add an explicit bounds check before the operation that reads or writes "
        "beyond the allocated buffer. Replace unbounded operations (strcpy, gets, "
        "sprintf) with safe API equivalents (strlcpy, fgets, snprintf)."
    ),
    "format-string": (
        "Replace the non-literal format argument with a hard-coded format string. "
        'Use printf("%s", user_input) instead of printf(user_input). '
        "Never pass untrusted data as the format argument."
    ),
    "integer-overflow": (
        "Validate that arithmetic on size/index values cannot overflow before use. "
        "Use checked-arithmetic helpers or cast to a wider unsigned type before the "
        "operation. Assert that the result is within expected bounds."
    ),
    "sql-injection": (
        "Replace string-concatenated queries with parameterised statements / prepared "
        "queries so that user-supplied data is treated as a value, not as SQL syntax."
    ),
    "xss": (
        "HTML-encode all user-supplied values before inserting them into HTML context. "
        "Use a template engine with automatic escaping enabled by default."
    ),
    "path-traversal": (
        "Canonicalise the input path and reject anything that resolves outside the "
        "intended base directory. Verify that realpath() or equivalent starts with "
        "the allowed prefix before proceeding."
    ),
    "auth": (
        "Enforce the authorisation check before the sensitive operation. "
        "Never rely on client-supplied role or session data without server-side "
        "verification. Use a centralised authorisation helper."
    ),
    "crypto": (
        "Replace the deprecated or weak cryptographic primitive with a current, "
        "vetted algorithm. Rotate keys and nonces. Never reuse a nonce/IV for the "
        "same key."
    ),
    "use-after-free": (
        "Set the pointer to NULL immediately after free(). Use RAII / smart pointers "
        "to prevent re-use. Add a static-analysis annotation to catch future regressions."
    ),
    "null-deref": (
        "Add a NULL-pointer guard before every dereference of a pointer that may "
        "be NULL on an error or empty-collection path."
    ),
    "race-condition": (
        "Protect the shared state with an appropriate lock (mutex, rwlock) and ensure "
        "the lock scope covers the entire check-then-act sequence."
    ),
    "command-injection": (
        "Avoid constructing shell commands from user-supplied input. "
        "Use an API that accepts argument arrays (execv, subprocess with a list) "
        "rather than a shell string."
    ),
    "mem-safety": (
        "Audit every pointer dereference, allocation size calculation, and buffer "
        "length check in the affected function. Use memory-safe wrappers or enable "
        "compile-time sanitizers to catch remaining issues."
    ),
    "data-flow": (
        "Trace the full data-flow path from the untrusted source to the sink and "
        "insert a validation/sanitisation step at the earliest trust boundary."
    ),
}

_DEFAULT_STRATEGY = (
    "Review the finding description and apply the minimum change that removes "
    "the dangerous code path. Prefer safe-API replacements over ad-hoc validation."
)

_CWE_MAP: dict[str, str] = {
    "buffer-overflow": "CWE-120",
    "format-string": "CWE-134",
    "integer-overflow": "CWE-190",
    "sql-injection": "CWE-89",
    "xss": "CWE-79",
    "path-traversal": "CWE-22",
    "auth": "CWE-287",
    "crypto": "CWE-327",
    "use-after-free": "CWE-416",
    "null-deref": "CWE-476",
    "race-condition": "CWE-362",
    "command-injection": "CWE-78",
    "mem-safety": "CWE-119",
    "data-flow": "CWE-20",
}

_DEFAULT_CWE = "CWE-20"

_VERIFICATION_PLAN = (
    "Re-run the PoC harness against the patched binary under AddressSanitizer. "
    "A clean exit with no ASan errors confirms the patch eliminates the vulnerability. "
    "Also run the project's existing test suite to verify no regressions were introduced."
)


def _match_strategy(vuln_class: str) -> tuple[str, str]:
    """Return ``(fix_strategy, cwe)`` for *vuln_class* using longest-keyword match.

    The longest matching key wins so that "buffer-overflow" beats "overflow"
    and "use-after-free" beats "auth".  Falls back to the defaults for unknown
    classes.
    """
    needle = vuln_class.lower()
    best_key = ""
    for key in _FIX_STRATEGIES:
        if key in needle and len(key) > len(best_key):
            best_key = key
    strategy = _FIX_STRATEGIES.get(best_key, _DEFAULT_STRATEGY)
    cwe = _CWE_MAP.get(best_key, _DEFAULT_CWE)
    return strategy, cwe


def _is_patchable(finding: dict) -> bool:
    """Return True when the finding is eligible for patch candidate generation.

    Eligible findings are those that have been confirmed by the validate stage,
    marked as fix-now in the report bucket, or confirmed by the PoC stage.
    """
    status = str(finding.get("status", finding.get("validate_status", ""))).lower()
    poc_confirmed = bool(finding.get("poc_confirmed"))
    return poc_confirmed or status in {"confirmed", "fix_now"}


def build_patch_candidates(
    findings: list[dict],
    snippet_db: dict[str, dict] | None = None,
    *,
    include_all: bool = False,
) -> list[dict]:
    """Build patch candidate records for confirmed findings.

    Parameters
    ----------
    findings:
        Output of the VALIDATE / SHIELD / SUPPRESSIONS pipeline stages.
    snippet_db:
        Map from snippet ID to snippet dict, used to extract the vulnerable
        code region and file path.  An empty mapping is safe — the ``code_region``
        field will be empty for findings whose snippet is absent.
    include_all:
        When ``True``, generate candidates for *all* findings regardless of
        status.  Useful for dry-runs and full-coverage reporting.
        Defaults to ``False`` (patchable findings only).

    Returns
    -------
    list[dict]
        One ``PatchCandidate`` dict per eligible finding.  Each record
        contains the fields needed to guide a human or LLM patch author:

        ``patch_id``
            Unique identifier for this candidate.
        ``finding_id``
            Cross-reference back to the source finding.
        ``snippet_id``
            Snippet where the vulnerability was located.
        ``file``
            Relative path of the vulnerable file.
        ``lines``
            ``[start, end]`` line range of the vulnerable function.
        ``vuln_class``
            Vulnerability class string from the finding.
        ``severity``
            Normalised severity string (CRITICAL / HIGH / MEDIUM / LOW).
        ``cwe``
            CWE identifier derived from the vulnerability class.
        ``fix_strategy``
            Human-readable remediation guidance specific to the class.
        ``code_region``
            Verbatim snippet content for the patch author's context.
        ``verification_plan``
            Step-by-step instructions for verifying the patch.
        ``status``
            Always ``"candidate"`` at creation time.
    """
    db = snippet_db or {}
    candidates: list[dict] = []

    for finding in findings:
        if not include_all and not _is_patchable(finding):
            continue

        vuln_class = str(finding.get("class") or finding.get("domain") or "")
        strategy, cwe = _match_strategy(vuln_class)

        snippet_id = finding.get("snippet_id", "")
        snippet = db.get(snippet_id, {})

        finding_id = finding.get("id") or finding.get("finding_id") or snippet_id or ""
        # Use the global candidate counter (not len-after-append) plus a hash of
        # the finding_id to guarantee uniqueness even when multiple findings share
        # the same snippet_id.
        idx = len(candidates) + 1
        fid_tail = finding_id[-8:] if finding_id else "unknown"
        candidate: dict = {
            "patch_id": f"patch-{fid_tail}-{idx:04d}",
            "finding_id": finding_id,
            "snippet_id": snippet_id,
            "file": finding.get("file") or snippet.get("file") or "",
            "lines": finding.get("lines") or snippet.get("lines") or [],
            "vuln_class": vuln_class,
            "severity": str(finding.get("severity", "LOW")).upper(),
            "cwe": cwe,
            "fix_strategy": strategy,
            "code_region": snippet.get("content", ""),
            "verification_plan": _VERIFICATION_PLAN,
            "status": "candidate",
        }
        candidates.append(candidate)

    return candidates
