"""Self-recovery protocol — structured recovery when hunters produce no findings.

When a hunt pass yields zero findings, the system shouldn't just rephrase the
same prompt. It should change methodology. This module provides structured
recovery strategies based on the Glasswing-Open self-recovery protocol.

Strategies:
1. Change approach — read test suite for untested paths
2. Broaden scope — include files the hunter didn't touch
3. Switch attack class — try a different vulnerability class
4. Deepen analysis — trace call chains with more context
5. Check for dead code — find unreachable but reachable paths
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


RECOVERY_STRATEGIES: list[dict] = [
    {
        "name": "read-test-suite",
        "description": "Read the test suite to find untested code paths and edge cases the developer thought about but didn't cover.",
        "prompt_suffix": (
            "Your previous pass found nothing. Change approach: read the test "
            "suite for this subsystem. Look for tests that test edge cases — "
            "those edge cases are where bugs hide. Find code paths that have "
            "NO test coverage — those are the most likely to have vulnerabilities "
            "because nobody verified them."
        ),
    },
    {
        "name": "broaden-scope",
        "description": "Include files adjacent to the target that the hunter didn't touch.",
        "prompt_suffix": (
            "Your previous pass found nothing. Change approach: broaden your "
            "scope to include files in the same directory and related modules. "
            "Look for shared utilities, helper functions, and common patterns "
            "that might be vulnerable in a different context."
        ),
    },
    {
        "name": "switch-attack-class",
        "description": "Try a completely different vulnerability class on the same code.",
        "prompt_suffix": (
            "Your previous pass found nothing. Change approach: instead of "
            "looking for memory corruption, look for logic errors, race "
            "conditions, information leaks, or denial of service. The same "
            "code can have vulnerabilities in multiple classes."
        ),
    },
    {
        "name": "trace-call-chains",
        "description": "Follow function pointers, callbacks, and indirect calls to find hidden entry points.",
        "prompt_suffix": (
            "Your previous pass found nothing. Change approach: trace every "
            "function pointer, callback, and indirect call. Look for registered "
            "handlers, vtable entries, and dispatch tables. These often have "
            "weaker validation than direct callers."
        ),
    },
    {
        "name": "check-dead-code",
        "description": "Find unreachable but reachable code paths (conditional compilation, feature flags, error paths).",
        "prompt_suffix": (
            "Your previous pass found nothing. Change approach: look for code "
            "behind #ifdef, feature flags, debug builds, and error handling "
            "paths. Dead code often has fewer security checks because it was "
            "never exercised in production."
        ),
    },
]


def select_recovery_strategy(
    previous_strategies: list[str] | None = None,
) -> dict | None:
    """Select the next recovery strategy.

    Returns the strategy dict, or None if all strategies exhausted.
    """
    used = set(previous_strategies or [])

    # Round-robin through strategies, skipping already-used ones
    for strategy in RECOVERY_STRATEGIES:
        if strategy["name"] not in used:
            return strategy

    # All strategies used — return None to signal exhaustion
    return None


def build_recovery_prompt(
    base_prompt: str,
    strategy: dict,
    target_files: list[str] | None = None,
) -> str:
    """Build a recovery prompt by appending the strategy's prompt suffix."""
    parts = [base_prompt, "", "--- RECOVERY STRATEGY ---", strategy["prompt_suffix"]]

    if target_files:
        parts.append("")
        parts.append("Additional files to examine:")
        for f in target_files[:10]:
            parts.append(f"  - {f}")

    return "\n".join(parts)


def should_attempt_recovery(
    findings: list[dict],
    domain: str,
    min_findings: int = 1,
) -> bool:
    """Check if recovery should be attempted for a domain.

    Returns True if the domain has fewer than min_findings confirmed findings.
    """
    domain_findings = [
        f
        for f in findings
        if (f.get("domain") or f.get("class") or "") == domain
        and f.get("status") == "confirmed"
    ]
    return len(domain_findings) < min_findings
