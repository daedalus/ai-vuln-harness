"""Output content review gate — blocks weaponizable exploit content.

Implements the A3 containment gap from GAP.md: a review layer that inspects
generated exploit code, PoC payloads, and finding descriptions before they
are included in reports or written to disk.

Detection tiers:
  - BLOCK:  Actual exploit payloads (shellcode, ROP gadgets, reverse shells)
  - REDACT: Sensitive details that could enable weaponization (full memory
            dumps, raw addresses, credential material)
  - WARN:   Suspicious patterns that warrant human review

The gate is applied to PoC source code, finding descriptions, and chain
outputs before they reach the report or are written to the filesystem.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum

log = logging.getLogger("vuln-harness")


class ReviewAction(Enum):
    """Disposition of reviewed content."""

    PASS = "pass"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"


@dataclass
class ReviewResult:
    """Result of a content review."""

    action: ReviewAction
    findings: list[str] = field(default_factory=list)
    redacted_content: str | None = None

    @property
    def blocked(self) -> bool:
        return self.action == ReviewAction.BLOCK

    @property
    def redacted(self) -> bool:
        return self.action == ReviewAction.REDACT


# ---------------------------------------------------------------------------
# Detection patterns — organized by severity tier
# ---------------------------------------------------------------------------

_BLOCK_PATTERNS: list[tuple[str, str]] = [
    # Shellcode patterns
    (r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){7,}", "raw shellcode bytes"),
    (r"(?:int\s+main|void\s+start)\s*\(\s*(?:void\s*\*\s*)?\)\s*\{[^}]*"
     r"(?:execve|/bin/sh|/bin/bash)", "shellcode main function"),
    (r"char\s+shellcode\s*\[\s*\]\s*=\s*\{[^}]*0x[0-9a-fA-F]{2}", "shellcode array"),
    # Reverse shell patterns
    (r"(?:bash\s+-i\s+>&\s*/dev/tcp|nc\s+-e\s+/bin/(?:ba)?sh|"
     r"python.*socket.*connect.*subprocess)", "reverse shell"),
    (r"Socket\(\s*AF_INET\s*,\s*SOCK_STREAM\s*\).*connect\s*\(", "raw socket reverse shell"),
    # ROP chain construction
    (r"(?:pop\s+rdi|pop\s+rsi|ret\s*;?\s*(?:#|//)?\s*pop|gadget.*address)",
     "ROP gadget construction"),
    (r"(?:struct\s+rop_chain|rop\s*=\s*\[|chain\.append\(.*ret)",
     "ROP chain builder"),
    # Privilege escalation payloads
    (r"(?:chmod\s+[0-7]*777\s+/etc/passwd|cp\s+/bin/(?:ba)?sh\s+/tmp.*"
     r"&&\s*chmod)", "privilege escalation payload"),
    (r"(?:setuid\s*\(\s*0\s*\)|setgid\s*\(\s*0\s*\).*execve)",
     "setuid shell spawn"),
]

_REDACT_PATTERNS: list[tuple[str, str]] = [
    # Memory layout details that aid exploitation
    (r"(?:libc|heap|stack|vtable|code)\s*(?:_base|_addr|_ptr|_address)?"
     r"\s*[:=]\s*0x[0-9a-fA-F]{8,16}", "memory address disclosure"),
    (r"(?:leak|dump|read)\s*\(.*(?:proc/self/mem|/proc/\d+/mem)",
     "process memory read"),
    (r"/proc/self/mem", "proc mem access"),
    # Credential material in PoC output
    (r"(?:password|secret|api_key|token)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
     "hardcoded credential in output"),
    # Full ASan/dump output that contains exploitation aids
    (r"ASAN.*(?:WRITE|READ)\s+(?:of\s+size\s+\d+\s+at\s+0x[0-9a-fA-F]+)",
     "ASAN address disclosure"),
    # Raw hex addresses in exploitation context
    (r"0x[0-9a-fA-F]{12,16}", "raw memory address"),
]

_WARN_PATTERNS: list[tuple[str, str]] = [
    # Suspicious but potentially legitimate analysis
    (r"(?:exploit|payload|attack|weaponize|weaponise)",
     "exploit-related terminology"),
    (r"(?:overflow|underflow|corrupt|smash|hijack)",
     "memory corruption terminology"),
    (r"(?:privilege\s+escalation|privesc|priv\s+esc)",
     "privilege escalation reference"),
    (r"(?:sandbox\s+escape|jailbreak|breakout)",
     "sandbox escape reference"),
    # Network access in PoC
    (r"(?:curl|wget|requests\.(?:get|post)|urllib)\s*\(",
     "network request in PoC code"),
]


def _scan_content(
    content: str,
    patterns: list[tuple[str, str]],
) -> list[str]:
    """Scan content against a list of (regex, description) patterns.

    Returns list of matched descriptions.
    """
    matches: list[str] = []
    for pat, desc in patterns:
        if re.search(pat, content, re.IGNORECASE | re.DOTALL):
            matches.append(desc)
    return matches


def _redact_content(content: str, patterns: list[tuple[str, str]]) -> str:
    """Replace matched patterns with [REDACTED]."""
    result = content
    for pat, _desc in patterns:
        result = re.sub(pat, "[REDACTED]", result, flags=re.IGNORECASE | re.DOTALL)
    return result


def review_content(
    content: str,
    context: str = "",
    risk_level: str = "standard",
) -> ReviewResult:
    """Review content for weaponizable exploit material.

    Parameters
    ----------
    content:
        Text to review (PoC source, finding description, chain output).
    context:
        Optional context string (e.g. "poc_source", "finding_desc",
        "chain_output") for logging.
    risk_level:
        ``"strict"`` blocks on WARN patterns too.
        ``"standard"`` (default) blocks on BLOCK, redacts on REDACT,
        warns on WARN.

    Returns
    -------
    ReviewResult with action and any findings.
    """
    if not content or not content.strip():
        return ReviewResult(action=ReviewAction.PASS)

    # Tier 1: BLOCK patterns — weaponizable exploit content
    block_matches = _scan_content(content, _BLOCK_PATTERNS)
    if block_matches:
        log.warning(
            "OUTPUT_REVIEW BLOCK [%s]: %s",
            context,
            "; ".join(block_matches),
        )
        return ReviewResult(
            action=ReviewAction.BLOCK,
            findings=block_matches,
        )

    # Tier 2: REDACT patterns — sensitive exploitation aids
    redact_matches = _scan_content(content, _REDACT_PATTERNS)
    if redact_matches:
        redacted = _redact_content(content, _REDACT_PATTERNS)
        log.warning(
            "OUTPUT_REVIEW REDACT [%s]: %s",
            context,
            "; ".join(redact_matches),
        )
        return ReviewResult(
            action=ReviewAction.REDACT,
            findings=redact_matches,
            redacted_content=redacted,
        )

    # Tier 3: WARN patterns — suspicious but potentially legitimate
    warn_matches = _scan_content(content, _WARN_PATTERNS)
    if warn_matches:
        if risk_level == "strict":
            log.warning(
                "OUTPUT_REVIEW BLOCK (strict) [%s]: %s",
                context,
                "; ".join(warn_matches),
            )
            return ReviewResult(
                action=ReviewAction.BLOCK,
                findings=warn_matches,
            )
        log.info(
            "OUTPUT_REVIEW WARN [%s]: %s",
            context,
            "; ".join(warn_matches),
        )
        return ReviewResult(
            action=ReviewAction.WARN,
            findings=warn_matches,
        )

    return ReviewResult(action=ReviewAction.PASS)


def review_finding(finding: dict, risk_level: str = "standard") -> ReviewResult:
    """Review a complete finding dict for dangerous content.

    Checks ``desc``, ``poc_source``, ``exploit_code``, and ``chain_output``
    fields.
    """
    fields_to_check = [
        ("desc", "finding_desc"),
        ("poc_source", "poc_source"),
        ("exploit_code", "exploit_code"),
        ("chain_output", "chain_output"),
        ("attack_vector_desc", "attack_vector"),
    ]

    worst_action = ReviewAction.PASS
    all_findings: list[str] = []
    redacted_content: str | None = None

    for field_name, context in fields_to_check:
        value = finding.get(field_name, "")
        if not value or not isinstance(value, str):
            continue

        result = review_content(value, context=context, risk_level=risk_level)

        # Track worst action (BLOCK > REDACT > WARN > PASS)
        action_priority = {
            ReviewAction.BLOCK: 3,
            ReviewAction.REDACT: 2,
            ReviewAction.WARN: 1,
            ReviewAction.PASS: 0,
        }
        if action_priority[result.action] > action_priority[worst_action]:
            worst_action = result.action
            redacted_content = result.redacted_content

        all_findings.extend(result.findings)

    return ReviewResult(
        action=worst_action,
        findings=all_findings,
        redacted_content=redacted_content,
    )


def review_findings(
    findings: list[dict],
    risk_level: str = "standard",
) -> tuple[list[dict], list[dict]]:
    """Review a list of findings and split into passed/blocked.

    Parameters
    ----------
    findings:
        List of finding dicts.
    risk_level:
        ``"standard"`` or ``"strict"``.

    Returns
    -------
    ``(passed, blocked)`` — findings that passed review and findings that
    were blocked, each annotated with ``review_action`` and ``review_findings``.
    """
    passed: list[dict] = []
    blocked: list[dict] = []

    for f in findings:
        result = review_finding(f, risk_level=risk_level)
        annotated = {**f, "review_action": result.action.value}

        if result.blocked:
            annotated["review_findings"] = result.findings
            blocked.append(annotated)
            log.warning(
                "BLOCKED finding %s: %s",
                f.get("finding_id") or f.get("snippet_id", "?"),
                "; ".join(result.findings),
            )
        elif result.redacted:
            annotated["review_findings"] = result.findings
            if result.redacted_content:
                annotated["desc"] = result.redacted_content
            passed.append(annotated)
            log.info(
                "REDACTED finding %s: %s",
                f.get("finding_id") or f.get("snippet_id", "?"),
                "; ".join(result.findings),
            )
        else:
            passed.append(annotated)

    return passed, blocked
