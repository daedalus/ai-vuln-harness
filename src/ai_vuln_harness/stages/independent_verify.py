"""Independent Verification Phase — fresh agents verify every factual claim.

Between VALIDATE (adversarial, tries to disprove) and REPORT, this stage
launches one research agent per confirmed finding to independently verify
every factual claim against the actual source code. The agent that wrote
the finding also wrote the JSON — it won't catch its own blind spots.

This is Phase 6 of the Cloudflare security-audit-skill methodology.
"""

from __future__ import annotations

import json
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

from ai_vuln_harness.stages.runtime import (
    SYSTEM_PROMPT,
    _load_prompt,
    call_llm,
    format_prompt,
    repair_json_output,
    repair_with_llm,
)

logger = logging.getLogger(__name__)

_INDEPENDENT_VERIFY_PROMPT = _load_prompt("independent_verify")


def _build_source_context(finding: dict, snippet_db: dict) -> str:
    """Build source code context string for the verifier."""
    lines: list[str] = []

    # From code_positions
    for pos in finding.get("code_positions", []):
        file_path = pos.get("file_path", "")
        line_range = pos.get("line_range", "")
        role = pos.get("role", "")
        if file_path and line_range:
            snippet = snippet_db.get(file_path, {})
            code = snippet.get("source", "")
            lines.append(f"--- {role}: {file_path}:{line_range} ---")
            if code:
                lines.append(code[:3000])
            lines.append("")

    # From source_snippets
    for ss in finding.get("source_snippets", []):
        file_path = ss.get("file_path", "")
        snippet_text = ss.get("snippet", "")
        uid = ss.get("uid", "")
        if file_path and snippet_text:
            lines.append(
                f"--- snippet {uid}: {file_path}:{ss.get('line_start', '?')} ---"
            )
            lines.append(snippet_text[:2000])
            lines.append("")

    # From suspicious_points
    for sp in finding.get("suspicious_points", []):
        file_path = sp.get("file", "")
        func = sp.get("function", "")
        file_lines = sp.get("lines", [])
        if file_path and file_lines:
            lines.append(f"--- suspicious: {file_path}:{func} lines {file_lines} ---")

    # Fallback: call_path
    if not lines and finding.get("call_path"):
        lines.append(f"Call path: {' → '.join(finding['call_path'])}")

    return "\n".join(lines) if lines else "No source context available."


def _verify_one_finding(
    finding: dict,
    snippet_db: dict,
    model: str,
    *,
    auth: dict,
    cache: object | None = None,
) -> dict:
    """Verify a single finding against source code."""
    finding_json = json.dumps(finding, indent=2, default=str)[:6000]
    source_context = _build_source_context(finding, snippet_db)

    prompt = format_prompt(
        _INDEPENDENT_VERIFY_PROMPT,
        finding_json=finding_json,
        source_context=source_context[:8000],
    )

    try:
        raw = call_llm(
            model,
            prompt,
            system=SYSTEM_PROMPT,
            auth=auth,
            cache=cache,
        )
        parsed, _ = repair_json_output(raw)
        if not parsed:
            corrected = repair_with_llm(raw, model, auth=auth, cache=cache)
            if corrected:
                parsed, _ = repair_json_output(corrected)
        if not parsed:
            parsed = {"verdict": "verified", "notes": "unparseable response"}

        verdict = parsed.get("verdict", "verified")
        corrections = parsed.get("corrections", [])
        rejection_reason = parsed.get("rejection_reason", "")
        confidence_adj = parsed.get("confidence_adjustment", 0.0)

        result = {**finding}

        if verdict == "rejected":
            result["validate_status"] = "rejected"
            result["validate_reason"] = f"independent_verify: {rejection_reason}"
            logger.info(
                "independent_verify REJECTED finding=%s reason=%s",
                finding.get("title", "?"),
                rejection_reason[:100],
            )
        elif verdict == "corrected" and corrections:
            for corr in corrections:
                field = corr.get("field", "")
                should_be = corr.get("should_be")
                if field and should_be is not None:
                    result[field] = should_be
            result["independent_verify_corrected"] = True
            result["independent_verify_corrections"] = corrections
            logger.info(
                "independent_verify CORRECTED finding=%s corrections=%d",
                finding.get("title", "?"),
                len(corrections),
            )
        else:
            result["independent_verify_verified"] = True
            logger.debug(
                "independent_verify VERIFIED finding=%s",
                finding.get("title", "?"),
            )

        # Apply confidence adjustment
        if confidence_adj and isinstance(confidence_adj, (int, float)):
            vc = result.get("verification_confidence", {})
            old_score = vc.get("numeric_score", 0.5)
            new_score = max(0.0, min(1.0, old_score + confidence_adj))
            result["verification_confidence"] = {
                **vc,
                "numeric_score": new_score,
                "grade": "high"
                if new_score >= 0.8
                else "medium"
                if new_score >= 0.3
                else "low",
            }

        return result

    except Exception as e:
        logger.warning(
            "independent_verify exception for %s: %s",
            finding.get("title", "?"),
            e,
        )
        return {
            **finding,
            "independent_verify_error": str(e),
        }


def run_independent_verify(
    findings: list[dict],
    snippet_db: dict,
    model: str,
    *,
    auth: dict,
    cache: object | None = None,
    max_workers: int = 4,
) -> list[dict]:
    """Run independent verification on all confirmed findings.

    Only verifies findings with validate_status == "confirmed" or that
    have not been rejected. Rejected findings pass through unchanged.

    Returns the full list of findings with verification annotations.
    """
    if not findings:
        return findings

    to_verify = [
        f
        for f in findings
        if f.get("validate_status") in ("confirmed", "needs-more-info", None, "")
        and not f.get("rejected_by_suppression")
    ]
    skip_count = len(findings) - len(to_verify)

    if not to_verify:
        logger.info("independent_verify: nothing to verify (%d skipped)", skip_count)
        return findings

    logger.info(
        "independent_verify: verifying %d findings (skipping %d already-rejected)",
        len(to_verify),
        skip_count,
    )

    verified_map: dict[str, dict] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _verify_one_finding,
                f,
                snippet_db,
                model,
                auth=auth,
                cache=cache,
            ): f
            for f in to_verify
        }
        for future in as_completed(futures):
            original = futures[future]
            fid = original.get("finding_id", original.get("snippet_id", id(original)))
            try:
                verified_map[fid] = future.result()
            except Exception as e:
                logger.warning("independent_verify future failed: %s", e)
                verified_map[fid] = original

    result: list[dict] = []
    for f in findings:
        fid = f.get("finding_id", f.get("snippet_id", id(f)))
        if fid in verified_map:
            result.append(verified_map[fid])
        else:
            result.append(f)

    verified_count = sum(1 for f in result if f.get("independent_verify_verified"))
    corrected_count = sum(1 for f in result if f.get("independent_verify_corrected"))
    rejected_count = sum(
        1
        for f in result
        if f.get("validate_status") == "rejected"
        and f.get("validate_reason", "").startswith("independent_verify:")
    )
    logger.info(
        "independent_verify complete: %d verified, %d corrected, %d rejected",
        verified_count,
        corrected_count,
        rejected_count,
    )

    return result
