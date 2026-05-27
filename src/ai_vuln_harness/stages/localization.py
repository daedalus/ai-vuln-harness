"""Deterministic localization stage for normalizing suspicious points."""

from __future__ import annotations

from .contracts import has_valid_suspicious_points, standardize_finding
from .shield import (
    annotate_hallucination,
    build_call_graph,
    filter_unreachable,
    verify_call_path,
)

_HIGH_PRIORITY_SINKS = frozenset(
    {
        "memory-corruption",
        "buffer-overflow",
        "use-after-free",
        "format-string",
        "command-injection",
        "path-traversal",
    },
)

_DEFAULT_SINK = "generic"


def _sink_source_type(finding: dict) -> str:
    vuln_class = str(finding.get("class", "")).strip().lower()
    if vuln_class:
        return vuln_class
    tags = finding.get("tags")
    if isinstance(tags, list) and tags:
        return str(tags[0]).strip().lower() or _DEFAULT_SINK
    return _DEFAULT_SINK


def _point_confidence(
    finding: dict,
    call_path_verified: bool,
    reachable: bool,
    hallucination_detected: bool,
) -> float:
    confidence = 0.35
    vote_count = finding.get("vote_count", 1)
    if isinstance(vote_count, int):
        confidence += min(vote_count, 3) * 0.1
    if call_path_verified:
        confidence += 0.2
    if reachable:
        confidence += 0.2
    if not hallucination_detected:
        confidence += 0.1
    return max(0.0, min(1.0, confidence))


def _line_numbers(finding: dict, snippet: dict) -> list[int]:
    lines = finding.get("lines")
    if isinstance(lines, list) and lines and all(isinstance(v, int) for v in lines):
        return [int(v) for v in lines]
    snippet_lines = snippet.get("lines")
    if (
        isinstance(snippet_lines, list)
        and snippet_lines
        and all(isinstance(v, int) for v in snippet_lines)
    ):
        return [int(v) for v in snippet_lines]
    return [1]


def _function_name(finding: dict, snippet: dict) -> str:
    call_path = finding.get("call_path")
    if isinstance(call_path, list) and call_path:
        first = call_path[0]
        if isinstance(first, str) and first.strip():
            return first.strip()
    for key in ("function_name", "name", "snippet_id"):
        value = finding.get(key) or snippet.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return "unknown"


def _evidence_links(finding: dict, snippet: dict) -> list[str]:
    links = [str(finding.get("snippet_id", ""))]
    snippet_file = str(snippet.get("file", "")).strip()
    if snippet_file:
        links.append(snippet_file)
    call_path = finding.get("call_path")
    if isinstance(call_path, list):
        links.extend(str(entry) for entry in call_path if isinstance(entry, str))
    return [entry for entry in links if entry]


def _build_suspicious_point(
    finding: dict,
    snippet: dict,
    *,
    call_path_verified: bool,
    reachable: bool,
    hallucination_detected: bool,
    call_path_reason: str,
) -> dict:
    sink_source_type = _sink_source_type(finding)
    confidence = _point_confidence(
        finding,
        call_path_verified=call_path_verified,
        reachable=reachable,
        hallucination_detected=hallucination_detected,
    )
    return {
        "function": _function_name(finding, snippet),
        "file": str(
            finding.get("file")
            or snippet.get("file")
            or finding.get("snippet_id")
            or "unknown"
        ),
        "lines": _line_numbers(finding, snippet),
        "sink_source_type": sink_source_type,
        "confidence": confidence,
        "rationale": (
            f"call_path={call_path_reason}, reachable={'yes' if reachable else 'no'}, "
            f"hallucination={'yes' if hallucination_detected else 'no'}"
        ),
        "evidence_links": _evidence_links(finding, snippet),
    }


def localize_findings(
    findings: list[dict],
    snippet_db: dict[str, dict],
    *,
    entry_points: list[str] | None = None,
    max_hops: int = 6,
) -> tuple[list[dict], list[dict]]:
    """Attach normalized suspicious points and split findings by reachability."""
    if not findings:
        return [], []
    entry_points = entry_points or []
    snippets = list(snippet_db.values())
    graph = build_call_graph(snippets)
    annotated = annotate_hallucination(findings, snippet_db)
    reachable, unreachable = filter_unreachable(
        annotated,
        graph,
        entry_points,
        max_hops=max_hops,
    )
    reachable_ids = {id(item) for item in reachable}

    localized: list[dict] = []
    for finding in annotated:
        standardized = standardize_finding(finding)
        sid = str(standardized.get("snippet_id", ""))
        snippet = snippet_db.get(sid, {})
        verified, reason = verify_call_path(standardized, graph)
        is_reachable = id(finding) in reachable_ids
        hallucination_detected = bool(standardized.get("hallucination_detected"))
        suspicious_point = _build_suspicious_point(
            standardized,
            snippet,
            call_path_verified=verified,
            reachable=is_reachable,
            hallucination_detected=hallucination_detected,
            call_path_reason=reason,
        )
        sink = str(suspicious_point.get("sink_source_type", ""))
        is_high_priority_sink = sink in _HIGH_PRIORITY_SINKS
        point_confidence = float(suspicious_point.get("confidence", 0.0))
        points = [suspicious_point]
        updated = {
            **standardized,
            "suspicious_points": points,
            "call_path_verified": verified,
            "call_path_reason": reason,
            "has_valid_localization": has_valid_suspicious_points(
                {"suspicious_points": points},
            ),
            "localization_confidence": point_confidence,
            "high_priority_validate": bool(
                point_confidence >= 0.55 and is_high_priority_sink
            ),
            "localization_tier": (
                "high"
                if point_confidence >= 0.75
                else ("medium" if point_confidence >= 0.55 else "low")
            ),
            "localization_enforced": True,
        }
        localized.append(updated)
    return localized, unreachable
