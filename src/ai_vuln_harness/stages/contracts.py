"""Canonical stage contracts, required field schemas, and data flow contracts.

Canonical pipeline order (17 stages):
  INGESTOR → RECON → COORDINATOR → HUNT → LOCALIZATION → VALIDATE →
  FUZZ_ORCHESTRATOR → GAPFILL → VOTING → SHIELD → SUPPRESSIONS → CHAINS →
  POC → TRACE → EXPOSURE → FEEDBACK → REPORT

Every stage is a standalone module under ``stages/`` with a clean import path.
``run.py`` is the only entry point — it imports stages, it does not implement
them. Every stage validates its output against the corresponding schema.

Stage contracts are mandatory: validate outputs against schemas before stage
handoff. Apply bounded repair turns for malformed outputs (limited retries
before escalation).
"""

from __future__ import annotations

from collections.abc import Callable  # noqa: TC003

PIPELINE_STAGES = [
    "ingestor",
    "recon",
    "coordinator",
    "hunt",
    "localization",
    "pbt",
    "validate",
    "fuzz_orchestrator",
    "gapfill",
    "voting",
    "shield",
    "suppressions",
    "chainer",
    "poc",
    "patch",
    "trace",
    "exposure",
    "feedback",
    "report",
]


def standardize_finding(finding: dict) -> dict:
    out = dict(finding)
    out.setdefault("status", "raw")
    out.setdefault("poc_confirmed", False)
    out.setdefault("bucket_rationale", "")
    out.setdefault("call_path", [])
    out.setdefault("suspicious_points", [])
    out.setdefault("has_valid_localization", False)
    out.setdefault("localization_confidence", 0.0)
    return out


def has_valid_suspicious_points(finding: dict) -> bool:
    """Return True when finding contains at least one well-shaped suspicious point."""
    points = finding.get("suspicious_points")
    if not isinstance(points, list) or not points:
        return False
    for point in points:
        if not isinstance(point, dict):
            continue
        function_name = point.get("function")
        file_path = point.get("file")
        lines = point.get("lines")
        sink_type = point.get("sink_source_type")
        confidence = point.get("confidence")
        rationale = point.get("rationale")
        evidence_links = point.get("evidence_links")
        if not isinstance(function_name, str) or not function_name.strip():
            continue
        if not isinstance(file_path, str) or not file_path.strip():
            continue
        if not isinstance(lines, list) or not lines:
            continue
        if not all(isinstance(line, int) and line > 0 for line in lines):
            continue
        if not isinstance(sink_type, str) or not sink_type.strip():
            continue
        if not isinstance(confidence, (int, float)):
            continue
        if not isinstance(rationale, str):
            continue
        if not isinstance(evidence_links, list):
            continue
        if not all(isinstance(link, str) for link in evidence_links):
            continue
        return True
    return False


_TYPE_CHECK = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
}


def validate_subset_schema(data: object, schema: dict, path: str = "$") -> list[str]:
    errors: list[str] = []
    expected_type = schema.get("type")
    py_type = _TYPE_CHECK.get(expected_type)
    if py_type is not None and not isinstance(data, py_type):
        errors.append(f"{path}: expected {expected_type}")
        return errors

    enum = schema.get("enum")
    if enum is not None and data not in enum:
        errors.append(f"{path}: value not in enum {enum}")

    if isinstance(data, dict):
        for req in schema.get("required", []):
            if req not in data:
                errors.append(f"{path}: missing required field {req}")
        props = schema.get("properties", {})
        for k, v in data.items():
            if k in props:
                errors.extend(validate_subset_schema(v, props[k], f"{path}.{k}"))

    if isinstance(data, list):
        item_schema = schema.get("items")
        if item_schema:
            for i, item in enumerate(data):
                errors.extend(validate_subset_schema(item, item_schema, f"{path}[{i}]"))

    return errors


def apply_repair_turns(
    data: object,
    schema: dict,
    repair_fn: Callable[[object, list[str]], object] | None = None,
    max_attempts: int = 2,
) -> tuple[object, list[str]]:
    current = data
    for _ in range(max_attempts + 1):
        errors = validate_subset_schema(current, schema)
        if not errors:
            return current, []
        if repair_fn is None:
            return current, errors
        current = repair_fn(current, errors)
    return current, validate_subset_schema(current, schema)
