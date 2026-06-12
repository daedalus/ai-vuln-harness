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

import hashlib
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


def _finding_id(finding: dict) -> str:
    """Deterministic SHA256-based finding ID for cross-agent dedup.

    ID = SHA256(file_path + vuln_class + line_range).

    Uses the same composite key as report dedup: (file, class, start_line).
    Falls back to snippet_id when file metadata is absent.
    """
    lines = finding.get("lines") or []
    start_line = lines[0] if lines else 0
    end_line = lines[-1] if len(lines) > 1 else start_line
    file_key = str(finding.get("file") or finding.get("snippet_id") or "")
    vuln_class = str(finding.get("class") or "")
    line_range = f"{start_line}-{end_line}"
    raw = f"{file_key}|{vuln_class}|{line_range}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def standardize_finding(finding: dict) -> dict:
    out = dict(finding)
    out.setdefault("finding_id", _finding_id(out))
    out.setdefault("status", "raw")
    out.setdefault("poc_confirmed", False)
    out.setdefault("bucket_rationale", "")
    out.setdefault("call_path", [])
    out.setdefault("suspicious_points", [])
    out.setdefault("has_valid_localization", False)
    out.setdefault("localization_confidence", 0.0)
    return out


def _check_field(
    value: object, typ: type | tuple, validator: Callable[[object], bool] | None = None
) -> bool:
    if not isinstance(value, typ):
        return False
    if validator is not None and not validator(value):
        return False
    return True


def _is_valid_point(point: object) -> bool:
    if not isinstance(point, dict):
        return False
    if not _check_field(point.get("function"), str, lambda s: bool(s.strip())):
        return False
    if not _check_field(point.get("file"), str, lambda s: bool(s.strip())):
        return False
    if not _check_field(
        point.get("lines"),
        list,
        lambda lst: (
            bool(lst) and all(isinstance(line, int) and line > 0 for line in lst)
        ),
    ):
        return False
    if not _check_field(point.get("sink_source_type"), str, lambda s: bool(s.strip())):
        return False
    if not _check_field(point.get("confidence"), (int, float)):
        return False
    if not _check_field(point.get("rationale"), str):
        return False
    if not _check_field(
        point.get("evidence_links"),
        list,
        lambda lst: all(isinstance(link, str) for link in lst),
    ):
        return False
    return True


def has_valid_suspicious_points(finding: dict) -> bool:
    """Return True when finding contains at least one well-shaped suspicious point."""
    points = finding.get("suspicious_points")
    if not isinstance(points, list) or not points:
        return False
    return any(_is_valid_point(point) for point in points)


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
