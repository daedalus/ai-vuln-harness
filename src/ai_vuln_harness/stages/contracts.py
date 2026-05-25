"""Canonical stage contracts, required field schemas, and data flow contracts.

Canonical pipeline order (15 stages):
  INGESTOR → RECON → COORDINATOR → HUNT → VALIDATE → GAPFILL → VOTING →
  SHIELD → SUPPRESSIONS → CHAINS → POC → TRACE → EXPOSURE → FEEDBACK → REPORT

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
    "validate",
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
    return out


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
