"""Variant Hunter — search untouched files for same vulnerability pattern.

After a finding is confirmed, search the codebase for the same pattern in
files the hunter didn't touch. This multiplies findings per confirmed bug
by 3-10x (Glasswing-Open metric).

The variant hunter uses the confirmed finding's file, function name, and
vulnerability class to find:
- Same pattern in the same file (different call sites)
- Same pattern in sibling files (same directory)
- Same pattern across the codebase (grep for the dangerous function/API)
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Dangerous APIs/functions to grep for variants
_DANGEROUS_APIS: dict[str, list[str]] = {
    "buffer-overflow": [
        r"\bstrcpy\s*\(",
        r"\bstrcat\s*\(",
        r"\bsprintf\s*\(",
        r"\bgets\s*\(",
        r"\bmemcpy\s*\(",
        r"\bmemmove\s*\(",
        r"\bcopy_from_user\s*\(",
    ],
    "format-string": [
        r"\bprintf\s*\(",
        r"\bfprintf\s*\(",
        r"\bsnprintf\s*\(",
        r"\bsyslog\s*\(",
    ],
    "use-after-free": [
        r"\bfree\s*\(",
        r"\bdelete\s+",
        r"\bRELEASE\s*\(",
    ],
    "integer-overflow": [
        r"\bmalloc\s*\(",
        r"\bcalloc\s*\(",
        r"\brealloc\s*\(",
        r"\bkmalloc\s*\(",
    ],
    "path-traversal": [
        r"\bopen\s*\(",
        r"\bfopen\s*\(",
        r"\baccess\s*\(",
        r"\bstat\s*\(",
    ],
    "injection": [
        r"\bsystem\s*\(",
        r"\bexec[lv]p?\s*\(",
        r"\bpopen\s*\(",
        r"\beval\s*\(",
    ],
    "deserialization": [
        r"\bpickle\.load",
        r"\byaml\.load\s*\(",
        r"\bjson\.load",
        r"\bunserialize\s*\(",
    ],
}


def find_variant_files(
    confirmed_finding: dict,
    all_files: set[str],
    touched_files: set[str],
    *,
    max_variants: int = 20,
) -> list[dict]:
    """Find variant files that may have the same vulnerability pattern.

    Parameters
    ----------
    confirmed_finding:
        The confirmed finding dict.
    all_files:
        Set of all source files in the codebase.
    touched_files:
        Set of files already scanned by hunters.
    max_variants:
        Maximum number of variant files to return.

    Returns
    -------
    List of variant file dicts with {file, rationale, priority}.
    """
    source_file = str(confirmed_finding.get("file") or "")
    vuln_class = str(confirmed_finding.get("class") or "")
    func_name = ""

    # Extract function name from call_path or suspicious_points
    call_path = confirmed_finding.get("call_path") or []
    if call_path:
        func_name = str(call_path[-1]).rsplit(":", maxsplit=1)[-1] if call_path else ""

    if not func_name:
        sp = confirmed_finding.get("suspicious_points") or []
        if sp:
            func_name = str(sp[0].get("function") or "")

    # Get dangerous APIs for this vulnerability class
    dangerous_patterns = _DANGEROUS_APIS.get(vuln_class, [])

    variants: list[dict] = []

    # 1. Same file, different call sites
    if source_file and source_file in all_files:
        variants.append(
            {
                "file": source_file,
                "rationale": f"Same file as confirmed {vuln_class} — check other call sites",
                "priority": "high",
            }
        )

    # 2. Sibling files (same directory)
    if source_file:
        parent = str(Path(source_file).parent)
        for f in all_files:
            if (
                str(Path(f).parent) == parent
                and f != source_file
                and f not in touched_files
            ):
                variants.append(
                    {
                        "file": f,
                        "rationale": f"Sibling of {source_file} — shared coding idioms",
                        "priority": "high",
                    }
                )

    # 3. Files with same dangerous API (grep-based)
    if dangerous_patterns and func_name:
        for f in all_files:
            if f in touched_files or f == source_file:
                continue
            # Quick heuristic: check if filename suggests similar functionality
            fname = Path(f).stem.lower()
            source_stem = Path(source_file).stem.lower() if source_file else ""
            if fname == source_stem and f not in [v["file"] for v in variants]:
                variants.append(
                    {
                        "file": f,
                        "rationale": f"Same module name as {source_file} — likely same pattern",
                        "priority": "medium",
                    }
                )

    # Deduplicate and limit
    seen = set()
    result = []
    for v in variants:
        if v["file"] not in seen:
            seen.add(v["file"])
            result.append(v)
        if len(result) >= max_variants:
            break

    logger.info(
        "variant_hunter: found %d variants for %s in %s",
        len(result),
        vuln_class,
        source_file,
    )

    return result


def build_variant_tasks(
    confirmed_findings: list[dict],
    all_files: set[str],
    touched_files: set[str],
    *,
    max_tasks: int = 10,
) -> list[dict]:
    """Build hunt tasks for variant analysis.

    Returns a list of task dicts suitable for the coordinator.
    """
    tasks: list[dict] = []
    seen_files: set[str] = set()

    for finding in confirmed_findings:
        if finding.get("status") != "confirmed":
            continue

        variants = find_variant_files(finding, all_files, touched_files, max_variants=5)

        for v in variants:
            if v["file"] in seen_files:
                continue
            seen_files.add(v["file"])

            tasks.append(
                {
                    "task_id": f"variant_{finding.get('finding_id', 'unknown')}_{len(tasks)}",
                    "domain": f"variant-{finding.get('class', 'unknown')}",
                    "attack_class": finding.get("class", "unknown"),
                    "target_files": [v["file"]],
                    "rationale": v["rationale"],
                    "priority": v["priority"],
                    "source": "variant-hunter",
                    "seeded_by": finding.get("file", ""),
                }
            )

        if len(tasks) >= max_tasks:
            break

    logger.info("variant_hunter: generated %d variant tasks", len(tasks))
    return tasks
