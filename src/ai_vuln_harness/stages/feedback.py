"""Feedback stage — seed new Hunt tasks from confirmed, traced findings.

After Trace confirms that an attacker-controlled path reaches a sink, the
Feedback stage looks for the same attack class in sibling files (same
directory) that have not yet been covered.  This replicates the Glasswing /
Cloudflare Stage 7 feedback loop, where one real finding multiplies the
search surface before a final Report pass.

The key insight: if ``src/parser/lexer.c`` has a confirmed buffer-overflow,
the other files in ``src/parser/`` share the same coding idioms and should be
hunted for the same class before the pipeline closes.
"""

from __future__ import annotations

from pathlib import Path


def _sibling_files(
    source_file: str,
    all_files: set[str],
    *,
    exclude: set[str] | None = None,
) -> list[str]:
    """Return files in the same directory as *source_file* (excluding itself)."""
    parent = str(Path(source_file).parent)
    excluded = exclude or set()
    return sorted(
        f
        for f in all_files
        if str(Path(f).parent) == parent and f != source_file and f not in excluded
    )


def _build_one_feedback_task(
    finding: dict,
    all_files: set[str],
    covered: set[str],
    seen_keys: set[tuple[str, str]],
    scope_notes: str | None = None,
) -> dict | None:
    source_file = str(finding.get("file") or finding.get("snippet_id") or "")
    attack_class = str(
        finding.get("class")
        or finding.get("attack_class")
        or finding.get("domain")
        or "",
    )
    if not source_file or not attack_class:
        return None

    siblings = _sibling_files(source_file, all_files, exclude=covered)
    if not siblings:
        return None

    key = (str(Path(source_file).parent), attack_class)
    if key in seen_keys:
        return None
    seen_keys.add(key)

    task: dict = {
        "task_id": f"feedback_{attack_class}_{len(seen_keys)}",
        "domain": attack_class,
        "attack_class": attack_class,
        "target_files": siblings,
        "rationale": (
            f"Feedback: confirmed {attack_class!r} in {source_file} — "
            f"scanning {len(siblings)} sibling file(s) for the same pattern."
        ),
        "priority": "high",
        "source": "feedback",
        "seeded_by": source_file,
    }
    if scope_notes:
        task["scope_notes"] = scope_notes
    return task


def build_feedback_tasks(
    traced_findings: list[dict],
    all_snippets: list[dict],
    *,
    already_covered: set[str] | None = None,
    max_tasks: int = 10,
    scope_notes: str | None = None,
) -> list[dict]:
    covered = already_covered or set()
    all_files = {str(s.get("file") or "") for s in all_snippets if s.get("file")}
    seen_keys: set[tuple[str, str]] = set()
    tasks: list[dict] = []

    for finding in traced_findings:
        if len(tasks) >= max_tasks:
            break
        task = _build_one_feedback_task(
            finding,
            all_files,
            covered,
            seen_keys,
            scope_notes,
        )
        if task is not None:
            tasks.append(task)

    return tasks
