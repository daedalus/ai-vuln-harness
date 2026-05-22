"""Hunt-stage voting: merge outputs from multiple hunter runs and promote
only findings that appear in at least *min_votes* independent outputs.

This cuts noise before it reaches the Validate stage.
"""

from __future__ import annotations

from collections import defaultdict


def _finding_key(finding: dict) -> tuple[str, str]:
    """Canonical dedup key: (snippet_id, vulnerability class)."""
    return (
        str(finding.get("snippet_id") or ""),
        str(finding.get("class") or ""),
    )


def _severity_rank(sev: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(sev).upper(), 0)


def merge_hunter_outputs(
    outputs: list[list[dict]],
    min_votes: int = 2,
) -> tuple[list[dict], list[dict]]:
    """Merge findings from multiple hunter runs.

    Parameters
    ----------
    outputs:
        List of finding lists, one per hunter run.
    min_votes:
        Minimum number of runs a finding must appear in to be promoted.
        Defaults to 2 (majority of two or more hunters required).

    Returns
    -------
    (promoted, suppressed)
        *promoted* contains deduplicated findings that reached the vote
        threshold, each annotated with a ``vote_count`` field.
        *suppressed* contains findings that did not reach threshold.

    """
    if not outputs:
        return [], []

    # Single-run fast path: return all findings unchanged, vote_count=1
    if len(outputs) == 1:
        return [{**f, "vote_count": 1} for f in (outputs[0] or [])], []

    # Count votes per (snippet_id, class) and keep the highest-severity variant
    vote_counts: dict[tuple[str, str], int] = defaultdict(int)
    best_variant: dict[tuple[str, str], dict] = {}

    for run in outputs:
        seen_in_run: set[tuple[str, str]] = set()
        for f in run or []:
            key = _finding_key(f)
            if not key[0]:
                continue
            if key not in seen_in_run:
                vote_counts[key] += 1
                seen_in_run.add(key)
            existing = best_variant.get(key)
            if existing is None or _severity_rank(
                f.get("severity", ""),
            ) > _severity_rank(existing.get("severity", "")):
                best_variant[key] = f

    promoted: list[dict] = []
    suppressed: list[dict] = []

    for key, variant in best_variant.items():
        count = vote_counts[key]
        annotated = {**variant, "vote_count": count}
        if count >= min_votes:
            promoted.append(annotated)
        else:
            suppressed.append(annotated)

    return promoted, suppressed
