"""Hunt-stage voting: merge outputs from multiple hunter runs and promote
only findings that appear in at least *min_votes* independent outputs.

This cuts noise before it reaches the Validate stage.
"""

from __future__ import annotations

import re
from collections import defaultdict

# ---------------------------------------------------------------------------
# Complexity scoring (Mythos system card §4.3.1)
# ---------------------------------------------------------------------------

_CONJUNCTIVE_CONNECTORS = re.compile(
    r"\b(and|also|additionally|furthermore|requires\s+that|only\s+if)\b",
    re.IGNORECASE,
)

_CALL_PATH_CEILING = 8
_CONNECTOR_CEILING = 5
_FILE_CEILING = 4


def complexity_score(finding: dict) -> float:
    """Return a 0.0–1.0 complexity score for a finding.

    Higher scores indicate more over-engineered, multi-precondition findings
    that are statistically more likely to be false positives (Mythos system
    card §4.3.1).

    Components:

    - **call_path score** — ``len(call_path) / 8`` capped at 1.0.
    - **connector score** — count of conjunctive connectors ("and", "also",
      "additionally", "furthermore", "requires that", "only if") in ``desc``
      divided by 5, capped at 1.0.
    - **file score** — count of distinct files referenced in ``call_path``
      divided by 4, capped at 1.0.

    Weighted average: ``0.5 * call_path + 0.3 * connectors + 0.2 * files``.

    Parameters
    ----------
    finding:
        A finding dict, expected to contain optional keys ``call_path``
        (list) and ``desc`` (str).

    Returns
    -------
    float
        Score in [0.0, 1.0].

    """
    call_path: list[object] = finding.get("call_path") or []
    desc: str = str(finding.get("desc") or "")

    # Call-path length component
    cp_score = min(len(call_path) / _CALL_PATH_CEILING, 1.0)

    # Conjunctive connector component
    connector_count = len(_CONJUNCTIVE_CONNECTORS.findall(desc))
    conn_score = min(connector_count / _CONNECTOR_CEILING, 1.0)

    # Distinct files in call path component
    distinct_files: set[str] = set()
    for entry in call_path:
        if isinstance(entry, str):
            # Accept "file.c:func" or bare "file.c" patterns
            part = entry.split(":")[0]
            if part:
                distinct_files.add(part)
        elif isinstance(entry, dict):
            f = entry.get("file") or entry.get("path") or ""
            if f:
                distinct_files.add(str(f))
    file_score = min(len(distinct_files) / _FILE_CEILING, 1.0)

    return 0.5 * cp_score + 0.3 * conn_score + 0.2 * file_score


_COMPLEXITY_PENALTY_THRESHOLD = 0.75


def _finding_key(finding: dict) -> tuple[str, str]:
    """Canonical dedup key: (snippet_id, vulnerability class)."""
    return (
        str(finding.get("snippet_id") or ""),
        str(finding.get("class") or ""),
    )


def _severity_rank(sev: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(sev).upper(), 0)


def _count_votes(
    outputs: list[list[dict]],
) -> tuple[dict[tuple[str, str], int], dict[tuple[str, str], dict]]:
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
    return vote_counts, best_variant


def _build_results(
    best_variant: dict[tuple[str, str], dict],
    vote_counts: dict[tuple[str, str], int],
    min_votes: int,
) -> tuple[list[dict], list[dict]]:
    promoted: list[dict] = []
    suppressed: list[dict] = []
    for key, variant in best_variant.items():
        count = vote_counts[key]
        cscore = complexity_score(variant)
        annotated = {**variant, "vote_count": count, "complexity_score": cscore}
        if count >= min_votes:
            if cscore > _COMPLEXITY_PENALTY_THRESHOLD and count == min_votes:
                annotated["suppressed_reason"] = "complexity_penalty"
                suppressed.append(annotated)
            else:
                promoted.append(annotated)
        else:
            suppressed.append(annotated)
    return promoted, suppressed


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
        threshold, each annotated with a ``vote_count`` field and a
        ``complexity_score`` field.
        *suppressed* contains findings that did not reach threshold, plus
        findings demoted by the complexity penalty (annotated with
        ``"suppressed_reason": "complexity_penalty"``).

    """
    if not outputs:
        return [], []

    if len(outputs) == 1:
        result = []
        for f in outputs[0] or []:
            annotated = {**f, "vote_count": 1, "complexity_score": complexity_score(f)}
            result.append(annotated)
        return result, []

    vote_counts, best_variant = _count_votes(outputs)
    return _build_results(best_variant, vote_counts, min_votes)
