"""Hunt-stage voting: merge outputs from multiple hunter runs and promote
only findings that appear in at least *min_votes* independent outputs.

This cuts noise before it reaches the Validate stage.

Improvements:
- 3-tier validation model (Tier 1=Confirmed, Tier 2=Plausible, Tier 3=Theoretical)
- Severity gating: High/Critical requires Tier 1 or Tier 2
- Confidence aggregation across votes
- Evidence accumulation from multiple hunters
- Semantic dedup via embedding similarity (optional)
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

# ---------------------------------------------------------------------------
# 3-tier validation model (from anshug/claude-mythos)
# ---------------------------------------------------------------------------

TIER_CONFIRMED = 1  # Runtime exploit executed successfully
TIER_PLAUSIBLE = 2  # Validated code path, no runtime confirmation
TIER_THEORETICAL = 3  # Pattern match only, no validation

_TIER_RANK = {
    "confirmed": TIER_CONFIRMED,
    "plausible": TIER_PLAUSIBLE,
    "theoretical": TIER_THEORETICAL,
}
_TIER_NAMES = {
    TIER_CONFIRMED: "confirmed",
    TIER_PLAUSIBLE: "plausible",
    TIER_THEORETICAL: "theoretical",
}


def _determine_validation_tier(finding: dict) -> int:
    """Determine validation tier from finding attributes.

    Tier 1 (Confirmed): poc_confirmed=True, or confidence >= 0.9
    Tier 2 (Plausible): confidence >= 0.6, or has suspicious_points
    Tier 3 (Theoretical): everything else
    """
    if finding.get("poc_confirmed"):
        return TIER_CONFIRMED
    confidence = finding.get("confidence") or finding.get("validate_confidence") or 0.0
    if confidence >= 0.9:
        return TIER_CONFIRMED
    if confidence >= 0.6 or finding.get("suspicious_points"):
        return TIER_PLAUSIBLE
    return TIER_THEORETICAL


def _validate_severity_tier(finding: dict, *, enforce: bool = False) -> dict:
    """Enforce severity gating: High/Critical requires Tier 1 or Tier 2.

    If enforce=True and a finding is marked High/Critical but is only Tier 3
    (Theoretical), downgrade to Medium. This prevents unconfirmed findings from
    being reported as high-severity.

    Default is enforce=False to preserve backward compatibility.
    """
    if not enforce:
        return finding
    tier = finding.get("validation_tier", TIER_THEORETICAL)
    severity = str(finding.get("severity", "")).upper()
    if severity in ("CRITICAL", "HIGH") and tier == TIER_THEORETICAL:
        finding["severity"] = "MEDIUM"
        finding["severity_downgraded"] = True
        finding["downgrade_reason"] = (
            f"High/Critical requires Tier 1 or 2, was Tier {tier}"
        )
    return finding


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


def _finding_key(finding: dict) -> str:
    """Deterministic dedup key using SHA256-based finding_id.

    Falls back to (snippet_id, class) when finding_id is absent.
    Returns empty string when no valid key can be constructed.
    """
    fid = finding.get("finding_id")
    if fid:
        return fid
    snippet_id = str(finding.get("snippet_id") or "")
    if not snippet_id:
        return ""
    return snippet_id + "|" + str(finding.get("class") or "")


def _severity_rank(sev: str) -> int:
    return {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(str(sev).upper(), 0)


def _aggregate_finding_data(
    key: str,
    finding: dict,
    confidence_sums: dict[str, float],
    confidence_counts: dict[str, int],
    evidence_acc: dict[str, list[dict]],
    hunter_acc: dict[str, list[str]],
) -> None:
    """Aggregate confidence, evidence, and hunter info for a single finding."""
    conf = finding.get("confidence") or finding.get("validate_confidence") or 0.0
    if conf > 0:
        confidence_sums[key] += conf
        confidence_counts[key] += 1

    points = finding.get("suspicious_points") or []
    if points:
        evidence_acc[key].extend(points)

    model = finding.get("hunt_model") or finding.get("model") or "unknown"
    if model not in hunter_acc[key]:
        hunter_acc[key].append(model)


def _annotate_best_variants(
    best_variant: dict[str, dict],
    confidence_sums: dict[str, float],
    confidence_counts: dict[str, int],
    evidence_acc: dict[str, list[dict]],
    hunter_acc: dict[str, list[str]],
) -> None:
    """Annotate best variants with aggregated confidence, evidence, hunters."""
    for key, variant in best_variant.items():
        if confidence_counts[key] > 0:
            variant["aggregated_confidence"] = round(
                confidence_sums[key] / confidence_counts[key],
                3,
            )
        if evidence_acc[key]:
            variant["accumulated_evidence"] = evidence_acc[key]
        if hunter_acc[key]:
            variant["hunter_models"] = hunter_acc[key]


def _count_votes(
    outputs: list[list[dict]],
) -> tuple[dict[str, int], dict[str, dict]]:
    """Count votes and aggregate confidence/evidence across hunters."""
    vote_counts: dict[str, int] = defaultdict(int)
    best_variant: dict[str, dict] = {}
    confidence_sums: dict[str, float] = defaultdict(float)
    confidence_counts: dict[str, int] = defaultdict(int)
    evidence_acc: dict[str, list[dict]] = defaultdict(list)
    hunter_acc: dict[str, list[str]] = defaultdict(list)

    for run in outputs:
        seen_in_run: set[str] = set()
        for f in run or []:
            key = _finding_key(f)
            if not key:
                continue
            if key not in seen_in_run:
                vote_counts[key] += 1
                seen_in_run.add(key)
            _aggregate_finding_data(
                key, f, confidence_sums, confidence_counts, evidence_acc, hunter_acc,
            )
            existing = best_variant.get(key)
            if existing is None or _severity_rank(
                f.get("severity", ""),
            ) > _severity_rank(existing.get("severity", "")):
                best_variant[key] = f

    _annotate_best_variants(
        best_variant, confidence_sums, confidence_counts, evidence_acc, hunter_acc,
    )
    return vote_counts, best_variant


def _build_results(
    best_variant: dict[str, dict],
    vote_counts: dict[str, int],
    min_votes: int,
    *,
    enforce_severity_gating: bool = False,
) -> tuple[list[dict], list[dict]]:
    """Build promoted/suppressed lists with validation tier and severity gating.

    Applies:
    1. Validation tier assignment (Tier 1/2/3)
    2. Severity gating (High/Critical requires Tier 1 or 2) — when enforce_severity_gating=True
    3. Complexity penalty
    """
    promoted: list[dict] = []
    suppressed: list[dict] = []
    for key, variant in best_variant.items():
        count = vote_counts[key]
        cscore = complexity_score(variant)

        # Determine validation tier
        tier = _determine_validation_tier(variant)
        variant["validation_tier"] = tier
        variant["validation_tier_name"] = _TIER_NAMES.get(tier, "unknown")

        # Apply severity gating (only when enforced)
        variant = _validate_severity_tier(variant, enforce=enforce_severity_gating)

        annotated = {
            **variant,
            "vote_count": count,
            "complexity_score": cscore,
        }
        if count >= min_votes:
            if cscore > _COMPLEXITY_PENALTY_THRESHOLD and count == min_votes:
                annotated["suppressed_reason"] = "complexity_penalty"
                suppressed.append(annotated)
            else:
                promoted.append(annotated)
        else:
            suppressed.append(annotated)
    return promoted, suppressed


def _semantic_merge(
    outputs: list[list[dict]],
    similarity_threshold: float = 0.85,
) -> list[list[dict]]:
    """Merge semantically similar findings across hunter runs.

    After exact-key dedup, some findings describe the same vulnerability
    using different descriptions or at slightly different line ranges.
    This function uses embedding cosine similarity to detect and merge
    those clusters.

    Parameters
    ----------
    outputs:
        List of finding lists, one per hunter run.
    similarity_threshold:
        Minimum cosine similarity to consider two findings equivalent.

    Returns
    -------
    New ``outputs`` list with semantically similar findings merged.
    When sentence-transformers or faiss is unavailable, returns inputs unchanged.
    """
    try:
        from ai_vuln_harness.stages.embeddings import EmbeddingIndex
    except ImportError:
        return outputs

    index = EmbeddingIndex()
    if not index.available:
        return outputs

    # Flatten all findings with their origin run index
    flat: list[tuple[int, dict]] = []
    for run_idx, run in enumerate(outputs):
        for f in run or []:
            flat.append((run_idx, f))

    if len(flat) < 2:
        return outputs

    # Encode
    findings = [f for _, f in flat]
    index.encode_findings(findings)
    pairs = index.find_similar_pairs(threshold=similarity_threshold)

    if not pairs:
        return outputs

    # Union-find to cluster similar findings
    parent = list(range(len(flat)))

    def find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a: int, b: int) -> None:
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[ra] = rb

    for a, b, _sim in pairs:
        union(a, b)

    # Build clusters: root -> list of (run_idx, finding)
    clusters: dict[int, list[tuple[int, dict]]] = defaultdict(list)
    for i, (run_idx, f) in enumerate(flat):
        clusters[find(i)].append((run_idx, f))

    # Rebuild outputs: each cluster becomes one finding (best variant)
    new_outputs: list[list[dict]] = [[] for _ in outputs]
    seen_clusters: set[int] = set()

    for root, members in clusters.items():
        if root in seen_clusters:
            continue
        seen_clusters.add(root)

        if len(members) == 1:
            run_idx, f = members[0]
            new_outputs[run_idx].append(f)
            continue

        # Pick best variant by severity
        best_run_idx, best_f = members[0]
        for run_idx, f in members[1:]:
            if _severity_rank(f.get("severity", "")) > _severity_rank(
                best_f.get("severity", ""),
            ):
                best_run_idx, best_f = run_idx, f

        # Annotate with semantic merge info
        best_f = dict(best_f)
        origin_runs = sorted(set(ri for ri, _ in members))
        best_f["semantic_merge"] = True
        best_f["semantic_cluster_size"] = len(members)
        best_f["semantic_cluster_runs"] = origin_runs

        # Accumulate evidence from all members
        all_evidence: list[dict] = []
        all_models: list[str] = []
        for _, f in members:
            all_evidence.extend(f.get("suspicious_points") or [])
            model = f.get("hunt_model") or f.get("model") or "unknown"
            if model not in all_models:
                all_models.append(model)
        if all_evidence:
            best_f["accumulated_evidence"] = all_evidence
        if all_models:
            best_f["hunter_models"] = all_models

        new_outputs[best_run_idx].append(best_f)

    return new_outputs


def merge_hunter_outputs(
    outputs: list[list[dict]],
    min_votes: int = 2,
    *,
    enforce_severity_gating: bool = False,
    semantic_merge: bool = False,
    similarity_threshold: float = 0.85,
) -> tuple[list[dict], list[dict]]:
    """Merge findings from multiple hunter runs.

    Parameters
    ----------
    outputs:
        List of finding lists, one per hunter run.
    min_votes:
        Minimum number of runs a finding must appear in to be promoted.
        Defaults to 2 (majority of two or more hunters required).
    enforce_severity_gating:
        If True, High/Critical findings require Tier 1 or Tier 2 validation.
        Default False for backward compatibility.
    semantic_merge:
        If True, merge semantically similar findings across runs using
        embedding similarity before vote counting.  Requires
        sentence-transformers + faiss.  Default False for backward compat.
    similarity_threshold:
        Minimum cosine similarity for semantic merge (default 0.85).

    Returns
    -------
    (promoted, suppressed)
        *promoted* contains deduplicated findings that reached the vote
        threshold, each annotated with:
        - ``vote_count``: number of hunters that found it
        - ``complexity_score``: over-engineering penalty score
        - ``validation_tier``: 1 (confirmed), 2 (plausible), 3 (theoretical)
        - ``validation_tier_name``: human-readable tier name
        - ``aggregated_confidence``: average confidence across votes
        - ``accumulated_evidence``: merged suspicious_points from all hunters
        - ``hunter_models``: list of models that found this vulnerability

        *suppressed* contains findings that did not reach threshold, plus
        findings demoted by the complexity penalty (annotated with
        ``"suppressed_reason": "complexity_penalty"``).

    """
    if not outputs:
        return [], []

    # Optional semantic merge pass
    if semantic_merge and len(outputs) > 1:
        outputs = _semantic_merge(outputs, similarity_threshold=similarity_threshold)

    if len(outputs) == 1:
        result = []
        for f in outputs[0] or []:
            tier = _determine_validation_tier(f)
            f["validation_tier"] = tier
            f["validation_tier_name"] = _TIER_NAMES.get(tier, "unknown")
            f = _validate_severity_tier(f, enforce=enforce_severity_gating)
            annotated = {**f, "vote_count": 1, "complexity_score": complexity_score(f)}
            result.append(annotated)
        return result, []

    vote_counts, best_variant = _count_votes(outputs)
    return _build_results(
        best_variant,
        vote_counts,
        min_votes,
        enforce_severity_gating=enforce_severity_gating,
    )
