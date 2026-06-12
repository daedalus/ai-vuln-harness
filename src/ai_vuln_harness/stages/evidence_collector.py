"""Evidence Collector: populate Engagement Graph from pipeline findings.

This stage collects evidence from findings, suspicious_points, call paths,
and file references, then populates the Engagement Graph with structured
observations. This builds the knowledge base for chain discovery and
cross-session analysis.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .engagement_graph import EngagementGraph


def collect_surface_from_snippets(
    snippets: list[dict],
    graph: EngagementGraph,
) -> int:
    """Populate attack surface from ingested snippets.

    Returns the number of surface entries added.
    """
    count = 0
    for s in snippets:
        kind = _classify_surface_kind(s)
        path = s.get("file", "")
        name = s.get("name", "")
        detail = f"{s.get('kind', 'unknown')}: {name}" if name else s.get("kind", "")
        graph.add_surface(kind=kind, path=path, detail=detail, source="ingestor")
        count += 1
    return count


def _classify_surface_kind(snippet: dict) -> str:
    """Classify a snippet into a surface kind."""
    kind = snippet.get("kind", "").lower()
    if kind in ("function", "method"):
        return "code"
    if kind in ("class", "struct"):
        return "type"
    if "test" in snippet.get("file", "").lower():
        return "test"
    return "code"


def collect_facts_from_findings(
    findings: list[dict],
    graph: EngagementGraph,
) -> int:
    """Collect structured facts from findings.

    Returns the number of facts added.
    """
    count = 0
    for f in findings:
        # Add finding as a fact
        title = f.get("desc", f.get("title", "unknown finding"))
        severity = f.get("severity", "UNKNOWN")
        vuln_class = f.get("class", "unknown")
        fact = f"[{severity}] {vuln_class}: {title}"
        graph.add_fact(content=fact, source="findings")
        count += 1

        # Add suspicious_points as facts
        for sp in f.get("suspicious_points", []):
            func = sp.get("function", "")
            sp_file = sp.get("file", "")
            rationale = sp.get("rationale", "")
            if func or rationale:
                sp_fact = f"Suspicious: {func} in {sp_file} — {rationale}"
                graph.add_fact(content=sp_fact, source="suspicious_points")
                count += 1

        # Add call path as facts
        call_path = f.get("call_path", [])
        if call_path:
            path_str = " → ".join(str(c) for c in call_path)
            graph.add_fact(content=f"Call path: {path_str}", source="call_path")
            count += 1

    return count


def collect_hypotheses_from_findings(
    findings: list[dict],
    graph: EngagementGraph,
) -> int:
    """Convert findings into hypotheses in the graph.

    Returns the number of hypotheses added.
    """
    count = 0
    for f in findings:
        title = f.get("desc", f.get("title", ""))
        vuln_class = f.get("class", "unknown")
        file_path = f.get("file", "")
        snippet_id = f.get("snippet_id", "")

        if title and vuln_class:
            graph.add_hypothesis(
                target=file_path or snippet_id,
                vuln_class=vuln_class,
                claim=title,
                source="findings",
            )
            count += 1

            # Mark as confirmed if poc_confirmed
            if f.get("poc_confirmed"):
                hyps = graph.list_hypotheses(status="open")
                if hyps:
                    graph.update_hypothesis_status(hyps[-1]["id"], "confirmed")

    return count


def collect_chains_from_exploit_chains(
    chains: list[dict],
    graph: EngagementGraph,
) -> int:
    """Add exploit chains to the graph.

    Returns the number of chains added.
    """
    count = 0
    for chain in chains:
        name = chain.get("name", "unnamed chain")
        links = chain.get("links", [])
        is_critical = chain.get("severity", "").upper() in ("CRITICAL", "HIGH")
        graph.add_chain(
            name=name,
            links=links,
            is_critical=is_critical,
        )
        count += 1
    return count


def run_evidence_collector(
    findings: list[dict],
    snippets: list[dict],
    chains: list[dict],
    graph: EngagementGraph,
) -> dict:
    """Run the evidence collector stage.

    Populates the Engagement Graph with evidence from the pipeline:
    - Attack surface from snippets
    - Facts from findings, suspicious_points, call paths
    - Hypotheses from findings
    - Exploit chains

    Returns a summary of what was collected.
    """
    surface_count = collect_surface_from_snippets(snippets, graph)
    facts_count = collect_facts_from_findings(findings, graph)
    hyp_count = collect_hypotheses_from_findings(findings, graph)
    chain_count = collect_chains_from_exploit_chains(chains, graph)

    summary = {
        "surface_entries": surface_count,
        "facts_added": facts_count,
        "hypotheses_added": hyp_count,
        "chains_added": chain_count,
        "graph_summary": graph.summary(),
    }

    return summary
