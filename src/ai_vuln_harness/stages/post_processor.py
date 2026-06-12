"""Post-Processor: aggregate findings, generate dashboard, produce output.

This stage runs after all pipeline stages and produces:
- Severity/class/file aggregation
- Severity dashboard
- Machine-readable JSONL output
- KPI calculation (precision, duplicate rate, gap closure)
- Human-readable summary
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def aggregate_findings(findings: list[dict]) -> dict:
    """Aggregate findings by severity, class, and file.

    Returns a dict with:
    - by_severity: {severity: count}
    - by_class: {vuln_class: count}
    - by_file: {file: count}
    - total: total count
    """
    by_severity: dict[str, int] = defaultdict(int)
    by_class: dict[str, int] = defaultdict(int)
    by_file: dict[str, int] = defaultdict(int)

    for f in findings:
        sev = str(f.get("severity", "UNKNOWN")).upper()
        by_severity[sev] += 1

        cls = f.get("class", "unknown")
        by_class[cls] += 1

        file_path = f.get("file", f.get("snippet_id", "unknown"))
        by_file[file_path] += 1

    return {
        "by_severity": dict(by_severity),
        "by_class": dict(by_class),
        "by_file": dict(by_file),
        "total": len(findings),
    }


def generate_dashboard(findings: list[dict], chains: list[dict]) -> dict:
    """Generate a severity dashboard with counts and chain info.

    Returns a dict suitable for display or JSON export.
    """
    agg = aggregate_findings(findings)

    critical_findings = [f for f in findings if str(f.get("severity", "")).upper() == "CRITICAL"]
    high_findings = [f for f in findings if str(f.get("severity", "")).upper() == "HIGH"]

    confirmed = [f for f in findings if f.get("poc_confirmed")]
    unconfirmed = [f for f in findings if not f.get("poc_confirmed")]

    chains_critical = [c for c in chains if c.get("severity", "").upper() in ("CRITICAL", "HIGH")]

    return {
        "timestamp": datetime.now(UTC).isoformat(),
        "total_findings": agg["total"],
        "by_severity": agg["by_severity"],
        "by_class": agg["by_class"],
        "critical_count": len(critical_findings),
        "high_count": len(high_findings),
        "confirmed_count": len(confirmed),
        "unconfirmed_count": len(unconfirmed),
        "chains_total": len(chains),
        "chains_critical": len(chains_critical),
        "top_files": sorted(agg["by_file"].items(), key=lambda x: x[1], reverse=True)[:10],
    }


def write_findings_jsonl(findings: list[dict], output_path: Path) -> int:
    """Write findings to JSONL format.

    Returns the number of findings written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        for finding in findings:
            f.write(json.dumps(finding, default=str) + "\n")
    return len(findings)


def write_summary_json(
    dashboard: dict,
    kpis: dict,
    output_path: Path,
) -> None:
    """Write summary dashboard and KPIs to JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    summary = {
        "dashboard": dashboard,
        "kpis": kpis,
        "generated_at": datetime.now(UTC).isoformat(),
    }
    output_path.write_text(json.dumps(summary, indent=2, default=str))


def calculate_kpis(
    findings: list[dict],
    report: dict,
    elapsed_seconds: float = 0.0,
    cost_usd: float = 0.0,
) -> dict:
    """Calculate key performance indicators.

    Returns a dict with:
    - total_findings: total count
    - confirmed_count: poc_confirmed count
    - confirmation_rate: confirmed / total
    - severity_distribution: {severity: count}
    - class_distribution: {class: count}
    - elapsed_seconds: scan duration
    - cost_usd: total cost
    - cost_per_finding: cost / total (if total > 0)
    """
    agg = aggregate_findings(findings)
    confirmed = sum(1 for f in findings if f.get("poc_confirmed"))
    total = len(findings)

    summary = report.get("summary", {})
    bucketed = {
        "fix_now": summary.get("fix_now", 0),
        "backlog": summary.get("backlog", 0),
        "false_positive": summary.get("false_positive", 0),
    }

    return {
        "total_findings": total,
        "confirmed_count": confirmed,
        "confirmation_rate": round(confirmed / total, 3) if total > 0 else 0.0,
        "severity_distribution": agg["by_severity"],
        "class_distribution": agg["by_class"],
        "bucket_distribution": bucketed,
        "elapsed_seconds": round(elapsed_seconds, 1),
        "cost_usd": round(cost_usd, 4),
        "cost_per_finding": round(cost_usd / total, 4) if total > 0 else 0.0,
    }


def run_post_processor(
    findings: list[dict],
    chains: list[dict],
    report: dict,
    output_dir: Path,
    elapsed_seconds: float = 0.0,
    cost_usd: float = 0.0,
) -> dict:
    """Run the post-processor stage.

    Produces:
    - findings.jsonl in output_dir
    - summary.json in output_dir
    - Dashboard and KPIs

    Returns the dashboard dict.
    """
    dashboard = generate_dashboard(findings, chains)
    kpis = calculate_kpis(findings, report, elapsed_seconds, cost_usd)

    write_findings_jsonl(findings, output_dir / "findings.jsonl")
    write_summary_json(dashboard, kpis, output_dir / "summary.json")

    return {
        "dashboard": dashboard,
        "kpis": kpis,
    }
