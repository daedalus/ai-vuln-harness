"""MCP (Model Context Protocol) server for ai-vuln-harness — powered by FastMCP.

Exposes the vulnerability research pipeline as MCP tools so the harness can
be used from any MCP-compatible IDE or agent framework (Cursor, VS Code Claude
extension, Claude Desktop, etc.).

Exposed tools
-------------
``scan_repo``
    Launch the full (or selected) pipeline against a target repository path.
``get_findings``
    Read structured findings from a completed run's output directory.
``get_report``
    Read the final security report from a completed run's output directory.
``list_run_modes``
    Return the list of supported run-mode strings.

Usage
-----
As a script entry point::

    ai-vuln-harness-mcp

Or directly::

    python -m ai_vuln_harness.mcp_server

Configure in your IDE's MCP settings (stdio transport, no arguments required).
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path

import fastmcp

logger = logging.getLogger(__name__)


def _get_run_modes() -> list[str]:
    """Return all supported pipeline run modes.

    Derives from the single-mode list defined in ``run`` to prevent mode drift
    between the CLI and the MCP server, then appends meta-modes that orchestrate
    multiple sub-runs.
    """
    from ai_vuln_harness.run import _SINGLE_MODES  # lazy import — heavy module

    return _SINGLE_MODES + ["all", "benchmark"]


_RUN_MODES = _get_run_modes()

mcp = fastmcp.FastMCP("ai-vuln-harness", version="1.0.0")

# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


@mcp.tool(  # type: ignore[untyped-decorator]
    description=(
        "Run the ai-vuln-harness multi-agent vulnerability research pipeline "
        "against a target repository. The pipeline stages are: INGESTOR → RECON "
        "→ COORDINATOR → HUNT → LOCALIZATION → VALIDATE → FUZZ_ORCHESTRATOR → "
        "GAPFILL → VOTING → SHIELD → SUPPRESSIONS → CHAINS → POC → TRACE → "
        "EXPOSURE → FEEDBACK → REPORT. Returns a JSON summary of findings and "
        "the output directory path."
    )
)
def scan_repo(
    target: str,
    mode: str = "full",
    output_dir: str | None = None,
    auth_json: str | None = None,
    max_workers: int = 3,
) -> dict[str, object]:
    """Run the vulnerability pipeline against a target repository.

    Args:
        target: Absolute path to the repository to scan.
        mode: Pipeline run mode (full, max-run, validate-only, resume, diff,
            all, poc-only, benchmark). Default: full.
        output_dir: Directory for pipeline output. Created if absent. Default:
            <target>/../harness-output.
        auth_json: Path to auth.json with API keys.
        max_workers: Maximum concurrent model calls. Default: 3.

    Returns:
        A summary dict with status, target, mode, output_dir, and optionally
        finding_count and report_available.
    """
    if not target:
        raise ValueError("'target' argument is required")

    target_path = Path(target)
    if not target_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")

    if mode not in _RUN_MODES:
        raise ValueError(f"Unknown run mode '{mode}'. Supported: {_RUN_MODES}")

    out_path = Path(output_dir) if output_dir else target_path.parent / "harness-output"
    auth_path = Path(auth_json) if auth_json else None

    # Lazy import: avoids loading the heavy pipeline modules at server startup.
    from ai_vuln_harness.run import run as harness_run  # noqa: PLC0415

    harness_run(
        mode,
        target_path,
        output_dir=out_path,
        auth_path=auth_path,
        max_concurrency=max_workers,
    )

    summary: dict[str, object] = {
        "status": "completed",
        "target": str(target_path),
        "mode": mode,
        "output_dir": str(out_path),
    }
    findings_path = out_path / "findings.jsonl"
    report_path = out_path / "report.json"
    if findings_path.exists():
        raw_lines = [ln for ln in findings_path.read_text().splitlines() if ln.strip()]
        summary["finding_count"] = len(raw_lines)
    if report_path.exists():
        summary["report_available"] = True
    return summary


@mcp.tool(  # type: ignore[untyped-decorator]
    description=(
        "Read structured vulnerability findings from a completed pipeline run. "
        'Returns a JSON object {"error": string | null, "findings": [...]} where '
        '"findings" is an array of finding objects with fields: id, class, '
        "severity, desc, status, poc_confirmed, snippet_id, call_path."
    )
)
def get_findings(
    output_dir: str,
    status_filter: str | None = None,
) -> dict[str, object]:
    """Read findings JSONL from output_dir.

    Args:
        output_dir: Path to the pipeline output directory.
        status_filter: Optional filter — return only findings with this status
            (e.g. 'confirmed', 'rejected', 'raw'). Omit for all.

    Returns:
        A dict with the standardized shape:
        {
            "error": str | None,      # None on success, error message on failure
            "findings": list[object], # List of finding objects (possibly empty)
        }
    """
    out_path = Path(output_dir)
    findings_path = out_path / "findings.jsonl"
    if not findings_path.exists():
        return {"error": f"findings.jsonl not found in {out_path}", "findings": []}

    raw_findings: list[object] = []
    for raw_line in findings_path.read_text().splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            finding = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if status_filter and finding.get("status") != status_filter:
            continue
        raw_findings.append(finding)

    return {"error": None, "findings": raw_findings}


@mcp.tool(  # type: ignore[untyped-decorator]
    description=(
        "Read the final security report produced by a completed pipeline run. "
        "Returns the structured report as a JSON object."
    )
)
def get_report(output_dir: str) -> dict[str, object]:
    """Read report.json from output_dir.

    Args:
        output_dir: Path to the pipeline output directory.

    Returns:
        The report dict, or an error dict if the file is missing or invalid.
    """
    out_path = Path(output_dir)
    report_path = out_path / "report.json"
    if not report_path.exists():
        return {"error": f"report.json not found in {out_path}"}

    try:
        return json.loads(report_path.read_text())
    except json.JSONDecodeError as exc:
        return {"error": f"Failed to parse report.json: {exc}"}


@mcp.tool(description="Return the list of supported pipeline run-mode strings.")  # type: ignore[untyped-decorator]
def list_run_modes() -> dict[str, list[str]]:
    """Return all supported run-mode strings.

    Returns:
        A dict with a single key ``modes`` containing the list of mode strings.
    """
    return {"modes": _RUN_MODES}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for the ``ai-vuln-harness-mcp`` console script."""
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
