"""MCP (Model Context Protocol) stdio server for ai-vuln-harness.

Exposes the vulnerability research pipeline as MCP tools so the harness can
be used from any MCP-compatible IDE or agent framework (Cursor, VS Code Claude
extension, Claude Desktop, etc.).

Protocol: JSON-RPC 2.0 over stdin/stdout, one message per line (newline-delimited).

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
from typing import IO

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Protocol constants
# ---------------------------------------------------------------------------

_JSONRPC = "2.0"
_SERVER_NAME = "ai-vuln-harness"
_SERVER_VERSION = "1.0.0"

_PROTOCOL_VERSION = "2024-11-05"

_RUN_MODES = [
    "full",
    "max-run",
    "validate-only",
    "resume",
    "diff",
    "all",
    "poc-only",
    "benchmark",
]

# ---------------------------------------------------------------------------
# Tool schemas
# ---------------------------------------------------------------------------

_TOOLS: list[dict[str, object]] = [
    {
        "name": "scan_repo",
        "description": (
            "Run the ai-vuln-harness multi-agent vulnerability research pipeline "
            "against a target repository. The pipeline stages are: INGESTOR → RECON "
            "→ COORDINATOR → HUNT → LOCALIZATION → VALIDATE → FUZZ_ORCHESTRATOR → "
            "GAPFILL → VOTING → SHIELD → SUPPRESSIONS → CHAINS → POC → TRACE → "
            "EXPOSURE → FEEDBACK → REPORT. Returns a JSON summary of findings and "
            "the output directory path."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Absolute path to the repository to scan.",
                },
                "mode": {
                    "type": "string",
                    "description": (
                        "Pipeline run mode. One of: full, max-run, validate-only, "
                        "resume, diff, all, poc-only, benchmark. Default: full."
                    ),
                    "default": "full",
                },
                "output_dir": {
                    "type": "string",
                    "description": (
                        "Directory for pipeline output (findings, report, state DB). "
                        "Created if absent. Default: <target>/../harness-output."
                    ),
                },
                "auth_json": {
                    "type": "string",
                    "description": (
                        "Path to auth.json with API keys. Overrides "
                        "OPENROUTER_API_KEY and other provider env vars."
                    ),
                },
                "max_workers": {
                    "type": "integer",
                    "description": "Maximum concurrent model calls. Default: 3.",
                    "default": 3,
                },
            },
            "required": ["target"],
        },
    },
    {
        "name": "get_findings",
        "description": (
            "Read structured vulnerability findings from a completed pipeline run. "
            "Returns a JSON array of finding objects, each with fields: id, class, "
            "severity, desc, status, poc_confirmed, snippet_id, call_path."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_dir": {
                    "type": "string",
                    "description": "Path to the pipeline output directory.",
                },
                "status_filter": {
                    "type": "string",
                    "description": (
                        "Optional filter: return only findings with this status "
                        "(e.g. 'confirmed', 'rejected', 'raw'). Omit for all."
                    ),
                },
            },
            "required": ["output_dir"],
        },
    },
    {
        "name": "get_report",
        "description": (
            "Read the final security report produced by a completed pipeline run. "
            "Returns the structured report as a JSON object."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "output_dir": {
                    "type": "string",
                    "description": "Path to the pipeline output directory.",
                },
            },
            "required": ["output_dir"],
        },
    },
    {
        "name": "list_run_modes",
        "description": "Return the list of supported pipeline run-mode strings.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
        },
    },
]

# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------


def _ok(request_id: object, result: object) -> dict[str, object]:
    """Build a successful JSON-RPC response."""
    return {"jsonrpc": _JSONRPC, "id": request_id, "result": result}


def _err(
    request_id: object,
    code: int,
    message: str,
    data: object = None,
) -> dict[str, object]:
    """Build a JSON-RPC error response."""
    error: dict[str, object] = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    return {"jsonrpc": _JSONRPC, "id": request_id, "error": error}


def _text_content(text: str) -> list[dict[str, str]]:
    return [{"type": "text", "text": text}]


# ---------------------------------------------------------------------------
# Tool implementations
# ---------------------------------------------------------------------------


def _handle_scan_repo(args: dict[str, object]) -> dict[str, object]:
    """Launch the pipeline.  Returns a summary content block."""
    target = args.get("target", "")
    if not target:
        raise ValueError("'target' argument is required")

    target_path = Path(str(target))
    if not target_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {target}")

    mode = str(args.get("mode", "full"))
    if mode not in _RUN_MODES:
        raise ValueError(f"Unknown run mode '{mode}'. Supported: {_RUN_MODES}")

    output_dir_arg = args.get("output_dir")
    output_dir = (
        Path(str(output_dir_arg)) if output_dir_arg else target_path.parent / "harness-output"
    )

    auth_json_arg = args.get("auth_json")
    auth_path = Path(str(auth_json_arg)) if auth_json_arg else None

    max_workers = int(str(args.get("max_workers", 3)))

    # Import lazily so the module loads fast when used as a server.
    from ai_vuln_harness.run import run as harness_run  # noqa: PLC0415

    harness_run(
        mode,
        target_path,
        output_dir=output_dir,
        auth_json=auth_path,
        max_workers=max_workers,
    )

    summary: dict[str, object] = {
        "status": "completed",
        "target": str(target_path),
        "mode": mode,
        "output_dir": str(output_dir),
    }
    findings_path = output_dir / "findings.jsonl"
    report_path = output_dir / "report.json"
    if findings_path.exists():
        raw_lines = [ln for ln in findings_path.read_text().splitlines() if ln.strip()]
        summary["finding_count"] = len(raw_lines)
    if report_path.exists():
        summary["report_available"] = True
    return {"content": _text_content(json.dumps(summary, indent=2))}


def _handle_get_findings(args: dict[str, object]) -> dict[str, object]:
    """Read findings JSONL from output_dir."""
    output_dir_arg = args.get("output_dir", "")
    if not output_dir_arg:
        raise ValueError("'output_dir' argument is required")

    output_dir = Path(str(output_dir_arg))
    findings_path = output_dir / "findings.jsonl"
    if not findings_path.exists():
        return {
            "content": _text_content(
                json.dumps(
                    {"error": f"findings.jsonl not found in {output_dir}", "findings": []},
                    indent=2,
                )
            )
        }

    status_filter = args.get("status_filter")
    findings: list[object] = []
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
        findings.append(finding)

    return {"content": _text_content(json.dumps(findings, indent=2))}


def _handle_get_report(args: dict[str, object]) -> dict[str, object]:
    """Read report.json from output_dir."""
    output_dir_arg = args.get("output_dir", "")
    if not output_dir_arg:
        raise ValueError("'output_dir' argument is required")

    output_dir = Path(str(output_dir_arg))
    report_path = output_dir / "report.json"
    if not report_path.exists():
        return {
            "content": _text_content(
                json.dumps({"error": f"report.json not found in {output_dir}"}, indent=2)
            )
        }

    try:
        report = json.loads(report_path.read_text())
    except json.JSONDecodeError as exc:
        return {
            "content": _text_content(
                json.dumps({"error": f"Failed to parse report.json: {exc}"}, indent=2)
            )
        }
    return {"content": _text_content(json.dumps(report, indent=2))}


def _handle_list_run_modes(_args: dict[str, object]) -> dict[str, object]:
    return {"content": _text_content(json.dumps({"modes": _RUN_MODES}, indent=2))}


_TOOL_HANDLERS: dict[str, object] = {
    "scan_repo": _handle_scan_repo,
    "get_findings": _handle_get_findings,
    "get_report": _handle_get_report,
    "list_run_modes": _handle_list_run_modes,
}

# ---------------------------------------------------------------------------
# JSON-RPC dispatch
# ---------------------------------------------------------------------------


def _dispatch(request: dict[str, object]) -> dict[str, object] | None:
    """Process one JSON-RPC request and return a response dict (or None for
    notifications, which require no response)."""
    req_id = request.get("id")
    method = str(request.get("method", ""))
    params = request.get("params") or {}

    # Notifications (no "id") — acknowledge silently.
    if "id" not in request:
        return None

    if method == "initialize":
        return _ok(
            req_id,
            {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": _SERVER_NAME, "version": _SERVER_VERSION},
            },
        )

    if method == "tools/list":
        return _ok(req_id, {"tools": _TOOLS})

    if method == "tools/call":
        if not isinstance(params, dict):
            return _err(req_id, -32600, "Invalid params: expected object")
        tool_name = str(params.get("name", ""))
        tool_args = params.get("arguments") or {}
        handler = _TOOL_HANDLERS.get(tool_name)
        if handler is None:
            return _err(req_id, -32601, f"Tool not found: {tool_name}")
        if not callable(handler):
            return _err(req_id, -32601, f"Tool not callable: {tool_name}")
        if not isinstance(tool_args, dict):
            tool_args = {}
        try:
            result = handler(tool_args)
            return _ok(req_id, result)
        except (ValueError, FileNotFoundError) as exc:
            return _ok(
                req_id,
                {
                    "content": _text_content(str(exc)),
                    "isError": True,
                },
            )
        except Exception:  # noqa: BLE001
            logger.exception("Tool '%s' raised unexpected error", tool_name)
            return _ok(
                req_id,
                {
                    "content": _text_content(
                        f"Internal error running tool '{tool_name}'"
                    ),
                    "isError": True,
                },
            )

    return _err(req_id, -32601, f"Method not found: {method}")


# ---------------------------------------------------------------------------
# Stdio event loop
# ---------------------------------------------------------------------------


def serve(
    *,
    in_stream: IO[str] | None = None,
    out_stream: IO[str] | None = None,
) -> None:
    """Run the MCP server, reading JSON-RPC messages from *in_stream* (default:
    ``sys.stdin``) and writing responses to *out_stream* (default: ``sys.stdout``).

    Each message is a single JSON object terminated by a newline.  The server
    runs until EOF on the input stream.

    Args:
        in_stream: Readable text stream.  Defaults to ``sys.stdin``.
        out_stream: Writable text stream.  Defaults to ``sys.stdout``.
    """
    reader: IO[str] = in_stream if in_stream is not None else sys.stdin
    writer: IO[str] = out_stream if out_stream is not None else sys.stdout

    for raw_line in reader:
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        try:
            request = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            response = _err(None, -32700, f"Parse error: {exc}")
            writer.write(json.dumps(response) + "\n")
            writer.flush()
            continue

        response = _dispatch(request)
        if response is not None:
            writer.write(json.dumps(response) + "\n")
            writer.flush()


def main() -> None:
    """Entry point for the ``ai-vuln-harness-mcp`` console script."""
    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )
    serve()


if __name__ == "__main__":
    main()
