"""Tests for mcp_server.py — MCP stdio server."""

from __future__ import annotations

import io
import json

from ai_vuln_harness.mcp_server import (
    _RUN_MODES,
    _TOOLS,
    _dispatch,
    _err,
    _ok,
    _text_content,
    serve,
)

# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------


def _req(req_id, method, params=None):
    msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return msg


def _notify(method, params=None):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    return msg


# ---------------------------------------------------------------------------
# Unit helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_ok_structure(self):
        r = _ok(1, {"a": 1})
        assert r["jsonrpc"] == "2.0"
        assert r["id"] == 1
        assert r["result"] == {"a": 1}

    def test_err_structure(self):
        r = _err(2, -32601, "Method not found")
        assert r["jsonrpc"] == "2.0"
        assert r["id"] == 2
        assert r["error"]["code"] == -32601
        assert "not found" in r["error"]["message"]

    def test_err_with_data(self):
        r = _err(3, -32600, "Invalid request", data={"detail": "x"})
        assert r["error"]["data"] == {"detail": "x"}

    def test_text_content(self):
        blocks = _text_content("hello")
        assert len(blocks) == 1
        assert blocks[0]["type"] == "text"
        assert blocks[0]["text"] == "hello"


# ---------------------------------------------------------------------------
# Dispatch — initialize
# ---------------------------------------------------------------------------


class TestDispatchInitialize:
    def test_initialize_returns_result(self):
        response = _dispatch(_req(1, "initialize", {}))
        assert response is not None
        assert "result" in response

    def test_initialize_protocol_version(self):
        response = _dispatch(_req(1, "initialize", {}))
        assert response["result"]["protocolVersion"] == "2024-11-05"

    def test_initialize_server_name(self):
        response = _dispatch(_req(1, "initialize", {}))
        assert response["result"]["serverInfo"]["name"] == "ai-vuln-harness"

    def test_initialize_capabilities(self):
        response = _dispatch(_req(1, "initialize", {}))
        assert "tools" in response["result"]["capabilities"]


# ---------------------------------------------------------------------------
# Dispatch — notifications (no response)
# ---------------------------------------------------------------------------


class TestDispatchNotifications:
    def test_initialized_notification_returns_none(self):
        assert _dispatch(_notify("notifications/initialized")) is None

    def test_arbitrary_notification_returns_none(self):
        assert _dispatch(_notify("notifications/whatever")) is None


# ---------------------------------------------------------------------------
# Dispatch — tools/list
# ---------------------------------------------------------------------------


class TestDispatchToolsList:
    def test_tools_list_returns_result(self):
        response = _dispatch(_req(2, "tools/list"))
        assert "result" in response

    def test_tools_list_has_tools(self):
        response = _dispatch(_req(2, "tools/list"))
        tools = response["result"]["tools"]
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_tools_list_contains_scan_repo(self):
        response = _dispatch(_req(2, "tools/list"))
        names = [t["name"] for t in response["result"]["tools"]]
        assert "scan_repo" in names

    def test_tools_list_contains_get_findings(self):
        response = _dispatch(_req(2, "tools/list"))
        names = [t["name"] for t in response["result"]["tools"]]
        assert "get_findings" in names

    def test_tools_list_contains_get_report(self):
        response = _dispatch(_req(2, "tools/list"))
        names = [t["name"] for t in response["result"]["tools"]]
        assert "get_report" in names

    def test_tools_list_contains_list_run_modes(self):
        response = _dispatch(_req(2, "tools/list"))
        names = [t["name"] for t in response["result"]["tools"]]
        assert "list_run_modes" in names

    def test_each_tool_has_input_schema(self):
        for tool in _TOOLS:
            assert "inputSchema" in tool, f"{tool['name']} missing inputSchema"

    def test_each_tool_has_description(self):
        for tool in _TOOLS:
            assert tool.get("description"), f"{tool['name']} missing description"


# ---------------------------------------------------------------------------
# Dispatch — tools/call: list_run_modes
# ---------------------------------------------------------------------------


class TestDispatchListRunModes:
    def test_list_run_modes_returns_modes(self):
        response = _dispatch(
            _req(3, "tools/call", {"name": "list_run_modes", "arguments": {}})
        )
        content = response["result"]["content"]
        data = json.loads(content[0]["text"])
        assert "modes" in data

    def test_list_run_modes_all_modes_present(self):
        response = _dispatch(
            _req(3, "tools/call", {"name": "list_run_modes", "arguments": {}})
        )
        content = response["result"]["content"]
        data = json.loads(content[0]["text"])
        for mode in _RUN_MODES:
            assert mode in data["modes"]

    def test_list_run_modes_full_present(self):
        response = _dispatch(
            _req(3, "tools/call", {"name": "list_run_modes", "arguments": {}})
        )
        data = json.loads(response["result"]["content"][0]["text"])
        assert "full" in data["modes"]


# ---------------------------------------------------------------------------
# Dispatch — tools/call: get_findings
# ---------------------------------------------------------------------------


class TestDispatchGetFindings:
    def test_get_findings_missing_output_dir_returns_error_content(self):
        response = _dispatch(
            _req(4, "tools/call", {"name": "get_findings", "arguments": {}})
        )
        result = response["result"]
        assert result.get("isError") is True

    def test_get_findings_nonexistent_dir_returns_error_json(self, tmp_path):
        missing = tmp_path / "no-such-dir"
        response = _dispatch(
            _req(
                4,
                "tools/call",
                {"name": "get_findings", "arguments": {"output_dir": str(missing)}},
            )
        )
        result = response["result"]
        data = json.loads(result["content"][0]["text"])
        assert "findings" in data
        assert data["findings"] == []

    def test_get_findings_reads_jsonl(self, tmp_path):
        findings_file = tmp_path / "findings.jsonl"
        findings_file.write_text(
            json.dumps({"id": "f1", "class": "overflow", "status": "confirmed"})
            + "\n"
            + json.dumps({"id": "f2", "class": "uaf", "status": "rejected"})
            + "\n"
        )
        response = _dispatch(
            _req(
                5,
                "tools/call",
                {"name": "get_findings", "arguments": {"output_dir": str(tmp_path)}},
            )
        )
        findings = json.loads(response["result"]["content"][0]["text"])
        assert len(findings) == 2

    def test_get_findings_status_filter(self, tmp_path):
        findings_file = tmp_path / "findings.jsonl"
        findings_file.write_text(
            json.dumps({"id": "f1", "status": "confirmed"})
            + "\n"
            + json.dumps({"id": "f2", "status": "rejected"})
            + "\n"
        )
        response = _dispatch(
            _req(
                6,
                "tools/call",
                {
                    "name": "get_findings",
                    "arguments": {
                        "output_dir": str(tmp_path),
                        "status_filter": "confirmed",
                    },
                },
            )
        )
        findings = json.loads(response["result"]["content"][0]["text"])
        assert len(findings) == 1
        assert findings[0]["id"] == "f1"

    def test_get_findings_skips_blank_lines(self, tmp_path):
        findings_file = tmp_path / "findings.jsonl"
        findings_file.write_text(
            "\n"
            + json.dumps({"id": "f1", "status": "raw"})
            + "\n\n"
        )
        response = _dispatch(
            _req(
                7,
                "tools/call",
                {"name": "get_findings", "arguments": {"output_dir": str(tmp_path)}},
            )
        )
        findings = json.loads(response["result"]["content"][0]["text"])
        assert len(findings) == 1

    def test_get_findings_skips_invalid_json_lines(self, tmp_path):
        findings_file = tmp_path / "findings.jsonl"
        findings_file.write_text("not-json\n" + json.dumps({"id": "f1"}) + "\n")
        response = _dispatch(
            _req(
                8,
                "tools/call",
                {"name": "get_findings", "arguments": {"output_dir": str(tmp_path)}},
            )
        )
        findings = json.loads(response["result"]["content"][0]["text"])
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# Dispatch — tools/call: get_report
# ---------------------------------------------------------------------------


class TestDispatchGetReport:
    def test_get_report_missing_output_dir_returns_error(self):
        response = _dispatch(
            _req(9, "tools/call", {"name": "get_report", "arguments": {}})
        )
        assert response["result"].get("isError") is True

    def test_get_report_missing_file_returns_error_json(self, tmp_path):
        response = _dispatch(
            _req(
                9,
                "tools/call",
                {"name": "get_report", "arguments": {"output_dir": str(tmp_path)}},
            )
        )
        data = json.loads(response["result"]["content"][0]["text"])
        assert "error" in data

    def test_get_report_reads_json(self, tmp_path):
        report = {"findings": 5, "critical": 1}
        (tmp_path / "report.json").write_text(json.dumps(report))
        response = _dispatch(
            _req(
                10,
                "tools/call",
                {"name": "get_report", "arguments": {"output_dir": str(tmp_path)}},
            )
        )
        result = json.loads(response["result"]["content"][0]["text"])
        assert result["findings"] == 5
        assert result["critical"] == 1

    def test_get_report_invalid_json_returns_error(self, tmp_path):
        (tmp_path / "report.json").write_text("not-json{{{")
        response = _dispatch(
            _req(
                11,
                "tools/call",
                {"name": "get_report", "arguments": {"output_dir": str(tmp_path)}},
            )
        )
        data = json.loads(response["result"]["content"][0]["text"])
        assert "error" in data


# ---------------------------------------------------------------------------
# Dispatch — tools/call: scan_repo (arg-validation path only)
# ---------------------------------------------------------------------------


class TestDispatchScanRepo:
    def test_scan_repo_missing_target_returns_error(self):
        response = _dispatch(
            _req(12, "tools/call", {"name": "scan_repo", "arguments": {}})
        )
        assert response["result"].get("isError") is True

    def test_scan_repo_nonexistent_target_returns_error(self, tmp_path):
        response = _dispatch(
            _req(
                13,
                "tools/call",
                {
                    "name": "scan_repo",
                    "arguments": {"target": str(tmp_path / "no-such-repo")},
                },
            )
        )
        assert response["result"].get("isError") is True

    def test_scan_repo_invalid_mode_returns_error(self, tmp_path):
        response = _dispatch(
            _req(
                14,
                "tools/call",
                {
                    "name": "scan_repo",
                    "arguments": {"target": str(tmp_path), "mode": "not-a-mode"},
                },
            )
        )
        assert response["result"].get("isError") is True


# ---------------------------------------------------------------------------
# Dispatch — unknown method
# ---------------------------------------------------------------------------


class TestDispatchUnknownMethod:
    def test_unknown_method_returns_error(self):
        response = _dispatch(_req(99, "unknown/method"))
        assert "error" in response
        assert response["error"]["code"] == -32601

    def test_unknown_tool_returns_error(self):
        response = _dispatch(
            _req(
                100,
                "tools/call",
                {"name": "no_such_tool", "arguments": {}},
            )
        )
        assert "error" in response


# ---------------------------------------------------------------------------
# serve() — stdio event loop
# ---------------------------------------------------------------------------


class TestServe:
    def _run(self, lines: list[str]) -> list[dict]:
        in_stream = io.StringIO("\n".join(lines) + "\n")
        out_stream = io.StringIO()
        serve(in_stream=in_stream, out_stream=out_stream)
        out_stream.seek(0)
        results = []
        for line in out_stream:
            line = line.strip()
            if line:
                results.append(json.loads(line))
        return results

    def test_serve_initialize(self):
        responses = self._run(
            [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})]
        )
        assert len(responses) == 1
        assert responses[0]["result"]["serverInfo"]["name"] == "ai-vuln-harness"

    def test_serve_notification_no_response(self):
        responses = self._run(
            [json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"})]
        )
        assert len(responses) == 0

    def test_serve_tools_list(self):
        responses = self._run(
            [json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})]
        )
        assert len(responses) == 1
        assert "tools" in responses[0]["result"]

    def test_serve_list_run_modes(self):
        responses = self._run(
            [
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": 3,
                        "method": "tools/call",
                        "params": {"name": "list_run_modes", "arguments": {}},
                    }
                )
            ]
        )
        assert len(responses) == 1
        data = json.loads(responses[0]["result"]["content"][0]["text"])
        assert "full" in data["modes"]

    def test_serve_parse_error(self):
        responses = self._run(["not-valid-json{{{"])
        assert len(responses) == 1
        assert responses[0]["error"]["code"] == -32700

    def test_serve_blank_lines_skipped(self):
        responses = self._run(["", "   ", ""])
        assert len(responses) == 0

    def test_serve_multiple_requests(self):
        responses = self._run(
            [
                json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
                json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}),
            ]
        )
        assert len(responses) == 2
