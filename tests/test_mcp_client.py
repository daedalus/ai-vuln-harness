"""Tests for mcp_client.py — MCP client implementations."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from ai_vuln_harness.mcp_client import (
    InProcessMCPClient,
    MCPClient,
    MCPError,
    _build_notification,
    _build_request,
)

# ---------------------------------------------------------------------------
# JSON-RPC builder helpers
# ---------------------------------------------------------------------------


class TestBuildRequest:
    def test_basic_structure(self):
        raw = _build_request(1, "initialize")
        msg = json.loads(raw)
        assert msg["jsonrpc"] == "2.0"
        assert msg["id"] == 1
        assert msg["method"] == "initialize"

    def test_with_params(self):
        raw = _build_request(2, "tools/call", {"name": "foo", "arguments": {}})
        msg = json.loads(raw)
        assert msg["params"]["name"] == "foo"

    def test_without_params_no_params_key(self):
        raw = _build_request(3, "tools/list")
        msg = json.loads(raw)
        assert "params" not in msg

    def test_id_preserved(self):
        raw = _build_request(42, "initialize")
        assert json.loads(raw)["id"] == 42


class TestBuildNotification:
    def test_no_id(self):
        raw = _build_notification("notifications/initialized")
        msg = json.loads(raw)
        assert "id" not in msg

    def test_method_present(self):
        raw = _build_notification("notifications/initialized")
        msg = json.loads(raw)
        assert msg["method"] == "notifications/initialized"

    def test_with_params(self):
        raw = _build_notification("notifications/foo", {"key": "val"})
        msg = json.loads(raw)
        assert msg["params"]["key"] == "val"


# ---------------------------------------------------------------------------
# MCPError
# ---------------------------------------------------------------------------


class TestMCPError:
    def test_stores_code(self):
        err = MCPError(-32601, "Method not found")
        assert err.code == -32601

    def test_stores_message(self):
        err = MCPError(-32601, "Method not found")
        assert err.message == "Method not found"

    def test_stores_data(self):
        err = MCPError(-32600, "Bad request", data={"detail": "x"})
        assert err.data == {"detail": "x"}

    def test_str_includes_code(self):
        err = MCPError(-32601, "Method not found")
        assert "-32601" in str(err)


# ---------------------------------------------------------------------------
# InProcessMCPClient
# ---------------------------------------------------------------------------


class TestInProcessMCPClient:
    def test_context_manager(self):
        with InProcessMCPClient() as client:
            assert client._initialized is True

    def test_list_tools_returns_list(self):
        with InProcessMCPClient() as client:
            tools = client.list_tools()
            assert isinstance(tools, list)
            assert len(tools) > 0

    def test_list_tools_has_scan_repo(self):
        with InProcessMCPClient() as client:
            names = [t["name"] for t in client.list_tools()]
            assert "scan_repo" in names

    def test_list_tools_has_get_findings(self):
        with InProcessMCPClient() as client:
            names = [t["name"] for t in client.list_tools()]
            assert "get_findings" in names

    def test_list_tools_has_get_report(self):
        with InProcessMCPClient() as client:
            names = [t["name"] for t in client.list_tools()]
            assert "get_report" in names

    def test_list_tools_has_list_run_modes(self):
        with InProcessMCPClient() as client:
            names = [t["name"] for t in client.list_tools()]
            assert "list_run_modes" in names

    def test_call_tool_list_run_modes(self):
        with InProcessMCPClient() as client:
            result = client.call_tool("list_run_modes", {})
            data = json.loads(result["content"][0]["text"])
            assert "full" in data["modes"]

    def test_call_tool_get_findings_missing_dir(self, tmp_path):
        missing = tmp_path / "no-dir"
        with InProcessMCPClient() as client:
            result = client.call_tool("get_findings", {"output_dir": str(missing)})
            data = json.loads(result["content"][0]["text"])
            assert "findings" in data
            assert data["findings"] == []

    def test_call_tool_get_report_missing_file(self, tmp_path):
        with InProcessMCPClient() as client:
            result = client.call_tool("get_report", {"output_dir": str(tmp_path)})
            data = json.loads(result["content"][0]["text"])
            assert "error" in data

    def test_call_tool_get_findings_with_data(self, tmp_path):
        (tmp_path / "findings.jsonl").write_text(
            json.dumps({"id": "f1", "status": "confirmed"}) + "\n"
        )
        with InProcessMCPClient() as client:
            result = client.call_tool("get_findings", {"output_dir": str(tmp_path)})
            findings = json.loads(result["content"][0]["text"])
            assert len(findings) == 1
            assert findings[0]["id"] == "f1"

    def test_call_tool_get_report_with_data(self, tmp_path):
        report = {"total": 3, "critical": 1}
        (tmp_path / "report.json").write_text(json.dumps(report))
        with InProcessMCPClient() as client:
            result = client.call_tool("get_report", {"output_dir": str(tmp_path)})
            data = json.loads(result["content"][0]["text"])
            assert data["total"] == 3

    def test_unknown_tool_raises_mcp_error(self):
        with InProcessMCPClient() as client:
            with pytest.raises(MCPError) as exc_info:
                client.call_tool("not_a_real_tool", {})
            assert exc_info.value.code == -32601

    def test_stop_is_noop(self):
        client = InProcessMCPClient()
        client.start()
        client.stop()  # should not raise

    def test_multiple_calls(self):
        with InProcessMCPClient() as client:
            for _ in range(3):
                result = client.call_tool("list_run_modes", {})
                data = json.loads(result["content"][0]["text"])
                assert "modes" in data


# ---------------------------------------------------------------------------
# MCPClient (subprocess) — unit test with mocked subprocess
# ---------------------------------------------------------------------------


def _make_response(req_id: int, result: dict) -> str:
    return json.dumps({"jsonrpc": "2.0", "id": req_id, "result": result}) + "\n"


class TestMCPClientSubprocess:
    """Test MCPClient using a mocked subprocess.Popen."""

    def _build_mock_proc(self, responses: list[str]) -> MagicMock:
        mock_proc = MagicMock()
        mock_proc.stdin = MagicMock()
        # stdout.readline() pops responses in sequence then returns ""
        side_effect = responses + [""]
        mock_proc.stdout.readline.side_effect = side_effect
        mock_proc.wait.return_value = 0
        return mock_proc

    def test_start_sends_initialize(self):
        init_response = _make_response(
            1,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "test", "version": "0"},
            },
        )
        mock_proc = self._build_mock_proc([init_response])
        with patch("subprocess.Popen", return_value=mock_proc):
            client = MCPClient(["dummy-cmd"])
            client.start()
            # stdin.write should have been called with initialize request
            calls = [
                call_args[0][0]
                for call_args in mock_proc.stdin.write.call_args_list
            ]
            assert any("initialize" in c for c in calls)
            client.stop()

    def test_list_tools(self):
        init_resp = _make_response(
            1,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "test", "version": "0"},
            },
        )
        tools_resp = _make_response(
            2,
            {"tools": [{"name": "scan_repo", "description": "desc", "inputSchema": {}}]},
        )
        mock_proc = self._build_mock_proc([init_resp, tools_resp])
        with patch("subprocess.Popen", return_value=mock_proc):
            client = MCPClient(["dummy-cmd"])
            client.start()
            tools = client.list_tools()
            assert len(tools) == 1
            assert tools[0]["name"] == "scan_repo"
            client.stop()

    def test_call_tool_returns_result(self):
        init_resp = _make_response(
            1,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "test", "version": "0"},
            },
        )
        call_resp = _make_response(
            2,
            {"content": [{"type": "text", "text": '{"modes": ["full"]}'}]},
        )
        mock_proc = self._build_mock_proc([init_resp, call_resp])
        with patch("subprocess.Popen", return_value=mock_proc):
            with MCPClient(["dummy-cmd"]) as client:
                result = client.call_tool("list_run_modes", {})
                data = json.loads(result["content"][0]["text"])
                assert "full" in data["modes"]

    def test_mcp_error_raises(self):
        init_resp = _make_response(
            1,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "test", "version": "0"},
            },
        )
        error_resp = (
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "error": {"code": -32601, "message": "Method not found"},
                }
            )
            + "\n"
        )
        mock_proc = self._build_mock_proc([init_resp, error_resp])
        with patch("subprocess.Popen", return_value=mock_proc):
            with MCPClient(["dummy-cmd"]) as client:
                with pytest.raises(MCPError) as exc_info:
                    client.call_tool("bad_tool", {})
                assert exc_info.value.code == -32601

    def test_context_manager_calls_stop(self):
        init_resp = _make_response(
            1,
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "serverInfo": {"name": "test", "version": "0"},
            },
        )
        mock_proc = self._build_mock_proc([init_resp])
        with patch("subprocess.Popen", return_value=mock_proc):
            with MCPClient(["dummy-cmd"]):
                pass
            mock_proc.terminate.assert_called_once()

    def test_stop_without_start_does_not_crash(self):
        client = MCPClient(["dummy-cmd"])
        client.stop()  # _proc is None — must not raise
