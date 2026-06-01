"""Tests for mcp_server.py — FastMCP server."""

from __future__ import annotations

import asyncio
import json

import pytest

from fastmcp.client import Client
from ai_vuln_harness.mcp_server import _RUN_MODES, mcp

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _call(name: str, arguments: dict) -> object:
    """Synchronously call a tool on the in-process FastMCP server."""

    async def _run() -> object:
        async with Client(mcp) as c:
            return await c.session.call_tool(name, arguments)

    return asyncio.run(_run())


def _list_tools() -> list:
    """Return the list of tools from the in-process FastMCP server."""

    async def _run() -> list:
        async with Client(mcp) as c:
            return await c.list_tools()

    return asyncio.run(_run())


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


class TestToolRegistration:
    def test_tools_list_has_tools(self):
        tools = _list_tools()
        assert isinstance(tools, list)
        assert len(tools) > 0

    def test_tools_list_contains_scan_repo(self):
        names = [t.name for t in _list_tools()]
        assert "scan_repo" in names

    def test_tools_list_contains_get_findings(self):
        names = [t.name for t in _list_tools()]
        assert "get_findings" in names

    def test_tools_list_contains_get_report(self):
        names = [t.name for t in _list_tools()]
        assert "get_report" in names

    def test_tools_list_contains_list_run_modes(self):
        names = [t.name for t in _list_tools()]
        assert "list_run_modes" in names

    def test_each_tool_has_description(self):
        for tool in _list_tools():
            assert tool.description, f"{tool.name} missing description"

    def test_each_tool_has_input_schema(self):
        for tool in _list_tools():
            assert tool.inputSchema, f"{tool.name} missing inputSchema"


# ---------------------------------------------------------------------------
# list_run_modes
# ---------------------------------------------------------------------------


class TestListRunModes:
    def test_returns_modes_key(self):
        result = _call("list_run_modes", {})
        data = json.loads(result.content[0].text)
        assert "modes" in data

    def test_all_modes_present(self):
        result = _call("list_run_modes", {})
        data = json.loads(result.content[0].text)
        for mode in _RUN_MODES:
            assert mode in data["modes"]

    def test_full_mode_present(self):
        result = _call("list_run_modes", {})
        data = json.loads(result.content[0].text)
        assert "full" in data["modes"]

    def test_not_error(self):
        result = _call("list_run_modes", {})
        assert result.isError is False


# ---------------------------------------------------------------------------
# get_findings
# ---------------------------------------------------------------------------


class TestGetFindings:
    def test_missing_output_dir_returns_error(self):
        result = _call("get_findings", {})
        assert result.isError is True

    def test_nonexistent_dir_returns_error_json(self, tmp_path):
        missing = tmp_path / "no-such-dir"
        result = _call("get_findings", {"output_dir": str(missing)})
        data = json.loads(result.content[0].text)
        assert "findings" in data
        assert data["findings"] == []

    def test_reads_jsonl(self, tmp_path):
        (tmp_path / "findings.jsonl").write_text(
            json.dumps({"id": "f1", "class": "overflow", "status": "confirmed"})
            + "\n"
            + json.dumps({"id": "f2", "class": "uaf", "status": "rejected"})
            + "\n"
        )
        result = _call("get_findings", {"output_dir": str(tmp_path)})
        data = json.loads(result.content[0].text)
        assert data["error"] is None
        assert len(data["findings"]) == 2

    def test_status_filter(self, tmp_path):
        (tmp_path / "findings.jsonl").write_text(
            json.dumps({"id": "f1", "status": "confirmed"})
            + "\n"
            + json.dumps({"id": "f2", "status": "rejected"})
            + "\n"
        )
        result = _call(
            "get_findings",
            {"output_dir": str(tmp_path), "status_filter": "confirmed"},
        )
        data = json.loads(result.content[0].text)
        assert data["error"] is None
        assert len(data["findings"]) == 1
        assert data["findings"][0]["id"] == "f1"

    def test_skips_blank_lines(self, tmp_path):
        (tmp_path / "findings.jsonl").write_text(
            "\n" + json.dumps({"id": "f1", "status": "raw"}) + "\n\n"
        )
        result = _call("get_findings", {"output_dir": str(tmp_path)})
        data = json.loads(result.content[0].text)
        assert data["error"] is None
        assert len(data["findings"]) == 1

    def test_skips_invalid_json_lines(self, tmp_path):
        (tmp_path / "findings.jsonl").write_text(
            "not-json\n" + json.dumps({"id": "f1"}) + "\n"
        )
        result = _call("get_findings", {"output_dir": str(tmp_path)})
        data = json.loads(result.content[0].text)
        assert data["error"] is None
        assert len(data["findings"]) == 1


# ---------------------------------------------------------------------------
# get_report
# ---------------------------------------------------------------------------


class TestGetReport:
    def test_missing_output_dir_returns_error(self):
        result = _call("get_report", {})
        assert result.isError is True

    def test_missing_file_returns_error_json(self, tmp_path):
        result = _call("get_report", {"output_dir": str(tmp_path)})
        data = json.loads(result.content[0].text)
        assert "error" in data

    def test_reads_json(self, tmp_path):
        report = {"findings": 5, "critical": 1}
        (tmp_path / "report.json").write_text(json.dumps(report))
        result = _call("get_report", {"output_dir": str(tmp_path)})
        data = json.loads(result.content[0].text)
        assert data["findings"] == 5
        assert data["critical"] == 1

    def test_invalid_json_returns_error(self, tmp_path):
        (tmp_path / "report.json").write_text("not-json{{{")
        result = _call("get_report", {"output_dir": str(tmp_path)})
        data = json.loads(result.content[0].text)
        assert "error" in data


# ---------------------------------------------------------------------------
# scan_repo (arg-validation path only)
# ---------------------------------------------------------------------------


class TestScanRepo:
    def test_missing_target_returns_error(self):
        result = _call("scan_repo", {})
        assert result.isError is True

    def test_nonexistent_target_returns_error(self, tmp_path):
        result = _call("scan_repo", {"target": str(tmp_path / "no-such-repo")})
        assert result.isError is True

    def test_invalid_mode_returns_error(self, tmp_path):
        result = _call("scan_repo", {"target": str(tmp_path), "mode": "not-a-mode"})
        assert result.isError is True


# ---------------------------------------------------------------------------
# Unknown tool
# ---------------------------------------------------------------------------


class TestUnknownTool:
    def test_unknown_tool_returns_error(self):
        result = _call("no_such_tool", {})
        assert result.isError is True
