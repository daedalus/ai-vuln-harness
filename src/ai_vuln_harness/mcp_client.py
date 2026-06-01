"""MCP (Model Context Protocol) client — call tools on an MCP stdio server.

Launches an MCP server subprocess and communicates with it over stdin/stdout
using the JSON-RPC 2.0 protocol.

Typical use-cases
-----------------
* Call tools on another harness instance running as an MCP server.
* Wire up the harness to an LLM that exposes itself as an MCP server
  (e.g. a Claude Desktop plugin, a local Ollama MCP wrapper).
* Write integration tests by connecting to a mock MCP server.

Usage::

    from ai_vuln_harness.mcp_client import MCPClient

    # Context manager — starts the server subprocess, sends initialize,
    # and tears it down cleanly on exit.
    with MCPClient(["ai-vuln-harness-mcp"]) as client:
        modes = client.call_tool("list_run_modes", {})
        print(modes)

    # Or use InProcessMCPClient to test against the in-process FastMCP server
    # without spawning a subprocess (useful in tests).
    from ai_vuln_harness.mcp_client import InProcessMCPClient
    with InProcessMCPClient() as client:
        tools = client.list_tools()
"""

from __future__ import annotations

import asyncio
import json
import select
import subprocess
import threading

from fastmcp.client import Client as FastMCPClient

from .mcp_server import mcp

# ---------------------------------------------------------------------------
# JSON-RPC helpers (used by the subprocess-based MCPClient)
# ---------------------------------------------------------------------------

_JSONRPC = "2.0"


def _build_request(req_id: int, method: str, params: object = None) -> str:
    msg: dict[str, object] = {"jsonrpc": _JSONRPC, "id": req_id, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


def _build_notification(method: str, params: object = None) -> str:
    msg: dict[str, object] = {"jsonrpc": _JSONRPC, "method": method}
    if params is not None:
        msg["params"] = params
    return json.dumps(msg)


# ---------------------------------------------------------------------------
# MCPClient — subprocess-based
# ---------------------------------------------------------------------------


class MCPError(Exception):
    """Raised when the MCP server returns a JSON-RPC error response."""

    def __init__(self, code: int, message: str, data: object = None) -> None:
        super().__init__(f"MCP error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class MCPClient:
    """Subprocess-based MCP client.

    Launches *cmd* as a child process and communicates over its stdin/stdout
    using line-delimited JSON-RPC 2.0 (the MCP stdio transport).

    Args:
        cmd: Command and arguments to launch the MCP server subprocess
             (e.g. ``["ai-vuln-harness-mcp"]``).
        timeout: Seconds to wait for each response.  Default: 30.

    Example::

        with MCPClient(["ai-vuln-harness-mcp"]) as client:
            tools = client.list_tools()
            result = client.call_tool("list_run_modes", {})
    """

    def __init__(self, cmd: list[str], *, timeout: float = 30.0) -> None:
        self._cmd = cmd
        self._timeout = timeout
        self._proc: subprocess.Popen[str] | None = None
        self._req_id = 0
        self._lock = threading.Lock()

    def _next_id(self) -> int:
        with self._lock:
            self._req_id += 1
            return self._req_id

    def _send(self, line: str) -> None:
        assert self._proc is not None
        assert self._proc.stdin is not None
        self._proc.stdin.write(line + "\n")
        self._proc.stdin.flush()

    def _recv(self) -> dict[str, object]:
        assert self._proc is not None
        assert self._proc.stdout is not None
        fd: int | None = None
        try:
            raw_fd = self._proc.stdout.fileno()
            fd = raw_fd if isinstance(raw_fd, int) else None
        except (ValueError, TypeError):
            pass
        while True:
            if fd is not None:
                readable, _, _ = select.select([fd], [], [], self._timeout)
                if not readable:
                    raise TimeoutError(
                        f"MCP server did not respond within {self._timeout}s"
                    )
            raw = self._proc.stdout.readline()
            if not raw:
                raise EOFError("MCP server closed stdout unexpectedly")
            raw = raw.strip()
            if raw:
                return json.loads(raw)

    def _rpc(self, method: str, params: object = None) -> object:
        req_id = self._next_id()
        self._send(_build_request(req_id, method, params))
        response = self._recv()
        if "error" in response:
            err = response["error"]
            if isinstance(err, dict):
                raise MCPError(
                    int(err.get("code", -1)),
                    str(err.get("message", "unknown")),
                    err.get("data"),
                )
        return response.get("result")

    def start(self) -> None:
        """Start the server subprocess and perform the MCP handshake."""
        if not isinstance(self._cmd, list) or not self._cmd:
            raise ValueError(f"cmd must be a non-empty list, got {self._cmd!r}")
        # nosem: Popen with a list arg avoids shell injection (no shell=True);
        # the caller provides the MCP server command explicitly.
        self._proc = subprocess.Popen(
            self._cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
        )
        # MCP initialize handshake
        self._rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "ai-vuln-harness-client", "version": "1.0.0"},
            },
        )
        # Send initialized notification (no response expected)
        self._send(_build_notification("notifications/initialized"))

    def stop(self) -> None:
        """Terminate the server subprocess."""
        if self._proc is not None:
            if self._proc.stdin:
                try:
                    self._proc.stdin.close()
                except OSError:
                    pass
            self._proc.terminate()
            try:
                self._proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
            self._proc = None

    def list_tools(self) -> list[dict[str, object]]:
        """Return the list of tools registered on the server."""
        result = self._rpc("tools/list")
        if isinstance(result, dict):
            tools = result.get("tools", [])
            if isinstance(tools, list):
                return tools
        return []

    def call_tool(self, name: str, arguments: dict[str, object]) -> object:
        """Call a named tool on the MCP server.

        Args:
            name: Tool name (e.g. ``"list_run_modes"``).
            arguments: Dict of arguments matching the tool's ``inputSchema``.

        Returns:
            The ``result`` dict from the JSON-RPC response, typically with a
            ``"content"`` key containing a list of content blocks.

        Raises:
            MCPError: If the server returns an error-level JSON-RPC response.
        """
        return self._rpc("tools/call", {"name": name, "arguments": arguments})

    def __enter__(self) -> MCPClient:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# InProcessMCPClient — test-friendly, no subprocess
# ---------------------------------------------------------------------------


class InProcessMCPClient:
    """In-process MCP client that communicates directly with the FastMCP server.

    Useful in unit tests — no subprocess is spawned.  Uses
    :mod:`fastmcp.client.Client` connected directly to the :data:`mcp` server
    instance, so the full FastMCP tool dispatch path is exercised.

    Example::

        with InProcessMCPClient() as client:
            tools = client.list_tools()
            result = client.call_tool("list_run_modes", {})
    """

    def __init__(self) -> None:
        """In-process client — FastMCP handles initialization per call."""

    def start(self) -> None:
        """FastMCP handles initialization per call, so start is a no-op."""

    def stop(self) -> None:
        """No-op for in-process client."""

    def list_tools(self) -> list[dict[str, object]]:
        """Return the tools registered on the FastMCP server as plain dicts."""

        async def _list() -> list[dict[str, object]]:
            async with FastMCPClient(mcp) as client:
                tools = await client.list_tools()
                return [
                    {
                        "name": t.name,
                        "description": t.description or "",
                        "inputSchema": t.inputSchema,
                    }
                    for t in tools
                ]

        return asyncio.run(_list())

    def call_tool(self, name: str, arguments: dict[str, object]) -> dict[str, object]:
        """Call a named tool on the FastMCP server.

        Args:
            name: Tool name (e.g. ``"list_run_modes"``).
            arguments: Dict of arguments matching the tool's input schema.

        Returns:
            A dict with a ``"content"`` key (list of ``{"type", "text"}`` dicts)
            and an optional ``"isError": True`` key when the tool reported an
            error.

        Raises:
            MCPError: If the tool is unknown (not registered on the server).
        """

        async def _call() -> dict[str, object]:
            async with FastMCPClient(mcp) as client:
                result = await client.session.call_tool(name, arguments)
                content = [
                    {"type": item.type, "text": item.text}
                    for item in result.content
                    if hasattr(item, "text")
                ]
                if result.isError:
                    text = content[0]["text"] if content else ""
                    if "Unknown tool" in text:
                        raise MCPError(-32601, text)
                    return {"content": content, "isError": True}
                return {"content": content}

        return asyncio.run(_call())

    def __enter__(self) -> InProcessMCPClient:
        self.start()
        return self

    def __exit__(self, *_: object) -> None:
        self.stop()
