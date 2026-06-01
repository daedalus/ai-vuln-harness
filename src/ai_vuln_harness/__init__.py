from __future__ import annotations

from .mcp_client import InProcessMCPClient, MCPClient, MCPError
from .mcp_server import main as mcp_serve
from .run import main, run, run_all
from .skill_loader import load_skill_metadata, skill_description, skill_name

__version__ = "0.1.0"
__all__ = [
    "main",
    "run",
    "run_all",
    "load_skill_metadata",
    "skill_name",
    "skill_description",
    "mcp_serve",
    "MCPClient",
    "InProcessMCPClient",
    "MCPError",
]
