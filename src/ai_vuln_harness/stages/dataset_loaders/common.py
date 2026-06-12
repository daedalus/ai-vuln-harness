"""Common utilities for dataset loaders."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..rag_kb import VulnerabilityKB


def _default_cache_dir() -> Path:
    """Return the default cache directory (~/.ai-vuln-harness/cache/)."""
    return Path.home() / ".ai-vuln-harness" / "cache"


def _default_db_dir() -> Path:
    """Return the default database directory (~/.ai-vuln-harness/db/)."""
    return Path.home() / ".ai-vuln-harness" / "db"
