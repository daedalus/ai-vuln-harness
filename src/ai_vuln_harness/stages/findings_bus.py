"""Shared Findings Bus — JSONL inter-agent communication.

Agents read the bus before writing to avoid duplicating findings.
Each finding gets a deterministic ID (SHA256-based) that enables
exact dedup across agents.

This implements the Claude Mythos Red Teaming Framework's shared
findings bus pattern (/tmp/findings.jsonl).
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)


class FindingsBus:
    """Thread-safe JSONL-based findings bus for inter-agent communication.

    Agents append findings to the bus. Before writing, they should
    check for existing entries with the same finding_id to avoid
    duplication.
    """

    def __init__(self, path: Path | str) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._seen_ids: set[str] = set()
        self._load_existing()

    def _load_existing(self) -> None:
        """Load existing finding IDs from the bus file."""
        if not self._path.exists():
            return
        try:
            for line in self._path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    fid = entry.get("finding_id", "")
                    if fid:
                        self._seen_ids.add(fid)
                except json.JSONDecodeError:
                    continue
        except Exception as e:
            logger.warning("findings_bus: failed to load existing: %s", e)

    @staticmethod
    def compute_finding_id(finding: dict) -> str:
        """Compute deterministic finding ID: SHA256(file + class + line_range)."""
        lines = finding.get("lines") or []
        start_line = lines[0] if lines else 0
        end_line = lines[-1] if len(lines) > 1 else start_line
        file_key = str(finding.get("file") or finding.get("snippet_id") or "")
        vuln_class = str(finding.get("class") or "")
        line_range = f"{start_line}-{end_line}"
        raw = f"{file_key}|{vuln_class}|{line_range}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def is_duplicate(self, finding: dict) -> bool:
        """Check if a finding is already on the bus."""
        fid = finding.get("finding_id") or self.compute_finding_id(finding)
        return fid in self._seen_ids

    def append(self, finding: dict) -> bool:
        """Append a finding to the bus. Returns True if new, False if duplicate."""
        fid = finding.get("finding_id") or self.compute_finding_id(finding)

        with self._lock:
            if fid in self._seen_ids:
                return False

            entry = {**finding, "finding_id": fid}
            self._seen_ids.add(fid)

            try:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                with open(self._path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(entry, default=str) + "\n")
            except Exception as e:
                logger.warning("findings_bus: failed to append: %s", e)
                return False

        return True

    @property
    def count(self) -> int:
        """Number of unique findings on the bus."""
        return len(self._seen_ids)

    def read_all(self) -> list[dict]:
        """Read all findings from the bus."""
        if not self._path.exists():
            return []
        results = []
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                results.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return results
