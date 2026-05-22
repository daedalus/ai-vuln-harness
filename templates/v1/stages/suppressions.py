"""Persistent false-positive suppression registry.

Stores known false positives keyed on (snippet_id, class) so that confirmed
false positives are filtered out automatically in subsequent scans, without
relying on the API response cache.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class SuppressionRegistry:
    """JSON-backed registry of known-false-positive (snippet_id, class) pairs.

    Usage::

        reg = SuppressionRegistry(Path('output/suppressions.json'))
        reg.add(finding)           # mark as suppressed
        cleaned = reg.filter(findings)  # removes known FPs
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text() or "{}")
                self._store: dict[str, dict] = raw if isinstance(raw, dict) else {}
            except (json.JSONDecodeError, OSError):
                self._store = {}
        else:
            self._store = {}

    @staticmethod
    def _key(finding: dict) -> str:
        return json.dumps(
            [str(finding.get("snippet_id", "")), str(finding.get("class", ""))],
        )

    def add(self, finding: dict, reason: str = "") -> None:
        """Mark *finding* as a known false positive."""
        key = self._key(finding)
        self._store[key] = {
            "snippet_id": finding.get("snippet_id", ""),
            "class": finding.get("class", ""),
            "reason": reason or finding.get("validate_reason", ""),
        }
        self._flush()

    def suppress_many(self, findings: list[dict], reason: str = "") -> None:
        """Mark all findings in the list as known false positives."""
        for f in findings:
            self.add(f, reason=reason)

    def is_suppressed(self, finding: dict) -> bool:
        return self._key(finding) in self._store

    def filter(self, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        """Return ``(kept, suppressed)``.

        Findings whose ``(snippet_id, class)`` key appears in the registry are
        removed from *kept* and placed in *suppressed*.
        """
        kept: list[dict] = []
        suppressed: list[dict] = []
        for f in findings:
            if self.is_suppressed(f):
                suppressed.append({**f, "suppressed_by_registry": True})
            else:
                kept.append(f)
        return kept, suppressed

    def _flush(self) -> None:
        self.path.write_text(json.dumps(self._store, indent=2))

    def __len__(self) -> int:
        return len(self._store)

    def __contains__(self, finding: dict) -> bool:
        return self.is_suppressed(finding)
