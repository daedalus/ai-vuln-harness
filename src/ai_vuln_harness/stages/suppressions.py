"""Persistent false-positive suppression registry.

Stores known false positives keyed on (snippet_id, class) so that confirmed
false positives are filtered out automatically in subsequent scans, without
relying on the API response cache.

Supports two backends:
- JSON file (default, backward compatible)
- SQLite FTS5 (optional, enables fuzzy/embedding-based suppression)
"""

from __future__ import annotations

import json
import sqlite3
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

try:
    import numpy as np

    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    """Compute cosine similarity between two vectors."""
    norm_a = float(np.linalg.norm(a))
    norm_b = float(np.linalg.norm(b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


class SuppressionRegistry:
    """Registry of known-false-positive findings.

    Supports two modes:
    - **JSON mode** (default): exact (snippet_id, class) key matching.
    - **FTS5 mode** (optional): SQLite FTS5 text search + optional embedding
      similarity for fuzzy suppression matching.

    Usage::

        reg = SuppressionRegistry(Path('output/suppressions.json'))
        reg.add(finding)                    # mark as suppressed
        cleaned = reg.filter(findings)      # removes known FPs

        # FTS5 mode
        reg = SuppressionRegistry(Path('output/suppressions.json'), use_fts5=True)
        reg.add_fuzzy(finding, description="SQL injection in login")
        reg.is_suppressed_fuzzy(finding, threshold=0.85)
        results = reg.search("SQL injection")
    """

    def __init__(
        self,
        path: Path,
        use_fts5: bool = False,
    ) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)

        # JSON store (always loaded for backward compat)
        self._store: dict[str, dict] = {}
        if self.path.exists():
            try:
                raw = json.loads(self.path.read_text() or "{}")
                self._store = raw if isinstance(raw, dict) else {}
            except (json.JSONDecodeError, OSError):
                self._store = {}

        # FTS5 store
        self._use_fts5 = use_fts5
        self._conn: sqlite3.Connection | None = None
        if self._use_fts5:
            self._init_fts5()
            self._migrate_json_to_fts5()

    def _init_fts5(self) -> None:
        """Initialize FTS5 virtual table."""
        db_path = self.path.with_suffix(".db")
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("""
            CREATE TABLE IF NOT EXISTS suppressions (
                id INTEGER PRIMARY KEY,
                snippet_id TEXT NOT NULL,
                class TEXT NOT NULL,
                reason TEXT DEFAULT '',
                description TEXT DEFAULT '',
                embedding BLOB
            )
        """)
        self._conn.execute("""
            CREATE VIRTUAL TABLE IF NOT EXISTS suppressions_fts
            USING fts5(reason, description, content=suppressions, content_rowid=id)
        """)
        self._conn.commit()

    def _key(self, finding: dict) -> str:
        return json.dumps(
            [str(finding.get("snippet_id", "")), str(finding.get("class", ""))],
        )

    def add(self, finding: dict, reason: str = "") -> None:
        """Mark *finding* as a known false positive (exact match)."""
        key = self._key(finding)
        self._store[key] = {
            "snippet_id": finding.get("snippet_id", ""),
            "class": finding.get("class", ""),
            "reason": reason or finding.get("validate_reason", ""),
        }
        self._flush()

        if self._conn:
            cur = self._conn.execute(
                "INSERT OR REPLACE INTO suppressions (snippet_id, class, reason) VALUES (?, ?, ?)",
                (
                    finding.get("snippet_id", ""),
                    finding.get("class", ""),
                    reason or finding.get("validate_reason", ""),
                ),
            )
            rowid = cur.lastrowid
            self._conn.execute(
                "INSERT INTO suppressions_fts(rowid, reason, description) VALUES (?, ?, ?)",
                (rowid, reason or finding.get("validate_reason", ""), ""),
            )
            self._conn.commit()

    def _migrate_json_to_fts5(self) -> None:
        """One-time migration from JSON store to FTS5 table."""
        if not self._conn or not self._store:
            return

        count = self._conn.execute("SELECT COUNT(*) FROM suppressions").fetchone()[0]
        if count > 0:
            return

        for _key, entry in self._store.items():
            cur = self._conn.execute(
                "INSERT INTO suppressions (snippet_id, class, reason) VALUES (?, ?, ?)",
                (
                    entry.get("snippet_id", ""),
                    entry.get("class", ""),
                    entry.get("reason", ""),
                ),
            )
            rowid = cur.lastrowid
            self._conn.execute(
                "INSERT INTO suppressions_fts(rowid, reason, description) VALUES (?, ?, ?)",
                (rowid, entry.get("reason", ""), ""),
            )
        self._conn.commit()

    def suppress_many(self, findings: list[dict], reason: str = "") -> None:
        """Mark all findings in the list as known false positives."""
        for f in findings:
            self.add(f, reason=reason)

    def add_fuzzy(
        self,
        finding: dict,
        reason: str = "",
        description: str = "",
        embedding: np.ndarray | None = None,
    ) -> None:
        """Add suppression with optional fuzzy matching data.

        Parameters
        ----------
        finding:
            Finding dict (must have snippet_id and class).
        reason:
            Why this is a false positive.
        description:
            Natural language summary for FTS5 text search.
        embedding:
            384-dim float32 vector for cosine similarity matching.
        """
        # Always do exact add
        self.add(finding, reason=reason)

        if not self._conn:
            return

        # Update with description and embedding
        snippet_id = finding.get("snippet_id", "")
        cls = finding.get("class", "")

        embedding_blob = None
        if embedding is not None and _HAS_NUMPY:
            embedding_blob = embedding.astype("float32").tobytes()

        self._conn.execute(
            """UPDATE suppressions SET description = ?, embedding = ?
               WHERE snippet_id = ? AND class = ?""",
            (description, embedding_blob, snippet_id, cls),
        )

        # Update FTS with description
        row = self._conn.execute(
            "SELECT id FROM suppressions WHERE snippet_id = ? AND class = ?",
            (snippet_id, cls),
        ).fetchone()
        if row:
            self._conn.execute(
                "INSERT INTO suppressions_fts(suppressions_fts, rowid, reason, description) VALUES ('delete', ?, '', '')",
                (row[0],),
            )
            self._conn.execute(
                "INSERT INTO suppressions_fts(rowid, reason, description) VALUES (?, ?, ?)",
                (row[0], reason or "", description),
            )

        self._conn.commit()

    def is_suppressed(self, finding: dict) -> bool:
        """Exact key match (backward compatible)."""
        return self._key(finding) in self._store

    def is_suppressed_fuzzy(
        self,
        finding: dict,
        threshold: float = 0.85,
    ) -> bool:
        """Check if finding is suppressed via exact, text, or embedding match.

        Parameters
        ----------
        finding:
            Finding dict to check.
        threshold:
            Minimum cosine similarity for embedding match.

        Returns
        -------
        True if finding matches any existing suppression.
        """
        # Exact match first
        if self.is_suppressed(finding):
            return True

        if not self._conn:
            return False

        snippet_id = finding.get("snippet_id", "")
        cls = finding.get("class", "")

        # FTS5 text match on class
        try:
            rows = self._conn.execute(
                """SELECT id, embedding FROM suppressions
                   WHERE class = ? OR snippet_id = ?""",
                (cls, snippet_id),
            ).fetchall()
        except sqlite3.OperationalError:
            return False

        if rows:
            return True

        # Embedding similarity match
        if _HAS_NUMPY and finding.get("_embedding") is not None:
            query_emb = finding["_embedding"].astype("float32")
            all_rows = self._conn.execute(
                "SELECT id, embedding FROM suppressions WHERE embedding IS NOT NULL",
            ).fetchall()
            for _row_id, emb_blob in all_rows:
                if emb_blob:
                    stored_emb = np.frombuffer(emb_blob, dtype="float32")
                    sim = _cosine_similarity(query_emb, stored_emb)
                    if sim >= threshold:
                        return True

        return False

    def search(self, query: str, limit: int = 50) -> list[dict]:
        """Full-text search across suppressions.

        Parameters
        ----------
        query:
            Search query (FTS5 MATCH syntax).
        limit:
            Maximum results.

        Returns
        -------
        List of suppression dicts matching the query.
        """
        if not self._conn:
            return []

        try:
            rows = self._conn.execute(
                """SELECT s.snippet_id, s.class, s.reason, s.description
                   FROM suppressions_fts f
                   JOIN suppressions s ON s.id = f.rowid
                   WHERE suppressions_fts MATCH ?
                   LIMIT ?""",
                (query, limit),
            ).fetchall()
        except sqlite3.OperationalError:
            return []

        return [
            {
                "snippet_id": r[0],
                "class": r[1],
                "reason": r[2],
                "description": r[3],
            }
            for r in rows
        ]

    def filter(self, findings: list[dict]) -> tuple[list[dict], list[dict]]:
        """Return ``(kept, suppressed)``.

        Findings whose ``(snippet_id, class)`` key appears in the registry are
        removed from *kept* and placed in *suppressed*.
        """
        kept: list[dict] = []
        suppressed: list[dict] = []
        for f in findings:
            if self._use_fts5 and self.is_suppressed_fuzzy(f):
                suppressed.append({**f, "suppressed_by_registry": True})
            elif self.is_suppressed(f):
                suppressed.append({**f, "suppressed_by_registry": True})
            else:
                kept.append(f)
        return kept, suppressed

    def _flush(self) -> None:
        self.path.write_text(json.dumps(self._store, indent=2))

    def close(self) -> None:
        """Close database connection if open."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __len__(self) -> int:
        if self._conn:
            count = self._conn.execute("SELECT COUNT(*) FROM suppressions").fetchone()[
                0
            ]
            return count
        return len(self._store)

    def __contains__(self, finding: dict) -> bool:
        return self.is_suppressed(finding)

    def __enter__(self) -> SuppressionRegistry:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()
