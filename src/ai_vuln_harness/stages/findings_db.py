"""Persistent findings database with FTS5 full-text search.

Stores scan findings in SQLite with FTS5 indexing for cross-run search,
similarity queries, and aggregate statistics.

Usage:
    db = FindingsDB(Path("output/findings.db"))
    db.store_findings(findings, run_id="abc123")
    results = db.search("path traversal in auth")
    similar = db.get_similar(finding, threshold=0.85)
    stats = db.stats()
"""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

try:
    import numpy as np

    _HAS_NUMPY = True
except ImportError:
    _HAS_NUMPY = False


def _cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    norm_a = float(np.linalg.norm(a))
    norm_b = float(np.linalg.norm(b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return float(np.dot(a, b) / (norm_a * norm_b))


class FindingsDB:
    """SQLite + FTS5 database for persisting and querying findings across scans.

    Parameters
    ----------
    db_path:
        Path to the SQLite database file.
    """

    def __init__(self, db_path: Path | str) -> None:
        self._db_path = str(db_path)
        self._conn = sqlite3.connect(self._db_path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._init_schema()

    def _init_schema(self) -> None:
        """Create tables and indexes if they don't exist."""
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY,
                finding_id TEXT NOT NULL,
                run_id TEXT NOT NULL,
                run_timestamp TEXT NOT NULL,
                file_path TEXT,
                vuln_class TEXT,
                severity TEXT,
                confidence REAL,
                description TEXT,
                full_json TEXT,
                embedding BLOB
            );

            CREATE VIRTUAL TABLE IF NOT EXISTS findings_fts USING fts5(
                finding_id, vuln_class, description, file_path,
                content=findings, content_rowid=id
            );

            CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id);
            CREATE INDEX IF NOT EXISTS idx_findings_class ON findings(vuln_class);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
        """)
        self._conn.commit()

    def store_findings(self, findings: list[dict], run_id: str) -> int:
        """Store findings from a scan run.

        Parameters
        ----------
        findings:
            List of finding dicts.
        run_id:
            Scan run identifier.

        Returns
        -------
        int
            Number of findings stored.
        """
        if not findings:
            return 0

        ts = datetime.now(UTC).isoformat()
        count = 0

        for f in findings:
            finding_id = f.get("finding_id") or f.get("snippet_id", "")
            if not finding_id:
                continue

            # Check for duplicate within same run
            existing = self._conn.execute(
                "SELECT id FROM findings WHERE finding_id = ? AND run_id = ?",
                (finding_id, run_id),
            ).fetchone()
            if existing:
                continue

            embedding_blob = None
            emb = f.get("_embedding")
            if emb is not None and _HAS_NUMPY:
                embedding_blob = np.asarray(emb, dtype="float32").tobytes()

            serializable = {k: v for k, v in f.items() if k != "_embedding"}

            cur = self._conn.execute(
                """INSERT INTO findings
                   (finding_id, run_id, run_timestamp, file_path, vuln_class,
                    severity, confidence, description, full_json, embedding)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    finding_id,
                    run_id,
                    ts,
                    f.get("file") or f.get("file_path", ""),
                    f.get("class") or f.get("vuln_class", ""),
                    f.get("severity", ""),
                    f.get("confidence") or f.get("validate_confidence") or 0.0,
                    f.get("desc") or f.get("description", ""),
                    json.dumps(serializable),
                    embedding_blob,
                ),
            )
            rowid = cur.lastrowid
            self._conn.execute(
                """INSERT INTO findings_fts(rowid, finding_id, vuln_class, description, file_path)
                   VALUES (?, ?, ?, ?, ?)""",
                (
                    rowid,
                    finding_id,
                    f.get("class") or f.get("vuln_class", ""),
                    f.get("desc") or f.get("description", ""),
                    f.get("file") or f.get("file_path", ""),
                ),
            )
            count += 1

        self._conn.commit()
        return count

    def search(
        self,
        query: str,
        *,
        vuln_class: str | None = None,
        severity: str | None = None,
        file_pattern: str | None = None,
        min_run_id: str | None = None,
        limit: int = 50,
    ) -> list[dict]:
        """Full-text search across all stored findings.

        Parameters
        ----------
        query:
            Search query (FTS5 MATCH syntax).
        vuln_class:
            Filter by vulnerability class.
        severity:
            Filter by severity level.
        file_pattern:
            Filter by file path (SQL LIKE pattern).
        min_run_id:
            Only include runs with run_id >= this value.
        limit:
            Maximum results.

        Returns
        -------
        List of finding dicts.
        """
        conditions = []
        params: list = []

        if vuln_class:
            conditions.append("f.vuln_class = ?")
            params.append(vuln_class)
        if severity:
            conditions.append("f.severity = ?")
            params.append(severity)
        if file_pattern:
            conditions.append("f.file_path LIKE ?")
            params.append(file_pattern)
        if min_run_id:
            conditions.append("f.run_id >= ?")
            params.append(min_run_id)

        where_clause = ""
        if conditions:
            where_clause = "WHERE " + " AND ".join(conditions)

        if query:
            try:
                rows = self._conn.execute(
                    f"""SELECT f.finding_id, f.run_id, f.run_timestamp,
                               f.file_path, f.vuln_class, f.severity,
                               f.confidence, f.description, f.full_json
                        FROM findings_fts ft
                        JOIN findings f ON f.id = ft.rowid
                        WHERE findings_fts MATCH ?
                        {where_clause}
                        LIMIT ?""",
                    [query] + params + [limit],
                ).fetchall()
            except sqlite3.OperationalError:
                return []
        else:
            rows = self._conn.execute(
                f"""SELECT finding_id, run_id, run_timestamp,
                           file_path, vuln_class, severity,
                           confidence, description, full_json
                    FROM findings f
                    {where_clause}
                    LIMIT ?""",
                params + [limit],
            ).fetchall()

        return [self._row_to_dict(r) for r in rows]

    def get_similar(
        self,
        finding: dict,
        threshold: float = 0.85,
        limit: int = 10,
    ) -> list[dict]:
        """Find semantically similar findings from past runs.

        Parameters
        ----------
        finding:
            Reference finding dict (needs ``_embedding`` or ``class`` + ``desc``).
        threshold:
            Minimum cosine similarity.
        limit:
            Maximum results.

        Returns
        -------
        List of similar finding dicts, ordered by similarity descending.
        """
        if not _HAS_NUMPY:
            return []

        query_emb = finding.get("_embedding")
        if query_emb is None:
            return []

        query_np = np.asarray(query_emb, dtype="float32")
        query_norm = float(np.linalg.norm(query_np))
        if query_norm == 0:
            return []

        rows = self._conn.execute(
            "SELECT id, finding_id, run_id, embedding FROM findings WHERE embedding IS NOT NULL",
        ).fetchall()

        results: list[tuple[float, dict]] = []
        for row_id, fid, run_id, emb_blob in rows:
            if emb_blob:
                stored_emb = np.frombuffer(emb_blob, dtype="float32")
                sim = _cosine_similarity(query_np, stored_emb)
                if sim >= threshold:
                    full = self._conn.execute(
                        """SELECT finding_id, run_id, run_timestamp,
                                  file_path, vuln_class, severity,
                                  confidence, description, full_json
                           FROM findings WHERE id = ?""",
                        (row_id,),
                    ).fetchone()
                    if full:
                        d = self._row_to_dict(full)
                        d["similarity"] = round(sim, 4)
                        results.append((sim, d))

        results.sort(key=lambda x: x[0], reverse=True)
        return [d for _, d in results[:limit]]

    def stats(self) -> dict:
        """Aggregate stats: findings per severity, per class, per run."""
        result: dict = {}

        rows = self._conn.execute(
            "SELECT severity, COUNT(*) FROM findings GROUP BY severity",
        ).fetchall()
        result["by_severity"] = {r[0] or "unknown": r[1] for r in rows}

        rows = self._conn.execute(
            "SELECT vuln_class, COUNT(*) FROM findings GROUP BY vuln_class",
        ).fetchall()
        result["by_class"] = {r[0] or "unknown": r[1] for r in rows}

        rows = self._conn.execute(
            "SELECT run_id, COUNT(*) FROM findings GROUP BY run_id",
        ).fetchall()
        result["by_run"] = {r[0]: r[1] for r in rows}

        result["total"] = self._conn.execute(
            "SELECT COUNT(*) FROM findings",
        ).fetchone()[0]

        return result

    def _row_to_dict(self, row: tuple) -> dict:
        """Convert a database row to a finding dict."""
        fid, run_id, ts, fpath, vclass, sev, conf, desc, full_json = row
        d: dict = {
            "finding_id": fid,
            "run_id": run_id,
            "run_timestamp": ts,
            "file_path": fpath,
            "vuln_class": vclass,
            "severity": sev,
            "confidence": conf,
            "description": desc,
        }
        if full_json:
            try:
                d.update(json.loads(full_json))
            except (json.JSONDecodeError, TypeError):
                pass
        return d

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
