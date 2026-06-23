"""Engagement Graph: typed SQLite world model for shared state across agents.

Implements the Mythos Architecture's C1 component — a typed graph with 6 tables:
  surface, facts, hypotheses, findings, dead_ends, chains

Every pipeline stage writes into this graph, providing a shared world model
across all agents. This enables:
- Cross-session observation persistence
- Chain discovery across findings
- Dead-end tracking (abandoned hypotheses)
- Attack surface mapping
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


class EngagementGraph:
    """Typed SQLite world model with 6 tables for shared engagement state."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        cur = self.conn.cursor()
        cur.executescript("""
            CREATE TABLE IF NOT EXISTS surface (
                id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                detail TEXT,
                source TEXT,
                ts REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS facts (
                id TEXT PRIMARY KEY,
                content TEXT NOT NULL,
                source TEXT,
                ts REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS hypotheses (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                vuln_class TEXT NOT NULL,
                claim TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'open',
                poc_sketch TEXT,
                source TEXT,
                ts REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                hyp_id TEXT,
                severity TEXT NOT NULL,
                cwe TEXT,
                title TEXT NOT NULL,
                file TEXT,
                poc_path TEXT,
                evidence TEXT,
                corroborators TEXT,
                cve_anchor TEXT,
                ts REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS dead_ends (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                why TEXT NOT NULL,
                source TEXT,
                ts REAL NOT NULL
            );

            CREATE TABLE IF NOT EXISTS chains (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                links TEXT NOT NULL,
                composite_poc_path TEXT,
                is_critical INTEGER NOT NULL DEFAULT 0,
                ts REAL NOT NULL
            );
        """)
        self.conn.commit()

    def _now(self) -> float:
        return time.time()

    def _gen_id(self, prefix: str, content: str) -> str:
        h = hashlib.sha256(content.encode()).hexdigest()[:12]
        return f"{prefix}:{h}"

    # --- Surface ---

    def add_surface(
        self, kind: str, path: str, detail: str = "", source: str = ""
    ) -> str:
        """Add an attack surface entry."""
        sid = self._gen_id("surf", f"{kind}:{path}:{detail}")
        self.conn.execute(
            "INSERT OR IGNORE INTO surface(id, kind, path, detail, source, ts) VALUES(?,?,?,?,?,?)",
            (sid, kind, path, detail, source, self._now()),
        )
        self.conn.commit()
        return sid

    def get_surface(self, sid: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM surface WHERE id=?", (sid,)).fetchone()
        return dict(row) if row else None

    def list_surface(self, kind: str | None = None) -> list[dict]:
        if kind:
            rows = self.conn.execute(
                "SELECT * FROM surface WHERE kind=? ORDER BY ts", (kind,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM surface ORDER BY ts").fetchall()
        return [dict(r) for r in rows]

    # --- Facts ---

    def add_fact(self, content: str, source: str = "") -> str:
        """Add a factual observation."""
        fid = self._gen_id("fact", content)
        self.conn.execute(
            "INSERT OR IGNORE INTO facts(id, content, source, ts) VALUES(?,?,?,?)",
            (fid, content, source, self._now()),
        )
        self.conn.commit()
        return fid

    def get_fact(self, fid: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM facts WHERE id=?", (fid,)).fetchone()
        return dict(row) if row else None

    def list_facts(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM facts ORDER BY ts").fetchall()
        return [dict(r) for r in rows]

    # --- Hypotheses ---

    def add_hypothesis(
        self,
        target: str,
        vuln_class: str,
        claim: str,
        poc_sketch: str = "",
        source: str = "",
    ) -> str:
        """Add a vulnerability hypothesis."""
        hid = self._gen_id("hyp", f"{target}:{vuln_class}:{claim}")
        self.conn.execute(
            "INSERT OR IGNORE INTO hypotheses(id, target, vuln_class, claim, status, poc_sketch, source, ts) VALUES(?,?,?,?,?,?,?,?)",
            (hid, target, vuln_class, claim, "open", poc_sketch, source, self._now()),
        )
        self.conn.commit()
        return hid

    def update_hypothesis_status(self, hid: str, status: str) -> None:
        """Update hypothesis status (open, confirmed, rejected, dead_end)."""
        self.conn.execute("UPDATE hypotheses SET status=? WHERE id=?", (status, hid))
        self.conn.commit()

    def get_hypothesis(self, hid: str) -> dict | None:
        row = self.conn.execute(
            "SELECT * FROM hypotheses WHERE id=?", (hid,)
        ).fetchone()
        return dict(row) if row else None

    def list_hypotheses(self, status: str | None = None) -> list[dict]:
        if status:
            rows = self.conn.execute(
                "SELECT * FROM hypotheses WHERE status=? ORDER BY ts", (status,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM hypotheses ORDER BY ts").fetchall()
        return [dict(r) for r in rows]

    # --- Findings ---

    def add_finding(
        self,
        title: str,
        severity: str,
        hyp_id: str = "",
        cwe: str = "",
        file: str = "",
        poc_path: str = "",
        evidence: str = "",
        corroborators: str = "",
        cve_anchor: str = "",
    ) -> str:
        """Add a confirmed finding."""
        fid = self._gen_id("find", f"{title}:{severity}:{file}")
        self.conn.execute(
            """INSERT OR IGNORE INTO findings(
                id, hyp_id, severity, cwe, title, file, poc_path,
                evidence, corroborators, cve_anchor, ts
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
            (
                fid,
                hyp_id,
                severity,
                cwe,
                title,
                file,
                poc_path,
                evidence,
                corroborators,
                cve_anchor,
                self._now(),
            ),
        )
        self.conn.commit()
        return fid

    def get_finding(self, fid: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
        return dict(row) if row else None

    def list_findings(self, severity: str | None = None) -> list[dict]:
        if severity:
            rows = self.conn.execute(
                "SELECT * FROM findings WHERE severity=? ORDER BY ts", (severity,)
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM findings ORDER BY ts").fetchall()
        return [dict(r) for r in rows]

    # --- Dead Ends ---

    def add_dead_end(self, target: str, why: str, source: str = "") -> str:
        """Record a dead end (abandoned hypothesis)."""
        did = self._gen_id("dead", f"{target}:{why}")
        self.conn.execute(
            "INSERT OR IGNORE INTO dead_ends(id, target, why, source, ts) VALUES(?,?,?,?,?)",
            (did, target, why, source, self._now()),
        )
        self.conn.commit()
        return did

    def list_dead_ends(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM dead_ends ORDER BY ts").fetchall()
        return [dict(r) for r in rows]

    # --- Chains ---

    def add_chain(
        self,
        name: str,
        links: list[str],
        composite_poc_path: str = "",
        is_critical: bool = False,
    ) -> str:
        """Add an exploit chain."""
        cid = self._gen_id("chain", f"{name}:{json.dumps(links)}")
        self.conn.execute(
            """INSERT OR IGNORE INTO chains(
                id, name, links, composite_poc_path, is_critical, ts
            ) VALUES(?,?,?,?,?,?)""",
            (
                cid,
                name,
                json.dumps(links),
                composite_poc_path,
                int(is_critical),
                self._now(),
            ),
        )
        self.conn.commit()
        return cid

    def get_chain(self, cid: str) -> dict | None:
        row = self.conn.execute("SELECT * FROM chains WHERE id=?", (cid,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["links"] = json.loads(d["links"])
        return d

    def list_chains(self, critical_only: bool = False) -> list[dict]:
        if critical_only:
            rows = self.conn.execute(
                "SELECT * FROM chains WHERE is_critical=1 ORDER BY ts"
            ).fetchall()
        else:
            rows = self.conn.execute("SELECT * FROM chains ORDER BY ts").fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["links"] = json.loads(d["links"])
            result.append(d)
        return result

    # --- Aggregate Queries ---

    def summary(self) -> dict:
        """Return a summary of all graph contents."""
        return {
            "surface_count": self.conn.execute(
                "SELECT COUNT(*) FROM surface"
            ).fetchone()[0],
            "facts_count": self.conn.execute("SELECT COUNT(*) FROM facts").fetchone()[
                0
            ],
            "hypotheses_count": self.conn.execute(
                "SELECT COUNT(*) FROM hypotheses"
            ).fetchone()[0],
            "hypotheses_open": self.conn.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE status='open'"
            ).fetchone()[0],
            "hypotheses_confirmed": self.conn.execute(
                "SELECT COUNT(*) FROM hypotheses WHERE status='confirmed'"
            ).fetchone()[0],
            "findings_count": self.conn.execute(
                "SELECT COUNT(*) FROM findings"
            ).fetchone()[0],
            "dead_ends_count": self.conn.execute(
                "SELECT COUNT(*) FROM dead_ends"
            ).fetchone()[0],
            "chains_count": self.conn.execute("SELECT COUNT(*) FROM chains").fetchone()[
                0
            ],
            "chains_critical": self.conn.execute(
                "SELECT COUNT(*) FROM chains WHERE is_critical=1"
            ).fetchone()[0],
        }

    def export_json(self) -> dict:
        """Export entire graph as a JSON-serializable dict."""
        return {
            "surface": self.list_surface(),
            "facts": self.list_facts(),
            "hypotheses": self.list_hypotheses(),
            "findings": self.list_findings(),
            "dead_ends": self.list_dead_ends(),
            "chains": self.list_chains(),
            "summary": self.summary(),
        }

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> EngagementGraph:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()
