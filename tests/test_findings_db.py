"""Tests for stages/findings_db.py — persistent findings database."""

import json
import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.findings_db import FindingsDB, _HAS_NUMPY


class FindingsDBTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self._tmp.name) / "findings.db"

    def tearDown(self):
        self._tmp.cleanup()

    def _finding(
        self,
        fid: str = "find:001",
        cls: str = "sql-injection",
        sev: str = "HIGH",
        desc: str = "SQL injection in login",
        file: str = "src/auth.py",
    ) -> dict:
        return {
            "finding_id": fid,
            "snippet_id": fid,
            "class": cls,
            "severity": sev,
            "desc": desc,
            "file": file,
            "confidence": 0.8,
            "status": "raw",
        }

    def test_store_and_retrieve(self):
        """Store findings and retrieve via FTS5 search."""
        with FindingsDB(self.db_path) as db:
            f = self._finding()
            count = db.store_findings([f], run_id="run1")
            self.assertEqual(count, 1)
            results = db.search("SQL injection")
            self.assertGreater(len(results), 0)
            self.assertEqual(results[0]["finding_id"], "find:001")

    def test_store_empty_list(self):
        """Storing empty list returns 0."""
        with FindingsDB(self.db_path) as db:
            count = db.store_findings([], run_id="run1")
            self.assertEqual(count, 0)

    def test_store_duplicate_same_run(self):
        """Duplicate finding_id in same run is skipped."""
        with FindingsDB(self.db_path) as db:
            f = self._finding()
            db.store_findings([f], run_id="run1")
            count = db.store_findings([f], run_id="run1")
            self.assertEqual(count, 0)

    def test_store_duplicate_different_run(self):
        """Same finding_id in different runs is stored."""
        with FindingsDB(self.db_path) as db:
            f = self._finding()
            db.store_findings([f], run_id="run1")
            count = db.store_findings([f], run_id="run2")
            self.assertEqual(count, 1)

    def test_search_by_vuln_class(self):
        """Search filtered by vulnerability class."""
        with FindingsDB(self.db_path) as db:
            db.store_findings(
                [self._finding(fid="f1", cls="sql-injection"), self._finding(fid="f2", cls="xss")],
                run_id="run1",
            )
            results = db.search("", vuln_class="xss")
            self.assertEqual(len(results), 1)
            self.assertEqual(results[0]["vuln_class"], "xss")

    def test_search_by_severity(self):
        """Search filtered by severity."""
        with FindingsDB(self.db_path) as db:
            db.store_findings(
                [self._finding(fid="f1", sev="HIGH"), self._finding(fid="f2", sev="LOW")],
                run_id="run1",
            )
            results = db.search("", severity="LOW")
            self.assertEqual(len(results), 1)

    def test_search_by_file_pattern(self):
        """Search filtered by file path LIKE pattern."""
        with FindingsDB(self.db_path) as db:
            db.store_findings(
                [self._finding(fid="f1", file="src/auth.py"), self._finding(fid="f2", file="src/api.py")],
                run_id="run1",
            )
            results = db.search("", file_pattern="%auth%")
            self.assertEqual(len(results), 1)

    def test_stats(self):
        """Stats returns correct aggregates."""
        with FindingsDB(self.db_path) as db:
            db.store_findings(
                [
                    self._finding(fid="f1", cls="sql-injection", sev="HIGH"),
                    self._finding(fid="f2", cls="xss", sev="LOW"),
                    self._finding(fid="f3", cls="sql-injection", sev="MEDIUM"),
                ],
                run_id="run1",
            )
            stats = db.stats()
            self.assertEqual(stats["total"], 3)
            self.assertEqual(stats["by_severity"]["HIGH"], 1)
            self.assertEqual(stats["by_class"]["sql-injection"], 2)

    def test_context_manager(self):
        """Context manager closes connection."""
        db = FindingsDB(self.db_path)
        db.close()
        self.assertIsNone(db._conn)

    def test_search_no_fts_match(self):
        """FTS5 search with no results returns empty."""
        with FindingsDB(self.db_path) as db:
            db.store_findings([self._finding()], run_id="run1")
            results = db.search("zzz_nonexistent_xyz")
            self.assertEqual(results, [])

    def test_search_no_filter(self):
        """Search without filters returns all."""
        with FindingsDB(self.db_path) as db:
            db.store_findings(
                [self._finding(fid="f1"), self._finding(fid="f2")],
                run_id="run1",
            )
            results = db.search("")
            self.assertEqual(len(results), 2)

    @unittest.skipUnless(_HAS_NUMPY, "numpy not installed")
    def test_get_similar(self):
        """get_similar finds semantically similar findings."""
        import numpy as np

        with FindingsDB(self.db_path) as db:
            emb1 = np.random.randn(384).astype("float32")
            emb2 = np.random.randn(384).astype("float32")
            f1 = self._finding(fid="f1")
            f1["_embedding"] = emb1
            f2 = self._finding(fid="f2")
            f2["_embedding"] = emb2
            db.store_findings([f1, f2], run_id="run1")

            query = self._finding(fid="q1")
            query["_embedding"] = emb1  # same as f1
            results = db.get_similar(query, threshold=0.5, limit=5)
            self.assertGreater(len(results), 0)
            self.assertEqual(results[0]["finding_id"], "f1")


if __name__ == "__main__":
    unittest.main()
