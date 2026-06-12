"""Tests for stages/rag_kb.py — RAG Knowledge Base for CWE/CVE patterns."""

import json
import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.rag_kb import VulnerabilityKB, _HAS_FAISS, _HAS_SKLEARN


class VulnerabilityKBTests(unittest.TestCase):
    def setUp(self):
        self.kb = VulnerabilityKB()

    def test_initial_size(self):
        self.assertGreater(self.kb.size, 0)

    def test_search_sqli(self):
        results = self.kb.search("SELECT * FROM users WHERE id = ?", top_k=3)
        self.assertGreater(len(results), 0)
        cwcs = [r["cwe"] for r in results]
        self.assertIn("CWE-89", cwcs)

    def test_search_command_injection(self):
        results = self.kb.search("os.system(user_input)", top_k=3)
        self.assertGreater(len(results), 0)
        cwcs = [r["cwe"] for r in results]
        self.assertIn("CWE-78", cwcs)

    def test_search_xss(self):
        results = self.kb.search("innerHTML = userInput", top_k=3)
        self.assertGreater(len(results), 0)
        cwcs = [r["cwe"] for r in results]
        self.assertIn("CWE-79", cwcs)

    def test_search_pickle(self):
        results = self.kb.search("pickle.load(data)", top_k=3)
        self.assertGreater(len(results), 0)
        cwcs = [r["cwe"] for r in results]
        self.assertIn("CWE-502", cwcs)

    def test_search_ssrf(self):
        results = self.kb.search("requests.get(user_url)", top_k=3)
        self.assertGreater(len(results), 0)
        cwcs = [r["cwe"] for r in results]
        self.assertIn("CWE-918", cwcs)

    def test_add_pattern(self):
        self.kb.add_pattern(
            cwe="CWE-999",
            title="Custom Vulnerability",
            description="A custom test vulnerability",
            patterns=["custom_pattern"],
        )
        self.assertEqual(self.kb.size, len(self.kb.list_patterns()))
        result = self.kb.get_pattern("CWE-999")
        self.assertIsNotNone(result)
        self.assertEqual(result["title"], "Custom Vulnerability")

    def test_get_pattern(self):
        result = self.kb.get_pattern("CWE-89")
        self.assertIsNotNone(result)
        self.assertEqual(result["title"], "SQL Injection")

    def test_get_pattern_not_found(self):
        result = self.kb.get_pattern("CWE-99999")
        self.assertIsNone(result)

    def test_list_patterns(self):
        patterns = self.kb.list_patterns()
        self.assertEqual(len(patterns), self.kb.size)
        self.assertTrue(all("cwe" in p for p in patterns))

    def test_search_threshold(self):
        results = self.kb.search("completely unrelated query xyz", threshold=0.9)
        self.assertLessEqual(len(results), 2)

    def test_load_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "patterns.json"
            patterns = [
                {"cwe": "CWE-8888", "title": "Test", "description": "Test vuln", "patterns": ["test"]},
            ]
            path.write_text(json.dumps(patterns))
            loaded = self.kb.load_from_file(path)
            self.assertEqual(loaded, 1)
            result = self.kb.get_pattern("CWE-8888")
            self.assertIsNotNone(result)

    def test_search_returns_score(self):
        results = self.kb.search("SQL injection vulnerability", top_k=1)
        self.assertGreater(len(results), 0)
        self.assertIn("score", results[0])
        self.assertGreater(results[0]["score"], 0)

    def test_search_returns_patterns(self):
        results = self.kb.search("pickle.load", top_k=1)
        self.assertGreater(len(results), 0)
        self.assertIn("patterns", results[0])
        self.assertIsInstance(results[0]["patterns"], list)

    def test_keyword_fallback(self):
        results = self.kb._keyword_search("pickle.load(data)", top_k=3)
        self.assertGreater(len(results), 0)
        cwcs = [r["cwe"] for r in results]
        self.assertIn("CWE-502", cwcs)

    def test_search_backend(self):
        results = self.kb.search("SQL injection", top_k=1)
        if results:
            backend = results[0].get("backend")
            if _HAS_SKLEARN:
                self.assertEqual(backend, "tfidf")
            else:
                self.assertEqual(backend, "keyword")


class VulnerabilityKBDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test_kb.db"

    def tearDown(self):
        self.tmp.cleanup()

    def test_init_with_db(self):
        with VulnerabilityKB(self.db_path) as kb:
            self.assertGreater(kb.size, 0)
            self.assertIsNotNone(kb._conn)

    def test_add_pattern_persist(self):
        with VulnerabilityKB(self.db_path) as kb:
            kb.add_pattern(
                cwe="CWE-7777",
                title="Persisted Pattern",
                description="Test persistence",
                patterns=["persist"],
                persist=True,
            )
            rows = kb._conn.execute("SELECT * FROM cwe_patterns WHERE cwe='CWE-7777'").fetchall()
            self.assertEqual(len(rows), 1)

    def test_load_from_file_persist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "patterns.json"
            patterns = [
                {"cwe": "CWE-8888", "title": "File Pattern", "description": "From file", "patterns": ["file"]},
            ]
            path.write_text(json.dumps(patterns))

            with VulnerabilityKB(self.db_path) as kb:
                loaded = kb.load_from_file(path, persist=True)
                self.assertEqual(loaded, 1)
                rows = kb._conn.execute("SELECT * FROM cwe_patterns WHERE cwe='CWE-8888'").fetchall()
                self.assertEqual(len(rows), 1)

    def test_db_survives_reopen(self):
        with VulnerabilityKB(self.db_path) as kb:
            kb.add_pattern(
                cwe="CWE-6666",
                title="Persistent",
                description="Should survive",
                patterns=["survive"],
                persist=True,
            )
        with VulnerabilityKB(self.db_path) as kb:
            result = kb.get_pattern("CWE-6666")
            self.assertIsNotNone(result)
            self.assertEqual(result["title"], "Persistent")

    def test_context_manager(self):
        with VulnerabilityKB(self.db_path) as kb:
            kb.add_pattern(
                cwe="CWE-5555",
                title="Context",
                description="Test context manager",
                patterns=["ctx"],
                persist=True,
            )
        self.assertIsNone(kb._conn)

    def test_search_with_db(self):
        with VulnerabilityKB(self.db_path) as kb:
            results = kb.search("pickle.load(data)", top_k=3)
            self.assertGreater(len(results), 0)
            cwcs = [r["cwe"] for r in results]
            self.assertIn("CWE-502", cwcs)


class VulnerabilityKBFAISSTests(unittest.TestCase):
    """Tests for FAISS backend (skipped if faiss not installed)."""

    @unittest.skipUnless(_HAS_FAISS, "FAISS not installed")
    def test_init_with_faiss(self):
        kb = VulnerabilityKB(use_faiss=True)
        self.assertTrue(kb._use_faiss)
        self.assertIsNotNone(kb._faiss_model)

    @unittest.skipUnless(_HAS_FAISS, "FAISS not installed")
    def test_search_with_faiss(self):
        kb = VulnerabilityKB(use_faiss=True)
        results = kb.search("pickle.load(data)", top_k=3)
        self.assertGreater(len(results), 0)
        cwcs = [r["cwe"] for r in results]
        self.assertIn("CWE-502", cwcs)
        self.assertEqual(results[0].get("backend"), "faiss")

    @unittest.skipUnless(_HAS_FAISS, "FAISS not installed")
    def test_faiss_build_index(self):
        kb = VulnerabilityKB(use_faiss=True)
        kb._build_faiss_index()
        self.assertTrue(kb._built_faiss)
        self.assertIsNotNone(kb._faiss_index)

    def test_faiss_fallback(self):
        """When FAISS is not available, should fall back gracefully."""
        kb = VulnerabilityKB(use_faiss=False)
        results = kb.search("SQL injection", top_k=1)
        self.assertGreater(len(results), 0)
        # Should use either tfidf or keyword backend
        backend = results[0].get("backend")
        self.assertIn(backend, ["tfidf", "keyword"])


if __name__ == "__main__":
    unittest.main()
