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
    """Tests for FAISS backend with mocking (no heavy deps needed)."""

    @unittest.skipUnless(_HAS_SKLEARN, "sklearn not installed")
    def test_tfidf_index_build(self):
        """TF-IDF index should build successfully."""
        kb = VulnerabilityKB()
        kb._build_tfidf_index()
        self.assertTrue(kb._built_tfidf)
        self.assertIsNotNone(kb._vectorizer)
        self.assertIsNotNone(kb._tfidf_matrix)

    def test_faiss_search_fallback(self):
        """When FAISS is not available, should fall back to TF-IDF or keyword."""
        kb = VulnerabilityKB(use_faiss=False)
        results = kb.search("SQL injection", top_k=1)
        self.assertGreater(len(results), 0)
        backend = results[0].get("backend")
        self.assertIn(backend, ["tfidf", "keyword"])

    def test_faiss_persist_to_disk(self):
        """FAISS index file is created when building index."""
        if not _HAS_SKLEARN:
            self.skipTest("sklearn not installed")
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test.db"
            kb = VulnerabilityKB(db_path=db_path, use_faiss=False)
            # Force TF-IDF build
            kb._build_tfidf_index()
            self.assertTrue(kb._built_tfidf)

    def test_search_returns_backend_field(self):
        """Search results include backend field."""
        kb = VulnerabilityKB(use_faiss=False)
        results = kb.search("SQL injection", top_k=1)
        self.assertGreater(len(results), 0)
        self.assertIn("backend", results[0])
        self.assertIn(results[0]["backend"], ["tfidf", "keyword"])


class VulnerabilityKBCorpusTests(unittest.TestCase):
    """Tests for expanded CWE catalog and corpus loading."""

    def test_add_patterns_from_corpus(self):
        """Bulk load patterns from a corpus dict list."""
        kb = VulnerabilityKB()
        initial = kb.size
        entries = [
            {"cwe": "CWE-200", "title": "Information Exposure", "description": "Sensitive info exposed"},
            {"cwe": "CWE-352", "title": "CSRF", "description": "Cross-site request forgery"},
            {"cwe": "CWE-400", "title": "Resource Exhaustion", "description": "DoS via resource consumption"},
        ]
        count = kb.add_patterns_from_corpus(entries)
        self.assertEqual(count, 3)
        self.assertEqual(kb.size, initial + 3)

    def test_add_patterns_from_corpus_persist(self):
        """Bulk load with persist=True saves to DB."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_kb.db"
            with VulnerabilityKB(db_path) as kb:
                entries = [
                    {"cwe": "CWE-9999", "title": "Custom", "description": "Test"},
                ]
                kb.add_patterns_from_corpus(entries, persist=True)
            with VulnerabilityKB(db_path) as kb2:
                result = kb2.get_pattern("CWE-9999")
                self.assertIsNotNone(result)

    def test_add_patterns_from_corpus_skips_missing_cwe(self):
        """Entries without 'cwe' key should be skipped."""
        kb = VulnerabilityKB()
        initial = kb.size
        entries = [{"title": "No CWE"}, {"cwe": "CWE-1000", "title": "Valid"}]
        count = kb.add_patterns_from_corpus(entries)
        self.assertEqual(count, 1)
        self.assertEqual(kb.size, initial + 1)

    def test_expanded_catalog_search(self):
        """Search should work with expanded catalog."""
        kb = VulnerabilityKB()
        entries = [
            {"cwe": "CWE-200", "title": "Information Exposure", "description": "Sensitive data exposed to unauthorized actors"},
            {"cwe": "CWE-352", "title": "Cross-Site Request Forgery", "description": "Forged requests on behalf of authenticated users"},
        ]
        kb.add_patterns_from_corpus(entries)
        results = kb.search("information exposure", top_k=3)
        self.assertGreater(len(results), 0)

    def test_load_expanded_catalog_mock(self):
        """Mock loading 300 entries from a catalog file."""
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "cwe_catalog.json"
            entries = [
                {"cwe": f"CWE-{i}", "title": f"Test CWE {i}", "description": f"Description {i}", "patterns": [f"pattern{i}"]}
                for i in range(1, 301)
            ]
            path.write_text(json.dumps(entries))
            kb = VulnerabilityKB()
            loaded = kb.load_from_file(path)
            self.assertEqual(loaded, 300)
            self.assertGreaterEqual(kb.size, 300)


class DomainAssignmentTests(unittest.TestCase):
    """Tests for embedding-based domain assignment in coordinator."""

    def test_assign_domain_by_embedding_no_centroids(self):
        """Returns None when no centroids provided."""
        from ai_vuln_harness.stages.coordinator import assign_domain_by_embedding
        snippet = {"name": "gets(buf)", "content": "char buf[10]; gets(buf);"}
        result = assign_domain_by_embedding(snippet, domain_centroids=None)
        self.assertIsNone(result)

    @unittest.skipUnless(_HAS_FAISS, "FAISS not installed")
    def test_build_domain_centroids(self):
        """build_domain_centroids returns dict of domain -> embedding."""
        from ai_vuln_harness.stages.coordinator import build_domain_centroids
        centroids = build_domain_centroids()
        self.assertIsNotNone(centroids)
        self.assertIn("mem-safety", centroids)
        self.assertIn("crypto", centroids)
        self.assertEqual(len(centroids), 11)

    @unittest.skipUnless(_HAS_FAISS, "FAISS not installed")
    def test_assign_domain_mem_safety(self):
        """Buffer overflow snippet should route to mem-safety."""
        from ai_vuln_harness.stages.coordinator import assign_domain_by_embedding, build_domain_centroids
        centroids = build_domain_centroids()
        snippet = {"name": "strcpy", "content": "char buf[10]; strcpy(buf, user_input); buffer overflow vulnerability"}
        result = assign_domain_by_embedding(snippet, domain_centroids=centroids)
        self.assertEqual(result, "mem-safety")

    @unittest.skipUnless(_HAS_FAISS, "FAISS not installed")
    def test_assign_domain_crypto(self):
        """Weak crypto snippet should route to crypto."""
        from ai_vuln_harness.stages.coordinator import assign_domain_by_embedding, build_domain_centroids
        centroids = build_domain_centroids()
        snippet = {"name": "encrypt", "content": "Uses MD5 hash for password hashing, weak cryptographic algorithm"}
        result = assign_domain_by_embedding(snippet, domain_centroids=centroids)
        self.assertEqual(result, "crypto")

    def test_assign_domain_empty_snippet(self):
        """Empty snippet should return None."""
        from ai_vuln_harness.stages.coordinator import assign_domain_by_embedding
        result = assign_domain_by_embedding({}, domain_centroids={"test": None})
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
