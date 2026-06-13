"""Tests for stages/suppressions.py — false-positive suppression registry."""

import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.suppressions import SuppressionRegistry, _HAS_NUMPY


class SuppressionRegistryTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.reg_path = Path(self._tmp.name) / "suppressions.json"

    def tearDown(self):
        self._tmp.cleanup()

    def _finding(self, sid: str = "sid1", cls: str = "buffer-overflow") -> dict:
        return {
            "snippet_id": sid,
            "class": cls,
            "severity": "HIGH",
            "status": "rejected",
        }

    def test_empty_registry_keeps_all(self):
        reg = SuppressionRegistry(self.reg_path)
        findings = [self._finding("a"), self._finding("b")]
        kept, suppressed = reg.filter(findings)
        self.assertEqual(len(kept), 2)
        self.assertEqual(suppressed, [])

    def test_add_and_filter(self):
        reg = SuppressionRegistry(self.reg_path)
        f = self._finding("sid1")
        reg.add(f, reason="confirmed false positive in test run")
        kept, suppressed = reg.filter([f, self._finding("sid2")])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["snippet_id"], "sid2")
        self.assertEqual(len(suppressed), 1)
        self.assertTrue(suppressed[0]["suppressed_by_registry"])

    def test_is_suppressed(self):
        reg = SuppressionRegistry(self.reg_path)
        f = self._finding("sid1")
        self.assertFalse(reg.is_suppressed(f))
        reg.add(f)
        self.assertTrue(reg.is_suppressed(f))

    def test_contains_operator(self):
        reg = SuppressionRegistry(self.reg_path)
        f = self._finding("sid1")
        reg.add(f)
        self.assertIn(f, reg)

    def test_persistence(self):
        reg1 = SuppressionRegistry(self.reg_path)
        reg1.add(self._finding("sid1"))
        reg2 = SuppressionRegistry(self.reg_path)
        self.assertTrue(reg2.is_suppressed(self._finding("sid1")))

    def test_suppress_many(self):
        reg = SuppressionRegistry(self.reg_path)
        findings = [self._finding("a"), self._finding("b"), self._finding("c")]
        reg.suppress_many(findings, reason="batch FP")
        self.assertEqual(len(reg), 3)

    def test_class_differentiates_key(self):
        reg = SuppressionRegistry(self.reg_path)
        f1 = {"snippet_id": "sid1", "class": "buffer-overflow"}
        f2 = {"snippet_id": "sid1", "class": "format-string"}
        reg.add(f1)
        self.assertTrue(reg.is_suppressed(f1))
        self.assertFalse(reg.is_suppressed(f2))

    def test_len(self):
        reg = SuppressionRegistry(self.reg_path)
        self.assertEqual(len(reg), 0)
        reg.add(self._finding())
        self.assertEqual(len(reg), 1)


class SuppressionRegistryFTS5Tests(unittest.TestCase):
    """Tests for FTS5-backed fuzzy suppression."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.reg_path = Path(self._tmp.name) / "suppressions.json"

    def tearDown(self):
        self._tmp.cleanup()

    def _finding(self, sid: str = "sid1", cls: str = "buffer-overflow") -> dict:
        return {
            "snippet_id": sid,
            "class": cls,
            "severity": "HIGH",
            "status": "rejected",
        }

    def test_exact_match_still_works(self):
        """Exact (snippet_id, class) match still works in FTS5 mode."""
        with SuppressionRegistry(self.reg_path, use_fts5=True) as reg:
            f = self._finding("sid1")
            reg.add(f, reason="known FP")
            self.assertTrue(reg.is_suppressed(f))
            self.assertTrue(reg.is_suppressed_fuzzy(f))

    def test_fts5_text_match_by_class(self):
        """FTS5 should match by reason text."""
        with SuppressionRegistry(self.reg_path, use_fts5=True) as reg:
            reg.add(self._finding("sid1", cls="sql-injection"), reason="known FP sql injection")
            results = reg.search("sql injection")
            self.assertGreater(len(results), 0)
            self.assertEqual(results[0]["class"], "sql-injection")

    def test_fts5_text_match_by_description(self):
        """FTS5 should match by description text."""
        with SuppressionRegistry(self.reg_path, use_fts5=True) as reg:
            reg.add_fuzzy(
                self._finding("sid1", cls="xss"),
                reason="known FP",
                description="Cross-site scripting via innerHTML",
            )
            results = reg.search("innerHTML")
            self.assertGreater(len(results), 0)

    def test_is_suppressed_fuzzy_by_class(self):
        """is_suppressed_fuzzy should match by class."""
        with SuppressionRegistry(self.reg_path, use_fts5=True) as reg:
            reg.add(self._finding("sid1", cls="sql-injection"))
            f2 = self._finding("sid2", cls="sql-injection")
            self.assertTrue(reg.is_suppressed_fuzzy(f2))

    def test_is_suppressed_fuzzy_no_match(self):
        """is_suppressed_fuzzy should not match unrelated findings."""
        with SuppressionRegistry(self.reg_path, use_fts5=True) as reg:
            reg.add(self._finding("sid1", cls="sql-injection"))
            f2 = self._finding("sid2", cls="buffer-overflow")
            self.assertFalse(reg.is_suppressed_fuzzy(f2))

    def test_migration_from_json(self):
        """FTS5 mode should auto-migrate existing JSON entries."""
        # Create JSON-only registry
        reg1 = SuppressionRegistry(self.reg_path)
        reg1.add(self._finding("sid1", cls="sql-injection"), reason="known FP")
        reg1.add(self._finding("sid2", cls="xss"), reason="another FP")

        # Re-open with FTS5 — should migrate
        with SuppressionRegistry(self.reg_path, use_fts5=True) as reg2:
            self.assertTrue(reg2.is_suppressed_fuzzy(self._finding("sid1", cls="sql-injection")))
            self.assertTrue(reg2.is_suppressed_fuzzy(self._finding("sid2", cls="xss")))

    def test_multiple_suppressions_same_area(self):
        """Multiple suppressions for same code area should coexist."""
        with SuppressionRegistry(self.reg_path, use_fts5=True) as reg:
            reg.add(self._finding("sid1", cls="sql-injection"))
            reg.add(self._finding("sid2", cls="sql-injection"))
            self.assertEqual(len(reg), 2)
            self.assertTrue(reg.is_suppressed_fuzzy(self._finding("sid1", cls="sql-injection")))
            self.assertTrue(reg.is_suppressed_fuzzy(self._finding("sid2", cls="sql-injection")))

    def test_empty_registry_no_crash(self):
        """Empty FTS5 registry should not crash."""
        with SuppressionRegistry(self.reg_path, use_fts5=True) as reg:
            self.assertEqual(len(reg), 0)
            results = reg.search("anything")
            self.assertEqual(results, [])
            self.assertFalse(reg.is_suppressed_fuzzy(self._finding()))

    def test_filter_uses_fuzzy_in_fts5_mode(self):
        """filter() should use fuzzy matching when use_fts5=True."""
        with SuppressionRegistry(self.reg_path, use_fts5=True) as reg:
            reg.add(self._finding("sid1", cls="sql-injection"))
            # Different snippet_id but same class — fuzzy match
            f2 = self._finding("sid2", cls="sql-injection")
            kept, suppressed = reg.filter([f2])
            self.assertEqual(len(kept), 0)
            self.assertEqual(len(suppressed), 1)

    @unittest.skipUnless(_HAS_NUMPY, "numpy not installed")
    def test_embedding_match(self):
        """Embedding similarity should suppress matching findings."""
        import numpy as np

        with SuppressionRegistry(self.reg_path, use_fts5=True) as reg:
            emb = np.random.randn(384).astype("float32")
            reg.add_fuzzy(
                self._finding("sid1", cls="custom-vuln"),
                description="Custom vulnerability",
                embedding=emb,
            )
            # Same embedding should match
            f2 = self._finding("sid2", cls="custom-vuln")
            f2["_embedding"] = emb
            self.assertTrue(reg.is_suppressed_fuzzy(f2, threshold=0.5))


if __name__ == "__main__":
    unittest.main()
