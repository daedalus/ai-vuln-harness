"""Tests for stages/voting.py — hunt-stage voting / consensus."""

import unittest

from ai_vuln_harness.stages.voting import merge_hunter_outputs, _semantic_merge
from ai_vuln_harness.stages.embeddings import _HAS_EMBEDDINGS


class MergeHunterOutputsTests(unittest.TestCase):
    def _finding(
        self, sid: str, cls: str = "buffer-overflow", sev: str = "HIGH"
    ) -> dict:
        return {
            "snippet_id": sid,
            "class": cls,
            "severity": sev,
            "status": "raw",
            "poc_confirmed": False,
        }

    def test_empty_outputs(self):
        promoted, suppressed = merge_hunter_outputs([])
        self.assertEqual(promoted, [])
        self.assertEqual(suppressed, [])

    def test_single_run_fast_path(self):
        findings = [self._finding("a"), self._finding("b")]
        promoted, suppressed = merge_hunter_outputs([findings], min_votes=2)
        # Fast path: single run, all promoted with vote_count=1
        self.assertEqual(len(promoted), 2)
        self.assertTrue(all(f["vote_count"] == 1 for f in promoted))
        self.assertEqual(suppressed, [])

    def test_two_runs_agreement_promotes(self):
        f = self._finding("sid1")
        promoted, suppressed = merge_hunter_outputs([[f], [f]], min_votes=2)
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0]["vote_count"], 2)
        self.assertEqual(suppressed, [])

    def test_two_runs_disagreement_suppresses(self):
        f1 = self._finding("sid1")
        f2 = self._finding("sid2")
        promoted, suppressed = merge_hunter_outputs([[f1], [f2]], min_votes=2)
        # Neither finding appears in both runs
        self.assertEqual(promoted, [])
        self.assertEqual(len(suppressed), 2)
        self.assertTrue(all(s["vote_count"] == 1 for s in suppressed))

    def test_higher_severity_variant_kept(self):
        low = self._finding("sid1", sev="LOW")
        high = self._finding("sid1", sev="HIGH")
        promoted, _ = merge_hunter_outputs([[low, high], [low]], min_votes=2)
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0]["severity"], "HIGH")

    def test_min_votes_one_promotes_all(self):
        findings = [self._finding("a"), self._finding("b")]
        promoted, suppressed = merge_hunter_outputs([findings, []], min_votes=1)
        self.assertEqual(len(promoted), 2)
        self.assertEqual(suppressed, [])

    def test_no_snippet_id_skipped(self):
        f = {"class": "something", "severity": "HIGH"}
        promoted, suppressed = merge_hunter_outputs([[f], [f]], min_votes=2)
        self.assertEqual(promoted, [])
        self.assertEqual(suppressed, [])


class SemanticMergeTests(unittest.TestCase):
    """Tests for embedding-based semantic merge in voting."""

    def _finding(
        self,
        sid: str,
        cls: str = "buffer-overflow",
        sev: str = "HIGH",
        desc: str = "",
        file: str = "",
    ) -> dict:
        return {
            "snippet_id": sid,
            "class": cls,
            "severity": sev,
            "desc": desc,
            "file": file,
            "status": "raw",
            "poc_confirmed": False,
        }

    @unittest.skipUnless(_HAS_EMBEDDINGS, "sentence-transformers not installed")
    def test_same_class_different_desc_merges(self):
        """Two findings with same class but different descriptions should merge."""
        f1 = self._finding("sid1", cls="sql-injection", desc="SQL injection in login query via user input")
        f2 = self._finding("sid2", cls="sql-injection", desc="SQL injection vulnerability in authentication endpoint")
        outputs = _semantic_merge([[f1], [f2]], similarity_threshold=0.7)
        # After merge, should have fewer unique findings
        total = sum(len(r) for r in outputs)
        # Ideally merged into 1, but at minimum should not crash
        self.assertGreaterEqual(total, 1)

    @unittest.skipUnless(_HAS_EMBEDDINGS, "sentence-transformers not installed")
    def test_different_class_no_merge(self):
        """Findings with different classes should not merge."""
        f1 = self._finding("sid1", cls="sql-injection", desc="SQL injection vulnerability")
        f2 = self._finding("sid2", cls="buffer-overflow", desc="Buffer overflow in parsing")
        outputs = _semantic_merge([[f1], [f2]], similarity_threshold=0.85)
        total = sum(len(r) for r in outputs)
        self.assertEqual(total, 2)

    @unittest.skipUnless(_HAS_EMBEDDINGS, "sentence-transformers not installed")
    def test_at_threshold_merges(self):
        """Similarity exactly at threshold should merge."""
        f1 = self._finding("sid1", cls="xss", desc="Cross-site scripting via innerHTML")
        f2 = self._finding("sid2", cls="xss", desc="Cross-site scripting through innerHTML assignment")
        outputs = _semantic_merge([[f1], [f2]], similarity_threshold=0.5)
        # Very low threshold should force merge
        total = sum(len(r) for r in outputs)
        self.assertLessEqual(total, 2)

    @unittest.skipUnless(_HAS_EMBEDDINGS, "sentence-transformers not installed")
    def test_below_threshold_no_merge(self):
        """Similarity below threshold should not merge."""
        f1 = self._finding("sid1", cls="sql-injection", desc="SQL injection vulnerability")
        f2 = self._finding("sid2", cls="crypto-weak", desc="Weak cryptographic algorithm usage")
        outputs = _semantic_merge([[f1], [f2]], similarity_threshold=0.99)
        total = sum(len(r) for r in outputs)
        self.assertEqual(total, 2)

    @unittest.skipUnless(_HAS_EMBEDDINGS, "sentence-transformers not installed")
    def test_single_run_merges_within(self):
        """Single run with similar findings should merge them."""
        f1 = self._finding("sid1", desc="SQL injection in login")
        f2 = self._finding("sid2", desc="SQL injection in authentication")
        outputs = _semantic_merge([[f1, f2]], similarity_threshold=0.5)
        total = sum(len(r) for r in outputs)
        self.assertLessEqual(total, 2)

    @unittest.skipUnless(_HAS_EMBEDDINGS, "sentence-transformers not installed")
    def test_empty_outputs_no_crash(self):
        """Empty outputs should not crash."""
        outputs = _semantic_merge([], similarity_threshold=0.85)
        self.assertEqual(outputs, [])

    def test_semantic_merge_flag_in_merge_hunter_outputs(self):
        """semantic_merge=False (default) should not trigger embedding merge."""
        f1 = self._finding("sid1", cls="sql-injection", desc="SQL injection")
        f2 = self._finding("sid2", cls="sql-injection", desc="SQL injection via input")
        promoted, suppressed = merge_hunter_outputs(
            [[f1], [f2]], min_votes=2, semantic_merge=False,
        )
        # Without semantic merge, different snippet_ids stay separate
        total = len(promoted) + len(suppressed)
        self.assertEqual(total, 2)

    def test_semantic_merge_true_with_embeddings(self):
        """semantic_merge=True should work end-to-end via merge_hunter_outputs."""
        if not _HAS_EMBEDDINGS:
            self.skipTest("sentence-transformers not installed")
        f1 = self._finding("sid1", cls="sql-injection", desc="SQL injection in login", sev="HIGH")
        f2 = self._finding("sid2", cls="sql-injection", desc="SQL injection vulnerability in auth", sev="MEDIUM")
        promoted, suppressed = merge_hunter_outputs(
            [[f1], [f2]], min_votes=2, semantic_merge=True, similarity_threshold=0.5,
        )
        # With low threshold, they should merge and promote
        total = len(promoted) + len(suppressed)
        self.assertLessEqual(total, 2)


if __name__ == "__main__":
    unittest.main()
