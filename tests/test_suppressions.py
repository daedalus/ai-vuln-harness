"""Tests for stages/suppressions.py — false-positive suppression registry."""

import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.suppressions import SuppressionRegistry


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
        # Re-load from disk
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


if __name__ == "__main__":
    unittest.main()
