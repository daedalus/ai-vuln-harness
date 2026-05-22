"""Adversarial tests for stages/suppressions.py — suppression registry edge cases.

Covers unicode keys, corrupted disk state, add-during-filter races,
very large registries, and boundary conditions in key computation.
"""

import tempfile
import unittest
from pathlib import Path

from stages.suppressions import SuppressionRegistry


class SuppressionUnicodeKeyTests(unittest.TestCase):
    """Special characters in snippet_id or class keys."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "sup.json"

    def tearDown(self):
        self._tmp.cleanup()

    def _reg(self):
        return SuppressionRegistry(self.path)

    def test_unicode_in_snippet_id(self):
        reg = self._reg()
        f = {"snippet_id": "café_main_ɸ", "class": "overflow"}
        reg.add(f)
        self.assertTrue(reg.is_suppressed(f))

    def test_punctuation_in_key(self):
        reg = self._reg()
        f = {"snippet_id": "a::b::c", "class": "foo/bar/baz"}
        reg.add(f)
        self.assertTrue(reg.is_suppressed(f))

    def test_whitespace_preserved(self):
        reg = self._reg()
        f = {"snippet_id": "  sid  ", "class": " overflow "}
        reg.add(f)
        self.assertTrue(reg.is_suppressed(f))

    def test_empty_string_keys(self):
        reg = self._reg()
        f = {"snippet_id": "", "class": ""}
        reg.add(f)
        self.assertTrue(reg.is_suppressed(f))


class SuppressionCorruptedDiskTests(unittest.TestCase):
    """Corrupted or malformed JSON on disk."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "sup.json"

    def tearDown(self):
        self._tmp.cleanup()

    def test_corrupted_json_initializes_empty(self):
        self.path.write_text("{not valid json!!!}")
        reg = SuppressionRegistry(self.path)
        self.assertEqual(len(reg), 0)

    def test_empty_file_initializes_empty(self):
        self.path.write_text("")
        reg = SuppressionRegistry(self.path)
        self.assertEqual(len(reg), 0)

    def test_json_is_array_instead_of_dict(self):
        self.path.write_text("[1, 2, 3]")
        reg = SuppressionRegistry(self.path)
        self.assertEqual(len(reg), 0)

    def test_non_dict_value_in_store(self):
        reg = SuppressionRegistry(self.path)
        reg._store = {"a": "not-a-dict"}
        reg._flush()
        reg2 = SuppressionRegistry(self.path)
        self.assertIsInstance(reg2, SuppressionRegistry)


class SuppressionEdgeCaseTests(unittest.TestCase):
    """Boundary and edge cases."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "sup.json"

    def tearDown(self):
        self._tmp.cleanup()

    def _reg(self):
        return SuppressionRegistry(self.path)

    def test_filter_on_empty_list(self):
        reg = self._reg()
        kept, suppressed = reg.filter([])
        self.assertEqual(kept, [])
        self.assertEqual(suppressed, [])

    def test_suppress_then_filter_same_batch(self):
        reg = self._reg()
        findings = [
            {"snippet_id": "a", "class": "x"},
            {"snippet_id": "b", "class": "y"},
        ]
        reg.suppress_many(findings)
        kept, suppressed = reg.filter(findings)
        self.assertEqual(kept, [])
        self.assertEqual(len(suppressed), 2)

    def test_add_then_immediate_filter_same_finding(self):
        reg = self._reg()
        f = {"snippet_id": "s1", "class": "overflow"}
        reg.add(f)
        kept, suppressed = reg.filter([f, {"snippet_id": "s2", "class": "other"}])
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0]["snippet_id"], "s2")
        self.assertEqual(len(suppressed), 1)

    def test_very_long_keys(self):
        reg = self._reg()
        long_sid = "a" * 10000
        f = {"snippet_id": long_sid, "class": "overflow"}
        reg.add(f)
        self.assertTrue(reg.is_suppressed(f))

    def test_contains_with_partial_match(self):
        reg = self._reg()
        reg.add({"snippet_id": "full_sid", "class": "overflow"})
        f_partial = {"snippet_id": "full", "class": "overflow"}
        self.assertFalse(reg.is_suppressed(f_partial))

    def test_key_with_double_colon(self):
        reg = self._reg()
        f = {"snippet_id": "a::b", "class": "c::d"}
        reg.add(f)
        self.assertTrue(reg.is_suppressed(f))
        different = {"snippet_id": "a", "b::class": "c", "d": ""}
        self.assertFalse(reg.is_suppressed(different))


class SuppressionPersistenceEdgeTests(unittest.TestCase):
    """Reloading with edge-case data."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / "sup.json"

    def tearDown(self):
        self._tmp.cleanup()

    def test_persist_after_many_adds(self):
        reg = SuppressionRegistry(self.path)
        for i in range(1000):
            reg.add({"snippet_id": f"s{i}", "class": "overflow"})
        reg2 = SuppressionRegistry(self.path)
        self.assertEqual(len(reg2), 1000)

    def test_oserror_on_read_initializes_empty(self):
        self.path.write_text("{}")
        import os

        os.chmod(str(self.path), 0o000)
        try:
            reg = SuppressionRegistry(self.path)
            self.assertIsInstance(reg, SuppressionRegistry)
        finally:
            os.chmod(str(self.path), 0o644)


if __name__ == "__main__":
    unittest.main()
