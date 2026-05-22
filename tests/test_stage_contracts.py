import unittest

from ai_vuln_harness.stages.coordinator import build_context_packs
from ai_vuln_harness.stages.contracts import standardize_finding, validate_subset_schema


class StageContractTests(unittest.TestCase):
    def test_recon_required(self):
        with self.assertRaises(ValueError):
            build_context_packs([], recon_tasks=None, allow_full_db_fallback=False)

    def test_standardized_finding_defaults(self):
        f = standardize_finding(
            {"snippet_id": "x", "severity": "LOW", "class": "info", "desc": "d"}
        )
        self.assertEqual(f["status"], "raw")
        self.assertFalse(f["poc_confirmed"])
        self.assertIn("bucket_rationale", f)

    def test_subset_schema(self):
        schema = {
            "type": "object",
            "required": ["a", "b"],
            "properties": {"a": {"type": "string"}, "b": {"type": "boolean"}},
        }
        self.assertEqual(validate_subset_schema({"a": "x", "b": True}, schema), [])
        self.assertNotEqual(validate_subset_schema({"a": "x"}, schema), [])


if __name__ == "__main__":
    unittest.main()
