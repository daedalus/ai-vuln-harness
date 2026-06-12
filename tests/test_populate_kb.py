"""Tests for scripts/populate_kb.py — KB population script."""

import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.rag_kb import VulnerabilityKB


class PopulateKBTests(unittest.TestCase):
    def test_populate_with_defaults_only(self):
        """Test that KB works with default patterns without downloading."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_kb.db"
            with VulnerabilityKB(db_path) as kb:
                self.assertGreater(kb.size, 0)
                # Should have 15 default CWE patterns
                self.assertGreaterEqual(kb.size, 15)

    def test_populate_from_file(self):
        """Test loading patterns from a JSON file."""
        with tempfile.TemporaryDirectory() as tmp:
            # Create custom patterns file
            patterns = [
                {"cwe": "CWE-1001", "title": "Custom Pattern 1", "description": "Test 1", "patterns": ["test1"]},
                {"cwe": "CWE-1002", "title": "Custom Pattern 2", "description": "Test 2", "patterns": ["test2"]},
            ]
            patterns_path = Path(tmp) / "custom_patterns.json"
            patterns_path.write_text(json.dumps(patterns))

            db_path = Path(tmp) / "test_kb.db"
            with VulnerabilityKB(db_path) as kb:
                initial_size = kb.size
                loaded = kb.load_from_file(patterns_path, persist=True)
                self.assertEqual(loaded, 2)
                self.assertEqual(kb.size, initial_size + 2)

    def test_search_after_populate(self):
        """Test search works after populating KB."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "test_kb.db"
            with VulnerabilityKB(db_path) as kb:
                results = kb.search("pickle.load(data)", top_k=3)
                self.assertGreater(len(results), 0)
                cwcs = [r["cwe"] for r in results]
                self.assertIn("CWE-502", cwcs)


import json


if __name__ == "__main__":
    unittest.main()
