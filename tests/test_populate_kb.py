"""Tests for scripts/populate_kb.py — KB population script."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.rag_kb import VulnerabilityKB, _HAS_FAISS


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


class PopulateKBCLITests(unittest.TestCase):
    """Tests for the populate_kb CLI entry point."""

    def _run_cli(self, *args: str, timeout: int = 120) -> subprocess.CompletedProcess:
        cmd = [sys.executable, "-m", "ai_vuln_harness.scripts.populate_kb", *args]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)

    def test_help_flag(self):
        """--help should exit 0 and show usage."""
        result = self._run_cli("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--faiss", result.stdout)
        self.assertIn("--reset", result.stdout)
        self.assertIn("--max-per-dataset", result.stdout)

    def test_default_run_creates_db(self):
        """Running without --faiss should create a .db file but no .faiss."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vuln_kb.db"
            result = self._run_cli("--output", str(db_path), "--datasets", "mitre_cwe", "--max-per-dataset", "5")
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue(db_path.exists(), "DB file not created")
            faiss_path = db_path.with_suffix(".faiss")
            self.assertFalse(faiss_path.exists(), "FAISS file should not exist without --faiss")

    @unittest.skipUnless(_HAS_FAISS, "FAISS not installed")
    def test_faiss_flag_creates_faiss_file(self):
        """--faiss should create both .db and .faiss files."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vuln_kb.db"
            faiss_path = db_path.with_suffix(".faiss")
            result = self._run_cli("--output", str(db_path), "--faiss", "--datasets", "mitre_cwe", "--max-per-dataset", "5")
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue(db_path.exists(), "DB file not created")
            self.assertTrue(faiss_path.exists(), "FAISS file not created with --faiss")
            self.assertGreater(faiss_path.stat().st_size, 0, "FAISS file is empty")

    @unittest.skipUnless(_HAS_FAISS, "FAISS not installed")
    def test_faiss_flag_with_reset(self):
        """--faiss --reset should rebuild from scratch."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vuln_kb.db"
            faiss_path = db_path.with_suffix(".faiss")
            # First run
            self._run_cli("--output", str(db_path), "--faiss", "--datasets", "mitre_cwe", "--max-per-dataset", "5")
            self.assertTrue(faiss_path.exists())
            # Second run with reset
            result = self._run_cli("--output", str(db_path), "--faiss", "--reset", "--datasets", "mitre_cwe", "--max-per-dataset", "5")
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue(faiss_path.exists())
            self.assertGreater(faiss_path.stat().st_size, 0)

    def test_datasets_flag(self):
        """--datasets should filter which datasets are loaded."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vuln_kb.db"
            result = self._run_cli("--output", str(db_path), "--datasets", "mitre_cwe", "--max-per-dataset", "10")
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue(db_path.exists())

    def test_reset_flag(self):
        """--reset should drop and recreate the database."""
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "vuln_kb.db"
            # First run
            self._run_cli("--output", str(db_path), "--datasets", "mitre_cwe", "--max-per-dataset", "5")
            self.assertTrue(db_path.exists())
            # Second run with reset
            result = self._run_cli("--output", str(db_path), "--reset", "--datasets", "mitre_cwe", "--max-per-dataset", "5")
            self.assertEqual(result.returncode, 0, msg=result.stderr)
            self.assertTrue(db_path.exists())


if __name__ == "__main__":
    unittest.main()
