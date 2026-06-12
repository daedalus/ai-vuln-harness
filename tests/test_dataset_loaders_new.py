"""Tests for new dataset loaders (OSV.dev, Snyk, D2A, Juliet)."""

import json
import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.dataset_loaders import (
    _create_vuldeepecker_representatives,
    load_d2a_from_file,
    load_juliet_representatives,
    load_osv_from_file,
    load_snyk_from_file,
)
from ai_vuln_harness.stages.rag_kb import VulnerabilityKB


class LoadOSVTests(unittest.TestCase):
    def setUp(self):
        self.kb = VulnerabilityKB()

    def test_load_from_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "osv.json"
            osv_data = {
                "vulns": [
                    {"id": "OSV-2024-1", "summary": "SQL injection in package", "details": "A SQL injection vulnerability", "aliases": ["CVE-2024-1234"], "severity": [{"score": "8.5"}]},
                    {"id": "OSV-2024-2", "summary": "XSS in template", "details": "Cross-site scripting", "aliases": [], "severity": []},
                ]
            }
            json_path.write_text(json.dumps(osv_data))

            count = load_osv_from_file(self.kb, json_path)
            self.assertEqual(count, 2)
            result = self.kb.get_pattern("OSV-2024-1")
            self.assertIsNotNone(result)
            self.assertIn("SQL injection", result["title"])


class LoadSnykTests(unittest.TestCase):
    def setUp(self):
        self.kb = VulnerabilityKB()

    def test_load_from_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "snyk.json"
            snyk_data = {
                "vulns": [
                    {"id": "SNYK-1234", "title": "SQL Injection", "description": "SQL injection in package", "cvssScore": 8.5, "CWE": [{"id": "CWE-89"}]},
                    {"id": "SNYK-5678", "title": "XSS", "description": "Cross-site scripting", "cvssScore": 6.5, "CWE": ["CWE-79"]},
                ]
            }
            json_path.write_text(json.dumps(snyk_data))

            count = load_snyk_from_file(self.kb, json_path)
            self.assertEqual(count, 2)
            result = self.kb.get_pattern("SNYK-1234")
            self.assertIsNotNone(result)
            self.assertIn("SQL Injection", result["title"])


class LoadD2ATests(unittest.TestCase):
    def setUp(self):
        self.kb = VulnerabilityKB()

    def test_load_from_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "d2a.json"
            d2a_data = [
                {"commit_message": "Fix SQL injection in query builder", "cve_id": "CVE-2024-1234"},
                {"commit_message": "Fix XSS in template rendering", "cve_id": ""},
            ]
            json_path.write_text(json.dumps(d2a_data))

            count = load_d2a_from_file(self.kb, json_path)
            self.assertEqual(count, 2)
            result = self.kb.get_pattern("CVE-2024-1234")
            self.assertIsNotNone(result)
            self.assertIn("CWE-89", result["patterns"])


class LoadJulietTests(unittest.TestCase):
    def setUp(self):
        self.kb = VulnerabilityKB()

    def test_representatives(self):
        count = load_juliet_representatives(self.kb)
        self.assertGreater(count, 0)
        result = self.kb.get_pattern("CWE-119")
        self.assertIsNotNone(result)
        self.assertIn("Juliet", result["title"])


class LoadAllDatasetsTests(unittest.TestCase):
    def test_load_representatives_only(self):
        kb = VulnerabilityKB()
        initial_size = kb.size

        # Load VulDeePecker + Juliet representatives (no downloads)
        _create_vuldeepecker_representatives(kb)
        load_juliet_representatives(kb)

        self.assertGreater(kb.size, initial_size)
        # Check some patterns exist
        self.assertIsNotNone(kb.get_pattern("CWE-119"))
        self.assertIsNotNone(kb.get_pattern("CWE-120"))


if __name__ == "__main__":
    unittest.main()
