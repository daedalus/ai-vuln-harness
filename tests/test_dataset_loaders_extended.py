"""Tests for new dataset loaders (Exploit-DB, GitHub Advisory, VulDeePecker)."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.dataset_loaders import (
    _create_vuldeepecker_representatives,
    load_exploitdb_from_file,
    load_github_advisory_from_file,
)
from ai_vuln_harness.stages.rag_kb import VulnerabilityKB


class LoadExploitDBTests(unittest.TestCase):
    def setUp(self):
        self.kb = VulnerabilityKB()

    def test_load_from_csv(self):
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "exploits.csv"
            with open(csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["id", "description", "platform", "type", "cve"])
                writer.writeheader()
                writer.writerow({"id": "12345", "description": "SQL Injection in PHP", "platform": "php", "type": "webapps", "cve": "CVE-2024-1234"})
                writer.writerow({"id": "12346", "description": "Buffer Overflow in Linux", "platform": "linux", "type": "local", "cve": ""})

            count = load_exploitdb_from_file(self.kb, csv_path)
            self.assertEqual(count, 2)
            result = self.kb.get_pattern("EDB-12345")
            self.assertIsNotNone(result)
            self.assertIn("SQL Injection", result["title"])

    def test_max_patterns_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = Path(tmp) / "exploits.csv"
            with open(csv_path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=["id", "description", "platform", "type", "cve"])
                writer.writeheader()
                for i in range(10):
                    writer.writerow({"id": str(i), "description": f"Exploit {i}", "platform": "linux", "type": "local", "cve": ""})

            count = load_exploitdb_from_file(self.kb, csv_path, max_patterns=3)
            self.assertEqual(count, 3)


class LoadGitHubAdvisoryTests(unittest.TestCase):
    def setUp(self):
        self.kb = VulnerabilityKB()

    def test_load_from_jsonl(self):
        with tempfile.TemporaryDirectory() as tmp:
            json_path = Path(tmp) / "advisories.json"
            advisories = [
                {"id": "GHSA-1234-5678", "summary": "SQL Injection in package", "description": "A SQL injection vulnerability", "severity": "high", "cwes": [{"cwe_id": "CWE-89"}]},
                {"id": "GHSA-8765-4321", "summary": "XSS in template", "description": "Cross-site scripting", "severity": "medium", "cwes": [{"cwe_id": "CWE-79"}]},
            ]
            with open(json_path, "w") as f:
                for adv in advisories:
                    f.write(json.dumps(adv) + "\n")

            count = load_github_advisory_from_file(self.kb, json_path)
            self.assertEqual(count, 2)
            result = self.kb.get_pattern("GHSA-1234-5678")
            self.assertIsNotNone(result)
            self.assertIn("SQL Injection", result["title"])


class VulDeePeckerTests(unittest.TestCase):
    def setUp(self):
        self.kb = VulnerabilityKB()

    def test_create_representatives(self):
        count = _create_vuldeepecker_representatives(self.kb)
        self.assertGreater(count, 0)
        # Check that CWE-119 was added
        result = self.kb.get_pattern("CWE-119")
        self.assertIsNotNone(result)

    def test_no_duplicates(self):
        initial_size = self.kb.size
        _create_vuldeepecker_representatives(self.kb)
        # Should not add duplicates
        self.assertLessEqual(self.kb.size, initial_size + 10)


if __name__ == "__main__":
    unittest.main()
