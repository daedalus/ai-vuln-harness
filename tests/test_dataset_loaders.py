"""Tests for stages/dataset_loaders.py — CWE/CVE dataset loaders."""

import json
import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.dataset_loaders import (
    load_cvefixes_from_file,
    load_mitre_cwe_from_file,
    load_nvd_cve_from_file,
)
from ai_vuln_harness.stages.rag_kb import VulnerabilityKB


class LoadMitreCweTests(unittest.TestCase):
    def setUp(self):
        self.kb = VulnerabilityKB()

    def test_load_from_xml_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Create a minimal CWE XML with custom IDs
            xml_content = """<?xml version="1.0" encoding="UTF-8"?>
            <Weaknesses xmlns="http://cwe.mitre.org/data/definitions">
                <Weakness ID="79001" Name="Custom XSS Variant">
                    <Description>A custom XSS variant.</Description>
                </Weakness>
                <Weakness ID="89001" Name="Custom SQLi Variant">
                    <Description>A custom SQL injection variant.</Description>
                </Weakness>
            </Weaknesses>"""
            xml_path = Path(tmp) / "cwe.xml"
            xml_path.write_text(xml_content)

            count = load_mitre_cwe_from_file(self.kb, xml_path)
            self.assertEqual(count, 2)
            result = self.kb.get_pattern("CWE-79001")
            self.assertIsNotNone(result)
            self.assertEqual(result["title"], "Custom XSS Variant")

    def test_max_patterns_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            xml_content = """<?xml version="1.0" encoding="UTF-8"?>
            <Weaknesses xmlns="http://cwe.mitre.org/data/definitions">
                <Weakness ID="79" Name="XSS"><Description>XSS</Description></Weakness>
                <Weakness ID="89" Name="SQLi"><Description>SQLi</Description></Weakness>
                <Weakness ID="22" Name="Path Traversal"><Description>PT</Description></Weakness>
            </Weaknesses>"""
            xml_path = Path(tmp) / "cwe.xml"
            xml_path.write_text(xml_content)

            count = load_mitre_cwe_from_file(self.kb, xml_path, max_patterns=2)
            self.assertEqual(count, 2)


class LoadNvdCveTests(unittest.TestCase):
    def setUp(self):
        self.kb = VulnerabilityKB()

    def test_load_from_json_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Create a minimal NVD JSON
            nvd_data = {
                "CVE_Items": [
                    {
                        "cve": {
                            "CVE_data_meta": {"ID": "CVE-2024-1234"},
                            "description": {
                                "description_data": [
                                    {"lang": "en", "value": "SQL injection in login form"}
                                ]
                            },
                            "weakness": {
                                "description_data": [
                                    {"value": "CWE-89"}
                                ]
                            },
                        }
                    }
                ]
            }
            json_path = Path(tmp) / "nvd.json"
            json_path.write_text(json.dumps(nvd_data))

            count = load_nvd_cve_from_file(self.kb, json_path)
            self.assertEqual(count, 1)
            result = self.kb.get_pattern("CVE-2024-1234")
            self.assertIsNotNone(result)
            self.assertIn("SQL injection", result["description"])


class LoadCvefixesTests(unittest.TestCase):
    def setUp(self):
        self.kb = VulnerabilityKB()

    def test_load_from_json_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            # Create a minimal CVEFixes JSON
            cvefixes_data = [
                {
                    "cve_id": "CVE-2024-5678",
                    "message": "Fix SQL injection in query builder",
                    "description": "The query builder was vulnerable to SQL injection.",
                }
            ]
            json_path = Path(tmp) / "cvefixes.json"
            json_path.write_text(json.dumps(cvefixes_data))

            count = load_cvefixes_from_file(self.kb, json_path)
            self.assertEqual(count, 1)
            result = self.kb.get_pattern("CVE-2024-5678")
            self.assertIsNotNone(result)
            self.assertIn("CWE-89", result["patterns"])


class LoadMultipleDatasetsTests(unittest.TestCase):
    def test_load_multiple_files(self):
        kb = VulnerabilityKB()
        initial_size = kb.size

        with tempfile.TemporaryDirectory() as tmp:
            # Load CWE
            xml_content = """<?xml version="1.0" encoding="UTF-8"?>
            <Weaknesses xmlns="http://cwe.mitre.org/data/definitions">
                <Weakness ID="999" Name="Custom Vuln"><Description>Test</Description></Weakness>
            </Weaknesses>"""
            xml_path = Path(tmp) / "cwe.xml"
            xml_path.write_text(xml_content)
            load_mitre_cwe_from_file(kb, xml_path)

            # Load CVE
            nvd_data = {"CVE_Items": [{"cve": {"CVE_data_meta": {"ID": "CVE-9999"}, "description": {"description_data": [{"lang": "en", "value": "Test CVE"}]}, "weakness": {"description_data": []}}}]}
            json_path = Path(tmp) / "nvd.json"
            json_path.write_text(json.dumps(nvd_data))
            load_nvd_cve_from_file(kb, json_path)

        self.assertGreater(kb.size, initial_size)
        self.assertIsNotNone(kb.get_pattern("CWE-999"))
        self.assertIsNotNone(kb.get_pattern("CVE-9999"))


if __name__ == "__main__":
    unittest.main()
