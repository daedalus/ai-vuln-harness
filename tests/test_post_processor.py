"""Tests for stages/post_processor.py — aggregate, dashboard, KPIs."""

import json
import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.post_processor import (
    aggregate_findings,
    calculate_kpis,
    generate_dashboard,
    run_post_processor,
    write_findings_jsonl,
    write_summary_json,
)


class AggregateFindingsTests(unittest.TestCase):
    def test_empty_findings(self):
        result = aggregate_findings([])
        self.assertEqual(result["total"], 0)
        self.assertEqual(result["by_severity"], {})

    def test_aggregate_by_severity(self):
        findings = [
            {"severity": "HIGH", "class": "sqli", "file": "a.py"},
            {"severity": "HIGH", "class": "xss", "file": "b.py"},
            {"severity": "LOW", "class": "sqli", "file": "a.py"},
        ]
        result = aggregate_findings(findings)
        self.assertEqual(result["by_severity"]["HIGH"], 2)
        self.assertEqual(result["by_severity"]["LOW"], 1)
        self.assertEqual(result["total"], 3)

    def test_aggregate_by_class(self):
        findings = [
            {"severity": "HIGH", "class": "sqli", "file": "a.py"},
            {"severity": "HIGH", "class": "sqli", "file": "b.py"},
            {"severity": "LOW", "class": "xss", "file": "c.py"},
        ]
        result = aggregate_findings(findings)
        self.assertEqual(result["by_class"]["sqli"], 2)
        self.assertEqual(result["by_class"]["xss"], 1)

    def test_aggregate_by_file(self):
        findings = [
            {"severity": "HIGH", "class": "sqli", "file": "a.py"},
            {"severity": "HIGH", "class": "xss", "file": "a.py"},
            {"severity": "LOW", "class": "sqli", "file": "b.py"},
        ]
        result = aggregate_findings(findings)
        self.assertEqual(result["by_file"]["a.py"], 2)
        self.assertEqual(result["by_file"]["b.py"], 1)


class GenerateDashboardTests(unittest.TestCase):
    def test_dashboard_structure(self):
        findings = [
            {"severity": "CRITICAL", "class": "rce", "file": "a.py", "poc_confirmed": True},
            {"severity": "HIGH", "class": "sqli", "file": "b.py", "poc_confirmed": False},
        ]
        chains = [{"name": "chain1", "severity": "CRITICAL"}]
        dashboard = generate_dashboard(findings, chains)
        self.assertEqual(dashboard["total_findings"], 2)
        self.assertEqual(dashboard["critical_count"], 1)
        self.assertEqual(dashboard["high_count"], 1)
        self.assertEqual(dashboard["confirmed_count"], 1)
        self.assertEqual(dashboard["chains_critical"], 1)
        self.assertIn("timestamp", dashboard)

    def test_dashboard_empty(self):
        dashboard = generate_dashboard([], [])
        self.assertEqual(dashboard["total_findings"], 0)
        self.assertEqual(dashboard["chains_total"], 0)


class WriteFindingsJsonlTests(unittest.TestCase):
    def test_write_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "findings.jsonl"
            findings = [{"severity": "HIGH", "class": "sqli"}]
            count = write_findings_jsonl(findings, path)
            self.assertEqual(count, 1)
            self.assertTrue(path.exists())
            lines = path.read_text().strip().split("\n")
            self.assertEqual(len(lines), 1)
            data = json.loads(lines[0])
            self.assertEqual(data["severity"], "HIGH")


class CalculateKpisTests(unittest.TestCase):
    def test_kpis_structure(self):
        findings = [
            {"severity": "HIGH", "class": "sqli", "poc_confirmed": True},
            {"severity": "LOW", "class": "xss", "poc_confirmed": False},
        ]
        report = {"summary": {"fix_now": 1, "backlog": 1, "false_positive": 0}}
        kpis = calculate_kpis(findings, report, elapsed_seconds=10.0, cost_usd=0.05)
        self.assertEqual(kpis["total_findings"], 2)
        self.assertEqual(kpis["confirmed_count"], 1)
        self.assertEqual(kpis["confirmation_rate"], 0.5)
        self.assertEqual(kpis["elapsed_seconds"], 10.0)
        self.assertEqual(kpis["cost_usd"], 0.05)
        self.assertEqual(kpis["cost_per_finding"], 0.025)

    def test_kpis_empty(self):
        kpis = calculate_kpis([], {})
        self.assertEqual(kpis["total_findings"], 0)
        self.assertEqual(kpis["confirmation_rate"], 0.0)
        self.assertEqual(kpis["cost_per_finding"], 0.0)


class RunPostProcessorTests(unittest.TestCase):
    def test_run_post_processor(self):
        with tempfile.TemporaryDirectory() as tmp:
            output_dir = Path(tmp)
            findings = [
                {"severity": "HIGH", "class": "sqli", "file": "a.py", "poc_confirmed": True},
            ]
            chains = [{"name": "chain1", "severity": "HIGH", "feasible": True}]
            report = {"summary": {"fix_now": 1, "backlog": 0, "false_positive": 0}}

            result = run_post_processor(findings, chains, report, output_dir)

            self.assertIn("dashboard", result)
            self.assertIn("kpis", result)
            self.assertTrue((output_dir / "findings.jsonl").exists())
            self.assertTrue((output_dir / "summary.json").exists())

    def test_write_summary_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "summary.json"
            dashboard = {"total_findings": 5}
            kpis = {"confirmation_rate": 0.8}
            write_summary_json(dashboard, kpis, path)
            self.assertTrue(path.exists())
            data = json.loads(path.read_text())
            self.assertEqual(data["dashboard"]["total_findings"], 5)
            self.assertIn("generated_at", data)


if __name__ == "__main__":
    unittest.main()
