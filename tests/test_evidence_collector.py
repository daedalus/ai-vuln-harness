"""Tests for stages/evidence_collector.py — populate Engagement Graph."""

import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.engagement_graph import EngagementGraph
from ai_vuln_harness.stages.evidence_collector import (
    collect_chains_from_exploit_chains,
    collect_facts_from_findings,
    collect_hypotheses_from_findings,
    collect_surface_from_snippets,
    run_evidence_collector,
)


class EvidenceCollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test_graph.db"
        self.graph = EngagementGraph(self.db_path)

    def tearDown(self):
        self.graph.close()
        self.tmp.cleanup()

    # --- collect_surface_from_snippets ---

    def test_collect_surface_from_snippets(self):
        snippets = [
            {"file": "src/server.py", "kind": "function", "name": "handle_request"},
            {"file": "src/db.py", "kind": "function", "name": "query"},
        ]
        count = collect_surface_from_snippets(snippets, self.graph)
        self.assertEqual(count, 2)
        surface = self.graph.list_surface()
        self.assertEqual(len(surface), 2)
        self.assertEqual(surface[0]["kind"], "code")

    def test_classify_surface_kind(self):
        snippets = [
            {"file": "a.py", "kind": "function", "name": "f"},
            {"file": "b.py", "kind": "class", "name": "C"},
            {"file": "tests/test_c.py", "kind": "function", "name": "test_f"},
        ]
        collect_surface_from_snippets(snippets, self.graph)
        surface = self.graph.list_surface()
        kinds = [s["kind"] for s in surface]
        self.assertIn("code", kinds)
        self.assertIn("type", kinds)

    # --- collect_facts_from_findings ---

    def test_collect_facts_from_findings(self):
        findings = [
            {
                "desc": "SQL injection in login",
                "severity": "HIGH",
                "class": "sql-injection",
                "suspicious_points": [
                    {"function": "query", "file": "db.py", "rationale": "direct concat"}
                ],
                "call_path": ["main", "login", "query"],
            }
        ]
        count = collect_facts_from_findings(findings, self.graph)
        self.assertGreater(count, 0)
        facts = self.graph.list_facts()
        self.assertGreater(len(facts), 0)
        # Check that finding fact exists
        finding_facts = [f for f in facts if "SQL injection" in f["content"]]
        self.assertEqual(len(finding_facts), 1)

    def test_collect_facts_from_suspicious_points(self):
        findings = [
            {
                "desc": "XSS in template",
                "severity": "MEDIUM",
                "class": "xss",
                "suspicious_points": [
                    {"function": "render", "file": "tmpl.py", "rationale": "unescaped output"}
                ],
            }
        ]
        collect_facts_from_findings(findings, self.graph)
        facts = self.graph.list_facts()
        sp_facts = [f for f in facts if "Suspicious:" in f["content"]]
        self.assertEqual(len(sp_facts), 1)

    def test_collect_facts_from_call_path(self):
        findings = [
            {
                "desc": "Buffer overflow",
                "severity": "CRITICAL",
                "class": "buffer-overflow",
                "call_path": ["main", "parse", "copy"],
            }
        ]
        collect_facts_from_findings(findings, self.graph)
        facts = self.graph.list_facts()
        cp_facts = [f for f in facts if "Call path:" in f["content"]]
        self.assertEqual(len(cp_facts), 1)
        self.assertIn("main → parse → copy", cp_facts[0]["content"])

    # --- collect_hypotheses_from_findings ---

    def test_collect_hypotheses(self):
        findings = [
            {"desc": "SQL injection", "class": "sql-injection", "file": "db.py"},
            {"desc": "XSS", "class": "xss", "file": "web.py"},
        ]
        count = collect_hypotheses_from_findings(findings, self.graph)
        self.assertEqual(count, 2)
        hyps = self.graph.list_hypotheses()
        self.assertEqual(len(hyps), 2)
        self.assertEqual(hyps[0]["status"], "open")

    def test_confirmed_hypothesis(self):
        findings = [
            {"desc": "RCE", "class": "rce", "file": "exec.py", "poc_confirmed": True}
        ]
        collect_hypotheses_from_findings(findings, self.graph)
        hyps = self.graph.list_hypotheses(status="confirmed")
        self.assertEqual(len(hyps), 1)

    # --- collect_chains_from_exploit_chains ---

    def test_collect_chains(self):
        chains = [
            {"name": "auth-bypass", "links": ["f1", "f2"], "severity": "CRITICAL"},
            {"name": "xss-chain", "links": ["f3"], "severity": "LOW"},
        ]
        count = collect_chains_from_exploit_chains(chains, self.graph)
        self.assertEqual(count, 2)
        all_chains = self.graph.list_chains()
        self.assertEqual(len(all_chains), 2)
        critical = self.graph.list_chains(critical_only=True)
        self.assertEqual(len(critical), 1)
        self.assertEqual(critical[0]["name"], "auth-bypass")

    # --- run_evidence_collector ---

    def test_run_evidence_collector(self):
        snippets = [{"file": "a.py", "kind": "function", "name": "f"}]
        findings = [
            {
                "desc": "Buffer overflow",
                "severity": "HIGH",
                "class": "buffer-overflow",
                "file": "a.py",
                "suspicious_points": [{"function": "copy", "file": "a.py", "rationale": "unbounded"}],
                "call_path": ["main", "copy"],
            }
        ]
        chains = [{"name": "chain1", "links": ["f1"], "severity": "HIGH"}]

        result = run_evidence_collector(findings, snippets, chains, self.graph)

        self.assertEqual(result["surface_entries"], 1)
        self.assertGreater(result["facts_added"], 0)
        self.assertEqual(result["hypotheses_added"], 1)
        self.assertEqual(result["chains_added"], 1)
        self.assertIn("graph_summary", result)

    def test_empty_inputs(self):
        result = run_evidence_collector([], [], [], self.graph)
        self.assertEqual(result["surface_entries"], 0)
        self.assertEqual(result["facts_added"], 0)
        self.assertEqual(result["hypotheses_added"], 0)
        self.assertEqual(result["chains_added"], 0)


if __name__ == "__main__":
    unittest.main()
