"""Tests for stages/engagement_graph.py — typed world model."""

import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.engagement_graph import EngagementGraph


class EngagementGraphTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tmp.name) / "test_graph.db"

    def tearDown(self):
        self.tmp.cleanup()

    def _graph(self):
        return EngagementGraph(self.db_path)

    # --- Surface ---

    def test_add_surface(self):
        with self._graph() as g:
            sid = g.add_surface("network", "src/server.py", "HTTP endpoint")
            self.assertIsNotNone(sid)
            self.assertTrue(sid.startswith("surf:"))

    def test_get_surface(self):
        with self._graph() as g:
            sid = g.add_surface("network", "src/server.py", "HTTP endpoint")
            s = g.get_surface(sid)
            self.assertIsNotNone(s)
            self.assertEqual(s["kind"], "network")
            self.assertEqual(s["path"], "src/server.py")

    def test_list_surface_by_kind(self):
        with self._graph() as g:
            g.add_surface("network", "a.py")
            g.add_surface("file", "b.py")
            g.add_surface("network", "c.py")
            nets = g.list_surface(kind="network")
            self.assertEqual(len(nets), 2)

    # --- Facts ---

    def test_add_fact(self):
        with self._graph() as g:
            fid = g.add_fact("Server uses Flask framework")
            self.assertTrue(fid.startswith("fact:"))

    def test_list_facts(self):
        with self._graph() as g:
            g.add_fact("fact 1")
            g.add_fact("fact 2")
            self.assertEqual(len(g.list_facts()), 2)

    # --- Hypotheses ---

    def test_add_hypothesis(self):
        with self._graph() as g:
            hid = g.add_hypothesis("src/db.py", "sql-injection", "User input flows to query")
            h = g.get_hypothesis(hid)
            self.assertIsNotNone(h)
            self.assertEqual(h["status"], "open")

    def test_update_hypothesis_status(self):
        with self._graph() as g:
            hid = g.add_hypothesis("a.py", "xss", "template injection")
            g.update_hypothesis_status(hid, "confirmed")
            h = g.get_hypothesis(hid)
            self.assertEqual(h["status"], "confirmed")

    def test_list_hypotheses_by_status(self):
        with self._graph() as g:
            h1 = g.add_hypothesis("a.py", "sqli", "claim 1")
            g.add_hypothesis("b.py", "xss", "claim 2")
            g.update_hypothesis_status(h1, "confirmed")
            open_h = g.list_hypotheses(status="open")
            confirmed_h = g.list_hypotheses(status="confirmed")
            self.assertEqual(len(open_h), 1)
            self.assertEqual(len(confirmed_h), 1)

    # --- Findings ---

    def test_add_finding(self):
        with self._graph() as g:
            fid = g.add_finding("SQL Injection in login", "HIGH", cwe="CWE-89", file="auth.py")
            f = g.get_finding(fid)
            self.assertIsNotNone(f)
            self.assertEqual(f["severity"], "HIGH")

    def test_list_findings_by_severity(self):
        with self._graph() as g:
            g.add_finding("f1", "HIGH")
            g.add_finding("f2", "LOW")
            g.add_finding("f3", "HIGH")
            highs = g.list_findings(severity="HIGH")
            self.assertEqual(len(highs), 2)

    # --- Dead Ends ---

    def test_add_dead_end(self):
        with self._graph() as g:
            did = g.add_dead_end("src/x.py", "Input not reachable from untrusted source")
            self.assertTrue(did.startswith("dead:"))
            self.assertEqual(len(g.list_dead_ends()), 1)

    # --- Chains ---

    def test_add_chain(self):
        with self._graph() as g:
            cid = g.add_chain("auth-bypass", ["f1", "f2", "f3"], is_critical=True)
            c = g.get_chain(cid)
            self.assertIsNotNone(c)
            self.assertEqual(c["links"], ["f1", "f2", "f3"])
            self.assertEqual(c["is_critical"], 1)

    def test_list_chains_critical_only(self):
        with self._graph() as g:
            g.add_chain("chain1", ["a"], is_critical=True)
            g.add_chain("chain2", ["b"], is_critical=False)
            critical = g.list_chains(critical_only=True)
            self.assertEqual(len(critical), 1)

    # --- Summary ---

    def test_summary(self):
        with self._graph() as g:
            g.add_surface("network", "a.py")
            g.add_fact("fact 1")
            g.add_hypothesis("a.py", "sqli", "claim")
            g.add_finding("f1", "HIGH")
            g.add_dead_end("b.py", "not reachable")
            g.add_chain("chain1", ["f1"], is_critical=True)
            s = g.summary()
            self.assertEqual(s["surface_count"], 1)
            self.assertEqual(s["findings_count"], 1)
            self.assertEqual(s["chains_critical"], 1)

    # --- Export ---

    def test_export_json(self):
        with self._graph() as g:
            g.add_surface("network", "a.py")
            g.add_finding("f1", "HIGH")
            data = g.export_json()
            self.assertIn("surface", data)
            self.assertIn("findings", data)
            self.assertIn("summary", data)
            self.assertEqual(len(data["surface"]), 1)

    # --- Context Manager ---

    def test_context_manager(self):
        with EngagementGraph(self.db_path) as g:
            g.add_fact("test")
        # Connection closed after exiting
        self.assertIsNotNone(g.conn)


if __name__ == "__main__":
    unittest.main()
