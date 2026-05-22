"""Tests for shielding-related improvements in stages/report.py:
- Improvement ②: fix_now gate (empty/unverified call path → backlog)
- Improvement ⑤: severity downgrade for poc_confirmed=False + needs-more-info
- Improvement ⑥: composite dedup key for split-continuation snippets
"""

import unittest

from ai_vuln_harness.stages.report import bucket_finding, deduplicate, build_report


class BucketFindingGateTests(unittest.TestCase):
    """Improvement ②: fix_now requires non-empty, graph-verified call path."""

    def _f(self, **kw) -> dict:
        base = {
            "snippet_id": "sid1",
            "severity": "HIGH",
            "class": "buffer-overflow",
            "desc": "d",
            "status": "confirmed",
            "poc_confirmed": True,
            "call_path": ["main", "handler", "sink"],
            "call_path_verified": True,
        }
        base.update(kw)
        return base

    def test_empty_call_path_blocked(self):
        bucket, rationale = bucket_finding(self._f(call_path=[]), trace_required=False)
        self.assertEqual(bucket, "backlog")
        self.assertIn("empty call_path", rationale)

    def test_unverified_call_path_blocked(self):
        bucket, rationale = bucket_finding(
            self._f(call_path_verified=False, call_path_reason="unverified hops: a→c"),
            trace_required=False,
        )
        self.assertEqual(bucket, "backlog")
        self.assertIn("call_path failed graph verification", rationale)

    def test_verified_call_path_promotes(self):
        bucket, _ = bucket_finding(self._f(), trace_required=False)
        self.assertEqual(bucket, "fix_now")

    def test_missing_call_path_verified_defaults_to_true(self):
        # call_path_verified not set → defaults to True (fail-open)
        f = self._f()
        del f["call_path_verified"]
        bucket, _ = bucket_finding(f, trace_required=False)
        self.assertEqual(bucket, "fix_now")


class SeverityDowngradeTests(unittest.TestCase):
    """Improvement ⑤: unconfirmed needs-more-info findings are downgraded."""

    def test_high_needs_more_info_downgraded(self):
        f = {
            "snippet_id": "sid1",
            "severity": "HIGH",
            "class": "buffer-overflow",
            "desc": "d",
            "status": "needs-more-info",
            "poc_confirmed": False,
            "call_path": ["main"],
        }
        bucket, rationale = bucket_finding(f, trace_required=False)
        # Downgraded HIGH→MEDIUM; MEDIUM is not fix_now
        self.assertEqual(bucket, "backlog")
        self.assertIn("MEDIUM", rationale)

    def test_poc_confirmed_skips_downgrade(self):
        f = {
            "snippet_id": "sid1",
            "severity": "HIGH",
            "class": "buffer-overflow",
            "desc": "d",
            "status": "confirmed",
            "poc_confirmed": True,
            "call_path": ["main", "sink"],
            "call_path_verified": True,
        }
        bucket, _ = bucket_finding(f, trace_required=False)
        self.assertEqual(bucket, "fix_now")


class DeduplicateCompositeKeyTests(unittest.TestCase):
    """Improvement ⑥: composite dedup key collapses split-continuation snippets."""

    def test_same_file_class_start_line_collapsed(self):
        f1 = {
            "snippet_id": "sha256:aaa:bbb",
            "file": "src/inflate.c",
            "class": "buffer-overflow",
            "lines": [100, 150],
            "severity": "HIGH",
        }
        f2 = {
            "snippet_id": "sha256:ccc:ddd",  # different snippet ID (continuation)
            "file": "src/inflate.c",
            "class": "buffer-overflow",
            "lines": [100, 175],
            "severity": "MEDIUM",
        }
        result = deduplicate([f1, f2])
        self.assertEqual(len(result), 1)
        # Higher severity kept
        self.assertEqual(result[0]["severity"], "HIGH")

    def test_different_start_line_not_collapsed(self):
        f1 = {
            "snippet_id": "sha256:aaa:bbb",
            "file": "src/inflate.c",
            "class": "buffer-overflow",
            "lines": [100, 150],
            "severity": "HIGH",
        }
        f2 = {
            "snippet_id": "sha256:ccc:ddd",
            "file": "src/inflate.c",
            "class": "buffer-overflow",
            "lines": [200, 250],  # different start line
            "severity": "MEDIUM",
        }
        result = deduplicate([f1, f2])
        self.assertEqual(len(result), 2)

    def test_different_file_not_collapsed(self):
        f1 = {
            "snippet_id": "x",
            "file": "a.c",
            "class": "buffer-overflow",
            "lines": [10, 20],
            "severity": "HIGH",
        }
        f2 = {
            "snippet_id": "y",
            "file": "b.c",
            "class": "buffer-overflow",
            "lines": [10, 20],
            "severity": "HIGH",
        }
        result = deduplicate([f1, f2])
        self.assertEqual(len(result), 2)


class BuildReportTests(unittest.TestCase):
    def test_empty_findings_report(self):
        report = build_report("repo", [], [], [])
        self.assertEqual(report["summary"]["fix_now"], 0)
        self.assertIn("fix_now", report["bucket_definitions"])

    def test_bucket_definitions_updated(self):
        report = build_report("repo", [], [], [])
        self.assertIn("graph-verified", report["bucket_definitions"]["fix_now"])


if __name__ == "__main__":
    unittest.main()
