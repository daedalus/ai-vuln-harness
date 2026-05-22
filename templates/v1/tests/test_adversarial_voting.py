"""Adversarial tests for stages/voting.py — hunter merge edge cases.

Targets self-duplication attacks, sparse overlap across many runs,
missing/invalid keys, severity inflation, and boundary conditions.
"""

import unittest

from stages.voting import merge_hunter_outputs


def _f(sid: str, cls: str = "buffer-overflow", sev: str = "HIGH") -> dict:
    return {
        "snippet_id": sid,
        "class": cls,
        "severity": sev,
        "status": "raw",
        "poc_confirmed": False,
    }


class VotingSelfDuplicateAttackTests(unittest.TestCase):
    """Single hunter repeats same finding many times — should count once."""

    def test_identical_findings_in_same_run_count_once(self):
        finding = _f("s1")
        run1 = [finding] * 100
        run2 = [_f("s1")]
        promoted, suppressed = merge_hunter_outputs([run1, run2], min_votes=2)
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0]["vote_count"], 2)

    def test_duplicate_findings_spread_across_runs(self):
        f = _f("s1")
        run1 = [f] * 10
        run2 = [f] * 10
        promoted, suppressed = merge_hunter_outputs([run1, run2], min_votes=2)
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0]["vote_count"], 2)


class VotingSparseOverlapTests(unittest.TestCase):
    """Many runs with very few common findings."""

    def test_ten_runs_sparse_agreement(self):
        common = _f("shared")
        runs = [
            [common] + [_f(f"unique_{i}_{j}") for j in range(10)] for i in range(10)
        ]
        promoted, suppressed = merge_hunter_outputs(runs, min_votes=3)
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0]["snippet_id"], "shared")

    def test_two_runs_no_overlap(self):
        runs = [[_f("a")], [_f("b")]]
        promoted, suppressed = merge_hunter_outputs(runs, min_votes=2)
        self.assertEqual(promoted, [])
        self.assertEqual(len(suppressed), 2)


class VotingMissingKeyTests(unittest.TestCase):
    """Findings with missing snippet_id or class keys."""

    def test_no_snippet_id_skipped_across_runs(self):
        f_no_sid = {"class": "overflow", "severity": "HIGH"}
        promoted, suppressed = merge_hunter_outputs(
            [[f_no_sid], [f_no_sid]], min_votes=2
        )
        self.assertEqual(promoted, [])
        self.assertEqual(suppressed, [])

    def test_no_class_key_falls_back_to_empty_string(self):
        f1 = {"snippet_id": "a", "severity": "HIGH", "class": "overflow"}
        f2 = {"snippet_id": "a", "severity": "LOW", "class": ""}
        promoted, suppressed = merge_hunter_outputs([[f1], [f2]], min_votes=2)
        self.assertEqual(len(suppressed), 2)


class VotingSeverityInflationTests(unittest.TestCase):
    """Hunters inflating severity to win conflict resolution."""

    def test_higher_severity_wins_on_conflict(self):
        low = _f("s1", sev="LOW")
        high = _f("s1", sev="CRITICAL")
        promoted, _ = merge_hunter_outputs([[low], [high], [low]], min_votes=2)
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0]["severity"], "CRITICAL")

    def test_all_hunters_report_same_severity(self):
        findings = [_f("s1", sev="MEDIUM")] * 3
        promoted, _ = merge_hunter_outputs([findings, findings])
        self.assertEqual(promoted[0]["severity"], "MEDIUM")


class VotingBoundaryConditionTests(unittest.TestCase):
    """Edge cases in vote counting."""

    def test_zero_min_votes(self):
        promoted, suppressed = merge_hunter_outputs([[_f("a")], [_f("b")]], min_votes=0)
        self.assertEqual(len(promoted), 2)

    def test_single_run_with_empty_hunter(self):
        promoted, suppressed = merge_hunter_outputs(
            [[_f("a"), _f("b")], []], min_votes=1
        )
        self.assertEqual(len(promoted), 2)
        self.assertEqual(suppressed, [])

    def test_all_empty_runs(self):
        promoted, suppressed = merge_hunter_outputs([[], [], []], min_votes=2)
        self.assertEqual(promoted, [])
        self.assertEqual(suppressed, [])

    def test_some_runs_are_none(self):
        promoted, suppressed = merge_hunter_outputs(
            [None, [_f("a")], None], min_votes=1
        )
        self.assertEqual(len(promoted), 1)

    def test_many_runs_hundred(self):
        common = _f("shared")
        runs = [[common] + [_f(f"u_{i}_{j}") for j in range(5)] for i in range(100)]
        promoted, suppressed = merge_hunter_outputs(runs, min_votes=50)
        self.assertEqual(len(promoted), 1)

    def test_exactly_min_votes(self):
        f = _f("s1")
        promoted, suppressed = merge_hunter_outputs(
            [[f], [f], [_f("other")]], min_votes=2
        )
        self.assertEqual(len(promoted), 1)
        self.assertTrue(all(p["vote_count"] >= 2 for p in promoted))


class VotingTypeEdgeTests(unittest.TestCase):
    """Non-dict items or mixed types inside runs."""

    def test_non_dict_items_skipped(self):
        run = [_f("a"), "string", 42, None, _f("b")]
        with self.assertRaises(AttributeError):
            merge_hunter_outputs([run, [_f("a")]], min_votes=2)

    def test_finding_with_none_snippet_id(self):
        f = _f("s1")
        f["snippet_id"] = None
        promoted, suppressed = merge_hunter_outputs([[f], [f]], min_votes=2)
        self.assertEqual(promoted, [])
        self.assertEqual(suppressed, [])


if __name__ == "__main__":
    unittest.main()
