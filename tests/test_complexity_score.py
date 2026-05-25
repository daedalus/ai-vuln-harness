"""Tests for complexity_score and merge_hunter_outputs complexity penalty.

Covers:
- complexity_score returns 0.0 for minimal findings.
- complexity_score increases with longer call paths.
- complexity_score increases with more conjunctive connectors.
- complexity_score increases with more distinct files in call_path.
- complexity_score is capped at 1.0.
- merge_hunter_outputs annotates findings with complexity_score.
- merge_hunter_outputs demotes high-complexity single-vote findings.
"""

from __future__ import annotations

import unittest

from ai_vuln_harness.stages.voting import complexity_score, merge_hunter_outputs


def _finding(
    sid: str,
    cls: str = "buffer-overflow",
    sev: str = "HIGH",
    call_path: list[object] | None = None,
    desc: str = "",
) -> dict:
    return {
        "snippet_id": sid,
        "class": cls,
        "severity": sev,
        "status": "raw",
        "poc_confirmed": False,
        "call_path": call_path or [],
        "desc": desc,
    }


class TestComplexityScoreBasic(unittest.TestCase):
    """complexity_score basic sanity checks."""

    def test_empty_finding_returns_zero(self):
        """Minimal finding with no call_path or desc scores 0.0."""
        self.assertAlmostEqual(complexity_score({}), 0.0)

    def test_minimal_finding_scores_zero(self):
        """Finding with empty call_path and no connectors scores 0.0."""
        f = _finding("s1")
        self.assertAlmostEqual(complexity_score(f), 0.0)

    def test_score_is_float_in_range(self):
        """Returned score is always a float in [0.0, 1.0]."""
        f = _finding("s1", call_path=["a.c", "b.c", "c.c"], desc="overflow and UAF")
        score = complexity_score(f)
        self.assertIsInstance(score, float)
        self.assertGreaterEqual(score, 0.0)
        self.assertLessEqual(score, 1.0)


class TestComplexityScoreCallPath(unittest.TestCase):
    """complexity_score call_path component."""

    def test_short_call_path_low_score(self):
        """Single-element call path contributes a low score."""
        f = _finding("s1", call_path=["main"])
        score = complexity_score(f)
        self.assertLess(score, 0.2)

    def test_long_call_path_increases_score(self):
        """8-element call path saturates the call_path component."""
        short = _finding("s1", call_path=["a"])
        long_ = _finding("s2", call_path=["a", "b", "c", "d", "e", "f", "g", "h"])
        self.assertGreater(complexity_score(long_), complexity_score(short))

    def test_call_path_ceiling_at_8(self):
        """Call path ≥ 8 elements caps the component at 1.0 (weight 0.5)."""
        f = _finding("s1", call_path=list(range(10)))
        # call_path component should be capped — total score ≤ 1.0
        self.assertLessEqual(complexity_score(f), 1.0)

    def test_call_path_with_file_colon_func_format(self):
        """'file.c:function' entries contribute file diversity."""
        f = _finding(
            "s1",
            call_path=["auth.c:check_creds", "session.c:create_session"],
        )
        score = complexity_score(f)
        self.assertGreater(score, 0.0)

    def test_call_path_with_dict_entries(self):
        """Dict entries with 'file' key are counted as distinct files."""
        f = _finding(
            "s1",
            call_path=[{"file": "a.c", "func": "foo"}, {"file": "b.c", "func": "bar"}],
        )
        score = complexity_score(f)
        self.assertGreater(score, 0.0)


class TestComplexityScoreConnectors(unittest.TestCase):
    """complexity_score connector component."""

    def test_no_connectors_zero_connector_score(self):
        """Desc with no connectors gives 0 connector score."""
        f = _finding("s1", desc="Simple buffer overflow.")
        self.assertAlmostEqual(complexity_score(f), 0.0)

    def test_one_and_connector_increases_score(self):
        """One 'and' in desc increases connector score."""
        f_no = _finding("s1", desc="Buffer overflow.")
        f_and = _finding("s2", desc="Buffer overflow and heap corruption.")
        self.assertGreater(complexity_score(f_and), complexity_score(f_no))

    def test_multiple_connectors_increase_score(self):
        """Multiple connectors increase score proportionally."""
        one = _finding("s1", desc="overflow and corruption")
        many = _finding(
            "s2",
            desc=(
                "overflow and corruption also requires that the heap is fragmented "
                "furthermore the caller is untrusted additionally size check missing"
            ),
        )
        self.assertGreater(complexity_score(many), complexity_score(one))

    def test_connector_ceiling_at_5(self):
        """5+ connectors saturate the component."""
        f = _finding(
            "s1",
            desc="a and b also c additionally d furthermore e requires that f only if g",
        )
        # connector component saturated — overall score ≤ 1.0
        self.assertLessEqual(complexity_score(f), 1.0)

    def test_case_insensitive_connectors(self):
        """Connector matching is case-insensitive."""
        f_lower = _finding("s1", desc="overflow AND corruption")
        f_upper = _finding("s2", desc="overflow and corruption")
        self.assertAlmostEqual(complexity_score(f_lower), complexity_score(f_upper))


class TestComplexityScoreFilesDiversity(unittest.TestCase):
    """complexity_score file diversity component."""

    def test_single_file_low_file_score(self):
        """Single distinct file contributes minimal file score."""
        f = _finding("s1", call_path=["src/a.c", "src/a.c"])
        # Both entries refer to same file
        score = complexity_score(f)
        # File score: 1/4 * 0.2 = 0.05; no connector, no length penalty
        self.assertLess(score, 0.2)

    def test_four_distinct_files_saturates(self):
        """Four distinct files saturates the file diversity component."""
        f_few = _finding("s1", call_path=["a.c"])
        f_many = _finding("s2", call_path=["a.c", "b.c", "c.c", "d.c"])
        self.assertGreater(complexity_score(f_many), complexity_score(f_few))


class TestMergeHunterOutputsComplexityPenalty(unittest.TestCase):
    """merge_hunter_outputs applies complexity penalty correctly."""

    def _high_complexity_finding(self, sid: str) -> dict:
        """Create a finding that scores > 0.75 complexity."""
        return {
            "snippet_id": sid,
            "class": "buffer-overflow",
            "severity": "HIGH",
            "status": "raw",
            "poc_confirmed": False,
            # 8 call_path entries in 4 different files → saturate cp + file
            "call_path": [
                "a.c:f1",
                "a.c:f2",
                "b.c:f3",
                "b.c:f4",
                "c.c:f5",
                "c.c:f6",
                "d.c:f7",
                "d.c:f8",
            ],
            # 5 connectors → saturate connector component
            "desc": (
                "Overflow occurs and also memory is corrupted additionally "
                "requires that heap is fragmented furthermore attacker controlled "
                "only if size is unchecked"
            ),
        }

    def test_annotates_complexity_score(self):
        """All promoted findings are annotated with complexity_score."""
        f = _finding("sid1")
        promoted, _ = merge_hunter_outputs([[f], [f]], min_votes=2)
        self.assertEqual(len(promoted), 1)
        self.assertIn("complexity_score", promoted[0])

    def test_annotates_complexity_score_single_run(self):
        """Single-run fast path also annotates complexity_score."""
        f = _finding("sid1")
        promoted, _ = merge_hunter_outputs([[f]], min_votes=1)
        self.assertEqual(len(promoted), 1)
        self.assertIn("complexity_score", promoted[0])

    def test_high_complexity_just_threshold_demoted(self):
        """High-complexity finding at exactly min_votes is demoted to suppressed."""
        f = self._high_complexity_finding("sid1")
        # Two runs agree (vote_count == min_votes == 2) but high complexity
        promoted, suppressed = merge_hunter_outputs([[f], [f]], min_votes=2)
        self.assertGreater(complexity_score(f), 0.75)
        self.assertEqual(len(promoted), 0)
        self.assertEqual(len(suppressed), 1)
        self.assertEqual(suppressed[0].get("suppressed_reason"), "complexity_penalty")

    def test_high_complexity_above_threshold_not_demoted(self):
        """High-complexity finding with votes above min_votes is NOT demoted."""
        f = self._high_complexity_finding("sid1")
        # Three runs agree (vote_count=3 > min_votes=2) → no penalty
        promoted, suppressed = merge_hunter_outputs([[f], [f], [f]], min_votes=2)
        self.assertGreater(complexity_score(f), 0.75)
        self.assertEqual(len(promoted), 1)
        # suppressed_reason should NOT be complexity_penalty
        for s in suppressed:
            self.assertNotEqual(s.get("suppressed_reason"), "complexity_penalty")

    def test_low_complexity_at_threshold_not_demoted(self):
        """Low-complexity finding at min_votes is promoted normally."""
        f = _finding("sid1")
        self.assertLessEqual(complexity_score(f), 0.75)
        promoted, suppressed = merge_hunter_outputs([[f], [f]], min_votes=2)
        self.assertEqual(len(promoted), 1)
        for s in suppressed:
            self.assertNotEqual(s.get("suppressed_reason"), "complexity_penalty")


if __name__ == "__main__":
    unittest.main()
