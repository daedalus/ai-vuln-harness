"""Tests for stages/voting.py — hunt-stage voting / consensus."""

import unittest

from stages.voting import merge_hunter_outputs


class MergeHunterOutputsTests(unittest.TestCase):
    def _finding(self, sid: str, cls: str = 'buffer-overflow', sev: str = 'HIGH') -> dict:
        return {'snippet_id': sid, 'class': cls, 'severity': sev, 'status': 'raw', 'poc_confirmed': False}

    def test_empty_outputs(self):
        promoted, suppressed = merge_hunter_outputs([])
        self.assertEqual(promoted, [])
        self.assertEqual(suppressed, [])

    def test_single_run_fast_path(self):
        findings = [self._finding('a'), self._finding('b')]
        promoted, suppressed = merge_hunter_outputs([findings], min_votes=2)
        # Fast path: single run, all promoted with vote_count=1
        self.assertEqual(len(promoted), 2)
        self.assertTrue(all(f['vote_count'] == 1 for f in promoted))
        self.assertEqual(suppressed, [])

    def test_two_runs_agreement_promotes(self):
        f = self._finding('sid1')
        promoted, suppressed = merge_hunter_outputs([[f], [f]], min_votes=2)
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0]['vote_count'], 2)
        self.assertEqual(suppressed, [])

    def test_two_runs_disagreement_suppresses(self):
        f1 = self._finding('sid1')
        f2 = self._finding('sid2')
        promoted, suppressed = merge_hunter_outputs([[f1], [f2]], min_votes=2)
        # Neither finding appears in both runs
        self.assertEqual(promoted, [])
        self.assertEqual(len(suppressed), 2)
        self.assertTrue(all(s['vote_count'] == 1 for s in suppressed))

    def test_higher_severity_variant_kept(self):
        low = self._finding('sid1', sev='LOW')
        high = self._finding('sid1', sev='HIGH')
        promoted, _ = merge_hunter_outputs([[low, high], [low]], min_votes=2)
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0]['severity'], 'HIGH')

    def test_min_votes_one_promotes_all(self):
        findings = [self._finding('a'), self._finding('b')]
        promoted, suppressed = merge_hunter_outputs([findings, []], min_votes=1)
        self.assertEqual(len(promoted), 2)
        self.assertEqual(suppressed, [])

    def test_no_snippet_id_skipped(self):
        f = {'class': 'something', 'severity': 'HIGH'}
        promoted, suppressed = merge_hunter_outputs([[f], [f]], min_votes=2)
        self.assertEqual(promoted, [])
        self.assertEqual(suppressed, [])


if __name__ == '__main__':
    unittest.main()
