"""Adversarial tests for stages/report.py — bucketing and dedup edge cases.

Covers missing severity/status, None values in critical fields,
empty dedup keys, downgrade boundary conditions, and large-scale
report merging scenarios.
"""

import unittest

from stages.report import (
    _downgrade_severity,
    _dedup_key,
    bucket_finding,
    build_report,
    deduplicate,
)


class ReportDowngradeSeverityTests(unittest.TestCase):
    """Severity downgrade boundary conditions."""

    def test_critical_downgrades_to_high(self):
        self.assertEqual(_downgrade_severity('CRITICAL'), 'HIGH')

    def test_informational_stays_informational(self):
        self.assertEqual(_downgrade_severity('INFORMATIONAL'), 'INFORMATIONAL')

    def test_low_downgrades_to_informational(self):
        self.assertEqual(_downgrade_severity('LOW'), 'INFORMATIONAL')

    def test_unknown_severity_defaults_informational(self):
        self.assertEqual(_downgrade_severity('UNKNOWN'), 'INFORMATIONAL')

    def test_case_insensitive_input(self):
        self.assertEqual(_downgrade_severity('high'), 'MEDIUM')
        self.assertEqual(_downgrade_severity('Critical'), 'HIGH')

    def test_none_severity(self):
        self.assertEqual(_downgrade_severity(None), 'INFORMATIONAL')

    def test_empty_string_severity(self):
        self.assertEqual(_downgrade_severity(''), 'INFORMATIONAL')


class ReportBucketFindingEdgeTests(unittest.TestCase):
    """Edge conditions in bucketing logic."""

    def test_missing_severity(self):
        f = {'snippet_id': 's1', 'class': 'overflow', 'status': 'confirmed', 'desc': 'd'}
        bucket, rationale = bucket_finding(f, trace_required=False)
        self.assertIsInstance(bucket, str)
        self.assertIsInstance(rationale, str)

    def test_missing_status(self):
        f = {'snippet_id': 's1', 'class': 'overflow', 'severity': 'HIGH', 'desc': 'd'}
        bucket, rationale = bucket_finding(f, trace_required=False)
        self.assertEqual(bucket, 'backlog')

    def test_poc_confirmed_false_with_confirmed_status_fixnow(self):
        f = {
            'snippet_id': 's1', 'class': 'overflow', 'severity': 'CRITICAL',
            'status': 'confirmed', 'poc_confirmed': False,
            'desc': 'd', 'call_path': ['main', 'sink'], 'call_path_verified': True,
        }
        bucket, _ = bucket_finding(f, trace_required=False)
        self.assertEqual(bucket, 'fix_now')

    def test_needs_more_info_with_poc_confirmed_skips_downgrade(self):
        f = {
            'snippet_id': 's1', 'class': 'overflow', 'severity': 'CRITICAL',
            'status': 'needs-more-info', 'poc_confirmed': True,
            'desc': 'd', 'call_path': ['main', 'sink'], 'call_path_verified': True,
        }
        bucket, rationale = bucket_finding(f, trace_required=False)
        self.assertEqual(bucket, 'backlog')
        self.assertIn('needs-more-info', rationale)

    def test_rejected_is_false_positive_without_call_path(self):
        f = {
            'snippet_id': 's1', 'class': 'overflow', 'severity': 'CRITICAL',
            'status': 'rejected', 'desc': 'd',
        }
        bucket, rationale = bucket_finding(f, trace_required=False)
        self.assertEqual(bucket, 'false_positive')

    def test_api_by_design_goes_to_backlog(self):
        f = {
            'snippet_id': 's1', 'class': 'format-string', 'severity': 'HIGH',
            'status': 'confirmed', 'desc': 'by design for printf',
            'function_name': 'printf_wrapper',
            'call_path': ['main', 'printf_wrapper'], 'call_path_verified': True,
        }
        bucket, _ = bucket_finding(f, trace_required=False)
        self.assertEqual(bucket, 'backlog')

    def test_trace_required_blocks_fix_now(self):
        f = {
            'snippet_id': 's1', 'class': 'overflow', 'severity': 'CRITICAL',
            'status': 'confirmed', 'poc_confirmed': True, 'desc': 'd',
            'call_path': ['main', 'sink'], 'call_path_verified': True,
        }
        bucket, _ = bucket_finding(f, trace_required=True, trace_confirmed=False)
        self.assertEqual(bucket, 'backlog')

    def test_trace_confirmed_passes(self):
        f = {
            'snippet_id': 's1', 'class': 'overflow', 'severity': 'CRITICAL',
            'status': 'confirmed', 'poc_confirmed': True, 'desc': 'd',
            'call_path': ['main', 'sink'], 'call_path_verified': True,
        }
        bucket, _ = bucket_finding(f, trace_required=True, trace_confirmed=True)
        self.assertEqual(bucket, 'fix_now')


class ReportDedupEdgeTests(unittest.TestCase):
    """Edge cases in composite-key deduplication."""

    def test_empty_findings(self):
        self.assertEqual(deduplicate([]), [])

    def test_single_finding(self):
        f = {'snippet_id': 's1', 'class': 'overflow', 'severity': 'HIGH'}
        result = deduplicate([f])
        self.assertEqual(len(result), 1)

    def test_missing_lines_key_same_file_class(self):
        f1 = {'snippet_id': 's1', 'class': 'overflow', 'severity': 'HIGH', 'file': 'a.c'}
        f2 = {'snippet_id': 's2', 'class': 'overflow', 'severity': 'MEDIUM', 'file': 'a.c'}
        result = deduplicate([f1, f2])
        self.assertEqual(len(result), 1)

    def test_empty_lines_list(self):
        f1 = {'snippet_id': 's1', 'class': 'overflow', 'severity': 'HIGH', 'file': 'a.c', 'lines': []}
        f2 = {'snippet_id': 's2', 'class': 'overflow', 'severity': 'MEDIUM', 'file': 'a.c', 'lines': []}
        result = deduplicate([f1, f2])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['severity'], 'HIGH')

    def test_different_files_collapse_by_snippet_id(self):
        f1 = {'snippet_id': 's1', 'class': 'overflow', 'severity': 'HIGH'}
        f2 = {'snippet_id': 's1', 'class': 'overflow', 'severity': 'MEDIUM'}
        result = deduplicate([f1, f2])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['severity'], 'HIGH')

    def test_different_classes_same_snippet_id(self):
        f1 = {'snippet_id': 's1', 'class': 'overflow', 'severity': 'HIGH', 'file': 'a.c'}
        f2 = {'snippet_id': 's1', 'class': 'uaf', 'severity': 'CRITICAL', 'file': 'a.c'}
        result = deduplicate([f1, f2])
        self.assertEqual(len(result), 2)

    def test_none_file_falls_back_to_snippet_id(self):
        f1 = {'snippet_id': 's1', 'class': 'overflow', 'severity': 'HIGH', 'file': None}
        f2 = {'snippet_id': 's1', 'class': 'overflow', 'severity': 'MEDIUM', 'file': None}
        result = deduplicate([f1, f2])
        self.assertEqual(len(result), 1)


class ReportBuildReportEdgeTests(unittest.TestCase):
    """Edge cases in full report building."""

    def test_no_findings_with_gaps(self):
        report = build_report('test-repo', [], [], [{'coverage_gap': 'mem', 'reason': 'no files'}])
        self.assertEqual(report['summary']['fix_now'], 0)
        self.assertEqual(len(report['gaps']), 1)

    def test_findings_with_missing_fields(self):
        findings = [
            {'snippet_id': 's1', 'class': 'overflow', 'severity': 'CRITICAL', 'status': 'confirmed',
             'desc': 'd', 'poc_confirmed': True, 'call_path': ['main', 'sink'], 'call_path_verified': True},
            {'snippet_id': 's2'},
        ]
        report = build_report('test-repo', findings, [], [], trace_required=False)
        self.assertGreaterEqual(len(report['findings']), 1)

    def test_chains_marked_feasible(self):
        report = build_report('repo', [], [{'feasible': True}, {'feasible': False}], [])
        self.assertEqual(report['summary']['chains_feasible'], 1)

    def test_bucket_definitions_present(self):
        report = build_report('repo', [], [], [])
        self.assertIn('fix_now', report['bucket_definitions'])
        self.assertIn('backlog', report['bucket_definitions'])
        self.assertIn('false_positive', report['bucket_definitions'])


if __name__ == '__main__':
    unittest.main()
