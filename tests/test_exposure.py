import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from ai_vuln_harness.stages.exposure import annotate_exposure_windows


class ExposureWindowTests(unittest.TestCase):
    @patch("ai_vuln_harness.stages.exposure.subprocess.run")
    def test_adds_exposure_window_and_metrics(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="2024-01-01T00:00:00+00:00\n"),
            MagicMock(returncode=0, stdout="2024-06-01T00:00:00+00:00\n"),
            MagicMock(returncode=0, stdout="2024-01-01T00:00:00+00:00\n"),
            MagicMock(returncode=0, stdout="2024-06-01T00:00:00+00:00\n"),
        ]
        findings = [
            {"file": "src/a.py", "status": "confirmed"},
            {"file": "src/b.py", "status": "rejected"},
        ]
        tracked, metrics = annotate_exposure_windows(findings, Path("/repo"))
        self.assertIn("exposure_window", tracked[0])
        self.assertIsNone(tracked[0]["exposure_window"]["fixed_commit_date"])
        self.assertIsNotNone(tracked[1]["exposure_window"]["fixed_commit_date"])
        self.assertEqual(metrics["resolved_findings"], 1)
        self.assertGreaterEqual(metrics["avg_exposure_window_days"], 0.0)

    @patch("ai_vuln_harness.stages.exposure.subprocess.run")
    def test_git_failure_is_fail_open(self, mock_run):
        mock_run.return_value = MagicMock(returncode=128, stdout="")
        findings = [{"file": "src/a.py", "status": "confirmed"}]
        tracked, metrics = annotate_exposure_windows(findings, Path("/repo"))
        self.assertNotIn("exposure_window", tracked[0])
        self.assertEqual(metrics["findings_tracked"], 0)


if __name__ == "__main__":
    unittest.main()
