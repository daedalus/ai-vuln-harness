"""Tests for the 'all' run mode — run_all(), _merge_reports(), and _SINGLE_MODES."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import patch

from run import _SINGLE_MODES, _merge_reports, run_all


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _report(
    repo: str = "/repo",
    findings: list[dict] | None = None,
    chains: list[dict] | None = None,
    gaps: list[dict] | None = None,
    summary: dict | None = None,
    mode_run: str = "full",
) -> dict:
    return {
        "repo": repo,
        "scan_date": "1970-01-01T00:00:00Z",
        "bucket_definitions": {},
        "summary": summary
        or {"fix_now": 0, "backlog": 0, "false_positive": 0, "chains_feasible": 0},
        "findings": findings or [],
        "chains": chains or [],
        "gaps": gaps or [],
        "mode_run": mode_run,
    }


def _finding(file: str, cls: str, line: int, sev: str = "LOW") -> dict:
    return {
        "snippet_id": f"{file}:{line}",
        "file": file,
        "class": cls,
        "lines": [line, line + 10],
        "severity": sev,
        "desc": "test finding",
        "call_path": [],
        "status": "raw",
    }


# ---------------------------------------------------------------------------
# _SINGLE_MODES
# ---------------------------------------------------------------------------


class SingleModesTests(unittest.TestCase):
    def test_all_not_in_single_modes(self):
        self.assertNotIn("all", _SINGLE_MODES)

    def test_expected_modes_present(self):
        for mode in ("full", "max-run", "validate-only", "resume", "diff"):
            self.assertIn(mode, _SINGLE_MODES)

    def test_is_list(self):
        self.assertIsInstance(_SINGLE_MODES, list)

    def test_no_duplicates(self):
        self.assertEqual(len(_SINGLE_MODES), len(set(_SINGLE_MODES)))


# ---------------------------------------------------------------------------
# _merge_reports
# ---------------------------------------------------------------------------


class MergeReportsTests(unittest.TestCase):
    def test_empty_list_returns_empty_report(self):
        merged = _merge_reports([])
        self.assertIn("findings", merged)
        self.assertEqual(merged["findings"], [])

    def test_single_report_findings_preserved(self):
        r = _report(findings=[_finding("a.c", "buf", 1, "HIGH")])
        merged = _merge_reports([r])
        self.assertEqual(len(merged["findings"]), 1)

    def test_identical_findings_deduplicated(self):
        f = _finding("a.c", "buf", 1, "HIGH")
        r1 = _report(findings=[f])
        r2 = _report(findings=[f])
        merged = _merge_reports([r1, r2])
        self.assertEqual(len(merged["findings"]), 1)

    def test_different_findings_kept(self):
        r1 = _report(findings=[_finding("a.c", "buf", 1)])
        r2 = _report(findings=[_finding("b.c", "uaf", 5)])
        merged = _merge_reports([r1, r2])
        self.assertEqual(len(merged["findings"]), 2)

    def test_highest_severity_kept_on_dedup(self):
        low = _finding("a.c", "buf", 1, "LOW")
        high = _finding("a.c", "buf", 1, "HIGH")
        merged = _merge_reports([_report(findings=[low]), _report(findings=[high])])
        self.assertEqual(len(merged["findings"]), 1)
        self.assertEqual(merged["findings"][0]["severity"].upper(), "HIGH")

    def test_chains_aggregated(self):
        r1 = _report(chains=[{"id": "c1"}])
        r2 = _report(chains=[{"id": "c2"}])
        merged = _merge_reports([r1, r2])
        self.assertEqual(len(merged["chains"]), 2)

    def test_gaps_aggregated(self):
        r1 = _report(gaps=[{"id": "g1"}])
        r2 = _report(gaps=[{"id": "g2"}])
        merged = _merge_reports([r1, r2])
        self.assertEqual(len(merged["gaps"]), 2)

    def test_summary_counters_summed(self):
        s1 = {"fix_now": 2, "backlog": 3, "false_positive": 1, "chains_feasible": 0}
        s2 = {"fix_now": 1, "backlog": 1, "false_positive": 0, "chains_feasible": 2}
        r1 = _report(summary=s1)
        r2 = _report(summary=s2)
        merged = _merge_reports([r1, r2])
        self.assertEqual(merged["summary"]["fix_now"], 3)
        self.assertEqual(merged["summary"]["backlog"], 4)
        self.assertEqual(merged["summary"]["false_positive"], 1)
        self.assertEqual(merged["summary"]["chains_feasible"], 2)

    def test_modes_run_list_present(self):
        r1 = _report(mode_run="full")
        r2 = _report(mode_run="max-run")
        merged = _merge_reports([r1, r2])
        self.assertIn("modes_run", merged)
        self.assertIn("full", merged["modes_run"])
        self.assertIn("max-run", merged["modes_run"])

    def test_repo_taken_from_first_report(self):
        r1 = _report(repo="/first")
        r2 = _report(repo="/second")
        merged = _merge_reports([r1, r2])
        self.assertEqual(merged["repo"], "/first")

    def test_non_integer_summary_values_ignored(self):
        r = _report(summary={"fix_now": 1, "label": "ignored"})
        merged = _merge_reports([r])
        self.assertNotIn("label", merged["summary"])


# ---------------------------------------------------------------------------
# run_all
# ---------------------------------------------------------------------------


class RunAllTests(unittest.TestCase):
    def _make_mock_run(self, report_override: dict | None = None):
        """Return a side-effect function that produces a minimal report per mode."""

        def _side_effect(mode, repo, **kwargs):
            r = _report(repo=str(repo), mode_run=mode)
            if report_override:
                r.update(report_override)
            return r

        return _side_effect

    def test_runs_all_single_modes_without_diff_when_no_base_commit(self):
        with patch("run.run", side_effect=self._make_mock_run()) as mock_run:
            run_all(Path("/repo"))
        called_modes = [c.args[0] for c in mock_run.call_args_list]
        self.assertNotIn("diff", called_modes)
        for mode in ("full", "max-run", "validate-only", "resume"):
            self.assertIn(mode, called_modes)

    def test_includes_diff_when_base_commit_provided(self):
        with patch("run.run", side_effect=self._make_mock_run()) as mock_run:
            run_all(Path("/repo"), base_commit="main")
        called_modes = [c.args[0] for c in mock_run.call_args_list]
        self.assertIn("diff", called_modes)

    def test_mode_run_field_is_all(self):
        with patch("run.run", side_effect=self._make_mock_run()):
            merged = run_all(Path("/repo"))
        self.assertEqual(merged.get("mode_run"), "all")

    def test_returns_merged_report_structure(self):
        with patch("run.run", side_effect=self._make_mock_run()):
            merged = run_all(Path("/repo"))
        for key in ("findings", "chains", "gaps", "summary", "modes_run"):
            self.assertIn(key, merged)

    def test_kwargs_forwarded_to_run(self):
        captured = []

        def _side_effect(mode, repo, **kwargs):
            captured.append(kwargs)
            return _report(mode_run=mode)

        with patch("run.run", side_effect=_side_effect):
            run_all(Path("/repo"), kl_threshold=3.0, cosine_threshold=0.9)

        for kwargs in captured:
            self.assertEqual(kwargs["kl_threshold"], 3.0)
            self.assertEqual(kwargs["cosine_threshold"], 0.9)

    def test_base_commit_forwarded_to_diff_run(self):
        captured = {}

        def _side_effect(mode, repo, **kwargs):
            if mode == "diff":
                captured["base_commit"] = kwargs.get("base_commit")
            return _report(mode_run=mode)

        with patch("run.run", side_effect=_side_effect):
            run_all(Path("/repo"), base_commit="v1.0", head_commit="v2.0")

        self.assertEqual(captured.get("base_commit"), "v1.0")

    def test_findings_merged_across_modes(self):
        call_count = [0]

        def _side_effect(mode, repo, **kwargs):
            call_count[0] += 1
            # Each mode returns a unique finding at a different line
            r = _report(
                mode_run=mode, findings=[_finding("x.c", "buf", call_count[0] * 100)]
            )
            return r

        with patch("run.run", side_effect=_side_effect):
            merged = run_all(Path("/repo"))

        # 4 modes (no diff) → 4 unique findings
        self.assertEqual(len(merged["findings"]), 4)

    def test_no_single_modes_returns_empty_report(self):
        with patch("run._SINGLE_MODES", []):
            merged = run_all(Path("/repo"))
        self.assertEqual(merged["findings"], [])
        self.assertEqual(merged.get("mode_run"), "all")


if __name__ == "__main__":
    unittest.main()
