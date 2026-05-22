"""Tests for benchmark regression gate helpers in run.py."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ai_vuln_harness.run import (
    _extract_report_kpis,
    _resolve_benchmark_targets,
    run_benchmark_gate,
)


def _sample_report(status: str = "confirmed") -> dict:
    return {
        "summary": {"fix_now": 1, "backlog": 0, "false_positive": 0},
        "findings": [
            {
                "file": "a.c",
                "class": "buffer-overflow",
                "lines": [10, 12],
                "severity": "HIGH",
                "status": status,
            }
        ],
        "gaps": [{"status": "resolved"}],
    }


def test_extract_report_kpis_includes_expected_metrics():
    kpis = _extract_report_kpis(
        _sample_report(),
        top_n=10,
        elapsed_seconds=10.0,
        cost_usd=0.5,
    )
    assert kpis["precision_at_top_n"] == 1.0
    assert kpis["reject_rate"] == 0.0
    assert kpis["duplicate_rate"] == 0.0
    assert kpis["gap_closure_rate"] == 1.0
    assert kpis["runtime_per_confirmed_finding_seconds"] == 10.0
    assert kpis["cost_per_confirmed_finding_usd"] == 0.5


def test_resolve_benchmark_targets_defaults_when_no_targets(tmp_path: Path):
    corpus_path = tmp_path / "corpus.json"
    corpus_path.write_text("{}")
    targets = _resolve_benchmark_targets(corpus_path, Path("/repo"), "library")
    assert targets == [{"name": "default", "repo": "/repo", "profile": "library"}]


def test_run_benchmark_gate_fails_when_baseline_missing(tmp_path: Path):
    corpus = tmp_path / "corpus.json"
    baseline = tmp_path / "baseline.json"
    thresholds = tmp_path / "thresholds.json"
    output = tmp_path / "artifact.json"
    corpus.write_text(
        json.dumps(
            {"targets": [{"name": "self", "repo": "/repo", "profile": "library"}]},
        ),
    )
    baseline.write_text(json.dumps({"profiles": {}}))
    thresholds.write_text(json.dumps({"defaults": {}}))

    mock_state = MagicMock()
    mock_state.total_cost.return_value = 0.0

    with (
        patch("ai_vuln_harness.run.run", return_value=_sample_report()),
        patch("ai_vuln_harness.run.StateDB", return_value=mock_state),
        pytest.raises(RuntimeError, match="Benchmark regression gate failed"),
    ):
        run_benchmark_gate(
            Path("/repo"),
            benchmark_corpus=corpus,
            benchmark_baseline=baseline,
            benchmark_thresholds=thresholds,
            benchmark_output=output,
            benchmark_profile="library",
        )

    artifact = json.loads(output.read_text())
    assert artifact["gate_passed"] is False
    assert artifact["missing_baselines"] == ["library"]


def test_run_benchmark_gate_updates_baseline_when_requested(tmp_path: Path):
    corpus = tmp_path / "corpus.json"
    baseline = tmp_path / "baseline.json"
    thresholds = tmp_path / "thresholds.json"
    output = tmp_path / "artifact.json"
    corpus.write_text(
        json.dumps(
            {"targets": [{"name": "self", "repo": "/repo", "profile": "library"}]},
        ),
    )
    baseline.write_text(json.dumps({"profiles": {}}))
    thresholds.write_text(json.dumps({"defaults": {}}))

    mock_state = MagicMock()
    mock_state.total_cost.return_value = 0.0

    with (
        patch("ai_vuln_harness.run.run", return_value=_sample_report()),
        patch("ai_vuln_harness.run.StateDB", return_value=mock_state),
    ):
        artifact = run_benchmark_gate(
            Path("/repo"),
            benchmark_corpus=corpus,
            benchmark_baseline=baseline,
            benchmark_thresholds=thresholds,
            benchmark_output=output,
            benchmark_profile="library",
            update_benchmark_baseline=True,
        )

    assert artifact["gate_passed"] is True
    saved = json.loads(baseline.read_text())
    assert "library" in saved["profiles"]


def test_run_benchmark_gate_flags_regression(tmp_path: Path):
    corpus = tmp_path / "corpus.json"
    baseline = tmp_path / "baseline.json"
    thresholds = tmp_path / "thresholds.json"
    output = tmp_path / "artifact.json"
    corpus.write_text(
        json.dumps(
            {"targets": [{"name": "self", "repo": "/repo", "profile": "library"}]},
        ),
    )
    baseline.write_text(
        json.dumps(
            {
                "profiles": {
                    "library": {
                        "precision_at_top_n": 1.0,
                        "reject_rate": 0.0,
                        "duplicate_rate": 0.0,
                        "gap_closure_rate": 1.0,
                        "runtime_per_confirmed_finding_seconds": 0.0,
                        "cost_per_confirmed_finding_usd": 0.0,
                    }
                }
            },
        ),
    )
    thresholds.write_text(
        json.dumps({"defaults": {"precision_at_top_n": 0.01, "reject_rate": 0.01}}),
    )

    mock_state = MagicMock()
    mock_state.total_cost.return_value = 0.0

    with (
        patch("ai_vuln_harness.run.run", return_value=_sample_report(status="rejected")),
        patch("ai_vuln_harness.run.StateDB", return_value=mock_state),
        pytest.raises(RuntimeError),
    ):
        run_benchmark_gate(
            Path("/repo"),
            benchmark_corpus=corpus,
            benchmark_baseline=baseline,
            benchmark_thresholds=thresholds,
            benchmark_output=output,
            benchmark_profile="library",
        )
