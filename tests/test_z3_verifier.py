from __future__ import annotations

from unittest.mock import patch

from ai_vuln_harness.stages import z3_verifier
from ai_vuln_harness.stages.z3_verifier import verify_validate_feasibility


def test_unknown_when_solver_unavailable():
    with patch("ai_vuln_harness.stages.z3_verifier.z3", None):
        status, reason = verify_validate_feasibility({}, {}, timeout_ms=10)
    assert status == "unknown"
    assert reason == "z3_unavailable"


def test_unknown_for_incomplete_constraints():
    status, reason = verify_validate_feasibility(
        {"desc": "", "validate_reason": ""},
        {"content": ""},
        timeout_ms=10,
    )
    assert status == "unknown"
    assert reason in {"incomplete_constraints", "z3_unavailable"}


def test_unsat_with_explicit_contradiction():
    finding = {
        "desc": "safe wrapper with bounds check",
        "call_path": [],
        "has_valid_localization": False,
        "localization_confidence": 0.1,
        "validate_runtime": {"vulnerability_observed": False},
    }
    status, reason = verify_validate_feasibility(finding, {"content": ""}, timeout_ms=10)
    if z3_verifier.z3 is None:
        assert status == "unknown"
        assert reason == "z3_unavailable"
    else:
        assert status == "unsat"
        assert reason == "infeasible_constraints"


def test_sat_with_runtime_observed():
    finding = {
        "desc": "possible overflow",
        "call_path": ["main", "sink"],
        "has_valid_localization": True,
        "localization_confidence": 0.8,
        "validate_runtime": {"vulnerability_observed": True},
    }
    status, reason = verify_validate_feasibility(finding, {"content": ""}, timeout_ms=10)
    if z3_verifier.z3 is None:
        assert status == "unknown"
        assert reason == "z3_unavailable"
    else:
        assert status == "sat"
        assert reason == "feasible_constraints"


def test_unknown_when_solver_reports_timeout():
    if z3_verifier.z3 is None:
        status, reason = verify_validate_feasibility({}, {}, timeout_ms=1)
        assert status == "unknown"
        assert reason == "z3_unavailable"
        return

    with patch(
        "ai_vuln_harness.stages.z3_verifier._check_with_assumption",
        return_value=("unknown", "timeout"),
    ):
        status, reason = verify_validate_feasibility(
            {"call_path": ["main"]},
            {"content": ""},
            timeout_ms=1,
        )
    assert status == "unknown"
    assert "timeout" in reason
