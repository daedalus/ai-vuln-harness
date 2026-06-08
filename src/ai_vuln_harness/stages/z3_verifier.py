"""Optional Z3-based feasibility checks for validation-stage findings.

Contract:
  - sat:     finding appears feasible under available constraints.
  - unsat:   finding appears infeasible / contradictory.
  - unknown: insufficient constraints, timeout, or unavailable solver.
"""

from __future__ import annotations

import importlib
import importlib.util
from typing import Protocol

if importlib.util.find_spec("z3") is not None:
    z3 = importlib.import_module("z3")
else:  # pragma: no cover - optional dependency
    z3 = None

_CONTRADICTION_KEYWORDS = (
    "safe wrapper",
    "bounds check",
    "sanitized",
    "input validated",
    "unreachable",
    "dead code",
)

_SAT = "sat"
_UNSAT = "unsat"
_UNKNOWN = "unknown"


def _extract_constraints(
    finding: dict, snippet: dict
) -> dict[str, bool | float | int | None]:
    call_path = finding.get("call_path")
    has_call_path = isinstance(call_path, list)
    call_path_reachable = has_call_path and bool(call_path)

    points = finding.get("suspicious_points")
    has_points = isinstance(points, list) and bool(points)
    has_localization = bool(finding.get("has_valid_localization", False) or has_points)

    runtime = finding.get("validate_runtime")
    runtime_observed: bool | None = None
    if isinstance(runtime, dict) and "vulnerability_observed" in runtime:
        runtime_observed = bool(runtime.get("vulnerability_observed"))

    confidence_raw = finding.get("localization_confidence")
    confidence: float | None = None
    if isinstance(confidence_raw, int | float):
        confidence = float(confidence_raw)

    text = (
        f"{finding.get('desc', '')} "
        f"{finding.get('validate_reason', '')} "
        f"{snippet.get('content', '')[:500]}"
    ).lower()
    contradiction_hint = any(keyword in text for keyword in _CONTRADICTION_KEYWORDS)

    known_signal_count = sum(
        (
            1 if has_call_path else 0,
            1 if has_points or "has_valid_localization" in finding else 0,
            1 if runtime_observed is not None else 0,
            1 if confidence is not None else 0,
            1 if contradiction_hint else 0,
        ),
    )
    constraints: dict[str, bool | float | int | None] = {
        "call_path_reachable": call_path_reachable,
        "has_localization": has_localization,
        "runtime_observed": runtime_observed,
        "confidence": confidence,
        "contradiction_hint": contradiction_hint,
        "known_signal_count": known_signal_count,
    }
    return constraints


class _SolverLike(Protocol):
    def push(self) -> None: ...  # noqa: E704

    def add(self, *args: object) -> None: ...  # noqa: E704

    def check(self) -> object: ...  # noqa: E704

    def reason_unknown(self) -> str: ...  # noqa: E704

    def pop(self) -> None: ...  # noqa: E704


def _check_with_assumption(solver: _SolverLike, expr: object) -> tuple[str, str]:
    if z3 is None:
        return _UNKNOWN, "z3_unavailable"
    solver.push()
    solver.add(expr)
    result = solver.check()
    reason = ""
    if result == z3.unknown:
        reason = str(solver.reason_unknown())
        status = _UNKNOWN
    elif result == z3.sat:
        status = _SAT
    else:
        status = _UNSAT
    solver.pop()
    return status, reason


def verify_validate_feasibility(
    finding: dict,
    snippet: dict,
    *,
    timeout_ms: int = 50,
) -> tuple[str, str]:
    """Return Z3 contract status (sat|unsat|unknown) and a short reason."""
    constraints = _extract_constraints(finding, snippet)
    if z3 is None:
        return _UNKNOWN, "z3_unavailable"

    known_signal_count = constraints["known_signal_count"]
    if not isinstance(known_signal_count, int) or known_signal_count == 0:
        return _UNKNOWN, "incomplete_constraints"

    solver = z3.Solver()
    solver.set(timeout=max(1, timeout_ms))

    call_path_reachable = z3.Bool("call_path_reachable")
    has_localization = z3.Bool("has_localization")
    runtime_observed = z3.Bool("runtime_observed")
    contradiction_hint = z3.Bool("contradiction_hint")
    confidence = z3.Real("confidence")

    solver.add(
        call_path_reachable == z3.BoolVal(bool(constraints["call_path_reachable"]))
    )
    solver.add(has_localization == z3.BoolVal(bool(constraints["has_localization"])))
    solver.add(
        contradiction_hint == z3.BoolVal(bool(constraints["contradiction_hint"]))
    )
    if constraints["runtime_observed"] is not None:
        solver.add(
            runtime_observed == z3.BoolVal(bool(constraints["runtime_observed"]))
        )
    if constraints["confidence"] is None:
        solver.add(confidence >= 0.0, confidence <= 1.0)
    else:
        solver.add(confidence == float(constraints["confidence"]))

    evidence = (
        z3.If(call_path_reachable, 1, 0)
        + z3.If(has_localization, 1, 0)
        + z3.If(runtime_observed, 2, 0)
        + z3.If(confidence >= z3.RealVal("0.65"), 1, 0)
    )
    feasible = z3.Or(
        runtime_observed,
        z3.And(z3.Not(contradiction_hint), evidence >= 2),
    )

    feasible_status, feasible_reason = _check_with_assumption(solver, feasible)
    if feasible_status == _UNKNOWN:
        reason = feasible_reason or "solver_unknown"
        return _UNKNOWN, f"solver_unknown:{reason}"
    infeasible_status, infeasible_reason = _check_with_assumption(
        solver, z3.Not(feasible)
    )
    if infeasible_status == _UNKNOWN:
        reason = infeasible_reason or "solver_unknown"
        return _UNKNOWN, f"solver_unknown:{reason}"

    if feasible_status == _SAT and infeasible_status == _UNSAT:
        return _SAT, "feasible_constraints"
    if feasible_status == _UNSAT and infeasible_status == _SAT:
        return _UNSAT, "infeasible_constraints"
    return _UNKNOWN, "incomplete_constraints"
