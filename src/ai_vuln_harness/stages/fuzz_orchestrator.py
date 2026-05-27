"""Optional fuzz-orchestrator stage for reproducibility-oriented artifacts."""

from __future__ import annotations

from collections import deque
import shutil

from .contracts import has_valid_suspicious_points
from .validate import recompile_and_run_unvalidated_vulnerable_snippet


def _finding_queue(
    findings: list[dict],
    *,
    high_confidence_threshold: float,
    max_targets: int,
) -> list[dict]:
    high: deque[dict] = deque()
    medium: deque[dict] = deque()
    low: deque[dict] = deque()
    for finding in findings:
        confidence = float(finding.get("localization_confidence", 0.0))
        if confidence >= high_confidence_threshold:
            high.append(finding)
        elif confidence >= 0.4:
            medium.append(finding)
        else:
            low.append(finding)
    ordered: list[dict] = []
    for bucket in (high, medium, low):
        while bucket and len(ordered) < max_targets:
            ordered.append(bucket.popleft())
    return ordered


def _function_target(finding: dict, snippet: dict) -> dict:
    points = finding.get("suspicious_points") or []
    point = points[0] if points else {}
    function_name = point.get("function") or finding.get("snippet_id") or "unknown"
    return {
        "target_id": f"fuzz-func-{finding.get('snippet_id', 'unknown')}",
        "phase": "phase1-function",
        "function": str(function_name),
        "file": str(point.get("file") or snippet.get("file") or "unknown"),
        "lines": point.get("lines") if isinstance(point.get("lines"), list) else [],
        "confidence": float(point.get("confidence", 0.0)),
        "seed_input": "auto-seed",
        "command": ["local-harness", "--target", str(function_name)],
    }


def _chain_targets(chains: list[dict], max_targets: int) -> list[dict]:
    generated: list[dict] = []
    for idx, chain in enumerate(chains[:max_targets]):
        call_path = chain.get("call_path")
        if not isinstance(call_path, list):
            call_path = []
        generated.append(
            {
                "target_id": f"fuzz-chain-{idx + 1}",
                "phase": "phase2-cross-function",
                "function": " -> ".join(str(v) for v in call_path) or "unknown-chain",
                "file": str(chain.get("file", "unknown")),
                "lines": chain.get("lines")
                if isinstance(chain.get("lines"), list)
                else [],
                "confidence": float(chain.get("confidence", 0.4)),
                "seed_input": "chain-seed",
                "command": ["local-harness", "--chain", str(idx + 1)],
            },
        )
    return generated


def _runtime_artifact(
    target: dict,
    finding: dict,
    snippet: dict,
    *,
    execute: bool,
    timeout_seconds: int,
    use_valgrind: bool,
) -> dict:
    default = {
        "seed_input": target.get("seed_input", "auto-seed"),
        "command": target.get("command", []),
        "stdout": "",
        "stderr": "",
        "sanitizer_signal": "",
        "exit_status": None,
        "compile_succeeded": False,
        "reproduced": False,
    }
    if not execute:
        default["stderr"] = "execution_disabled"
        return default
    source = str(snippet.get("content", "")).strip()
    if not source:
        default["stderr"] = "missing_snippet_source"
        return default
    sandbox_prefix: list[str] | None = None
    if use_valgrind:
        if shutil.which("valgrind") is None:
            default["stderr"] = "valgrind_not_available"
            return default
        sandbox_prefix = [
            "valgrind",
            "--error-exitcode=99",
            "--quiet",
        ]
    runtime = recompile_and_run_unvalidated_vulnerable_snippet(
        {**finding, "unvalidated_vulnerable_snippet": source},
        snippet,
        timeout_seconds=timeout_seconds,
        sandbox_prefix=sandbox_prefix,
    )
    stderr = str(runtime.get("stderr", ""))
    stdout = str(runtime.get("stdout", ""))
    runtime_signal = stderr.lower()
    has_signal = any(
        marker in runtime_signal
        for marker in (
            "sanitizer",
            "valgrind",
            "invalid read",
            "invalid write",
            "definitely lost",
        )
    )
    return {
        "seed_input": target.get("seed_input", "auto-seed"),
        "command": target.get("command", []),
        "stdout": stdout,
        "stderr": stderr,
        "sanitizer_signal": stderr if has_signal else "",
        "exit_status": runtime.get("exit_code"),
        "compile_succeeded": bool(runtime.get("compile_succeeded")),
        "reproduced": bool(runtime.get("vulnerability_observed")),
    }


def orchestrate_fuzz_targets(
    findings: list[dict],
    snippet_db: dict[str, dict],
    *,
    chains: list[dict] | None = None,
    execute: bool = False,
    timeout_seconds: int = 10,
    max_targets: int = 25,
    high_confidence_threshold: float = 0.75,
    max_chain_targets: int = 10,
    use_valgrind: bool = False,
) -> list[dict]:
    """Build fuzz targets/artifacts for function and cross-function tiers."""
    chains = chains or []
    valid_findings = [
        finding for finding in findings if has_valid_suspicious_points(finding)
    ]
    ordered_findings = _finding_queue(
        valid_findings,
        high_confidence_threshold=high_confidence_threshold,
        max_targets=max_targets,
    )

    artifacts: list[dict] = []
    for finding in ordered_findings:
        sid = str(finding.get("snippet_id", ""))
        snippet = snippet_db.get(sid, {})
        target = _function_target(finding, snippet)
        runtime_artifact = _runtime_artifact(
            target,
            finding,
            snippet,
            execute=execute,
            timeout_seconds=timeout_seconds,
            use_valgrind=use_valgrind,
        )
        artifacts.append(
            {
                "finding_id": finding.get("id", finding.get("snippet_id", "")),
                "snippet_id": sid,
                "target": target,
                "artifact": runtime_artifact,
            },
        )

    for chain_target in _chain_targets(chains, max_targets=max_chain_targets):
        artifacts.append(
            {
                "finding_id": chain_target["target_id"],
                "snippet_id": "",
                "target": chain_target,
                "artifact": {
                    "seed_input": chain_target.get("seed_input", "chain-seed"),
                    "command": chain_target.get("command", []),
                    "stdout": "",
                    "stderr": "chain_execution_not_implemented",
                    "sanitizer_signal": "",
                    "exit_status": None,
                    "compile_succeeded": False,
                    "reproduced": False,
                },
            },
        )
    return artifacts
