from unittest.mock import patch

from ai_vuln_harness.stages.fuzz_orchestrator import orchestrate_fuzz_targets


def test_orchestrate_fuzz_targets_builds_function_and_chain_targets():
    findings = [
        {
            "snippet_id": "s1",
            "localization_confidence": 0.9,
            "suspicious_points": [
                {
                    "function": "target",
                    "file": "src/a.c",
                    "lines": [10, 20],
                    "sink_source_type": "buffer-overflow",
                    "confidence": 0.9,
                    "rationale": "verified",
                    "evidence_links": ["s1", "src/a.c"],
                }
            ],
        }
    ]
    snippet_db = {"s1": {"id": "s1", "file": "src/a.c", "content": "int target(){return 0;}"}}
    chains = [{"call_path": ["entry", "target"], "file": "src/a.c", "confidence": 0.5}]
    artifacts = orchestrate_fuzz_targets(
        findings,
        snippet_db,
        chains=chains,
        execute=False,
        max_targets=5,
    )
    assert len(artifacts) == 2
    assert artifacts[0]["target"]["phase"] == "phase1-function"
    assert artifacts[1]["target"]["phase"] == "phase2-cross-function"


@patch("ai_vuln_harness.stages.fuzz_orchestrator.shutil.which", return_value="/bin/valgrind")
@patch(
    "ai_vuln_harness.stages.fuzz_orchestrator.recompile_and_run_unvalidated_vulnerable_snippet"
)
def test_orchestrate_fuzz_targets_uses_valgrind_prefix(run_mock, _which_mock):
    run_mock.return_value = {
        "stdout": "",
        "stderr": "valgrind: invalid read",
        "exit_code": 99,
        "compile_succeeded": True,
        "vulnerability_observed": True,
    }
    findings = [
        {
            "snippet_id": "s1",
            "localization_confidence": 0.9,
            "suspicious_points": [{"function": "target", "file": "src/a.c", "lines": [1]}],
        }
    ]
    snippet_db = {"s1": {"id": "s1", "file": "src/a.c", "content": "int main(){return 0;}"}}
    artifacts = orchestrate_fuzz_targets(
        findings,
        snippet_db,
        execute=True,
        use_valgrind=True,
    )
    sandbox_prefix = run_mock.call_args.kwargs["sandbox_prefix"]
    assert sandbox_prefix[0] == "valgrind"
    assert "--error-exitcode=99" in sandbox_prefix
    assert artifacts[0]["artifact"]["sanitizer_signal"]


@patch("ai_vuln_harness.stages.fuzz_orchestrator.shutil.which", return_value=None)
@patch(
    "ai_vuln_harness.stages.fuzz_orchestrator.recompile_and_run_unvalidated_vulnerable_snippet"
)
def test_orchestrate_fuzz_targets_handles_missing_valgrind(run_mock, _which_mock):
    findings = [
        {
            "snippet_id": "s1",
            "localization_confidence": 0.9,
            "suspicious_points": [{"function": "target", "file": "src/a.c", "lines": [1]}],
        }
    ]
    snippet_db = {"s1": {"id": "s1", "file": "src/a.c", "content": "int main(){return 0;}"}}
    artifacts = orchestrate_fuzz_targets(
        findings,
        snippet_db,
        execute=True,
        use_valgrind=True,
    )
    assert not run_mock.called
    assert artifacts[0]["artifact"]["stderr"] == "valgrind_not_available"
