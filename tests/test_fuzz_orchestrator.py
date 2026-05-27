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
