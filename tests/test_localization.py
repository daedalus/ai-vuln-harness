from ai_vuln_harness.stages.localization import localize_findings


def test_localize_findings_adds_suspicious_points():
    findings = [
        {
            "snippet_id": "s1",
            "severity": "HIGH",
            "class": "buffer-overflow",
            "desc": "overflow in copy",
            "call_path": ["entry", "target"],
        }
    ]
    snippet_db = {
        "s1": {
            "id": "s1",
            "name": "target",
            "file": "src/a.c",
            "lines": [10, 20],
            "content": "void target(char *src) { char buf[8]; strcpy(buf, src); }",
            "callees": [],
        }
    }
    localized, unreachable = localize_findings(findings, snippet_db, entry_points=["entry"])
    assert len(localized) == 1
    assert unreachable == []
    point = localized[0]["suspicious_points"][0]
    assert point["function"]
    assert point["file"] == "src/a.c"
    assert localized[0]["has_valid_localization"] is True
    assert localized[0]["high_priority_validate"] is True
