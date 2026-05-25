"""Tests for the patch candidate generation stage."""

import unittest

from ai_vuln_harness.stages.patch import (
    _is_patchable,
    _match_strategy,
    build_patch_candidates,
)


class MatchStrategyTests(unittest.TestCase):
    """Unit tests for _match_strategy."""

    def test_exact_class_match(self):
        strategy, cwe = _match_strategy("buffer-overflow")
        self.assertIn("bounds check", strategy.lower())
        self.assertEqual(cwe, "CWE-120")

    def test_partial_class_match(self):
        strategy, cwe = _match_strategy("heap-buffer-overflow")
        self.assertEqual(cwe, "CWE-120")

    def test_format_string(self):
        strategy, cwe = _match_strategy("format-string")
        self.assertIn("format", strategy.lower())
        self.assertEqual(cwe, "CWE-134")

    def test_sql_injection(self):
        _strategy, cwe = _match_strategy("sql-injection")
        self.assertEqual(cwe, "CWE-89")

    def test_xss(self):
        _strategy, cwe = _match_strategy("xss")
        self.assertEqual(cwe, "CWE-79")

    def test_auth(self):
        _strategy, cwe = _match_strategy("auth-bypass")
        self.assertEqual(cwe, "CWE-287")

    def test_path_traversal(self):
        _strategy, cwe = _match_strategy("path-traversal")
        self.assertEqual(cwe, "CWE-22")

    def test_crypto(self):
        _strategy, cwe = _match_strategy("weak-crypto")
        self.assertEqual(cwe, "CWE-327")

    def test_use_after_free(self):
        _strategy, cwe = _match_strategy("use-after-free")
        self.assertEqual(cwe, "CWE-416")

    def test_null_deref(self):
        _strategy, cwe = _match_strategy("null-deref")
        self.assertEqual(cwe, "CWE-476")

    def test_race_condition(self):
        _strategy, cwe = _match_strategy("race-condition")
        self.assertEqual(cwe, "CWE-362")

    def test_command_injection(self):
        _strategy, cwe = _match_strategy("command-injection")
        self.assertEqual(cwe, "CWE-78")

    def test_unknown_class_returns_defaults(self):
        strategy, cwe = _match_strategy("unknown-exotic-vuln")
        self.assertIn("minimum change", strategy.lower())
        self.assertEqual(cwe, "CWE-20")

    def test_empty_class_returns_defaults(self):
        strategy, cwe = _match_strategy("")
        self.assertIn("minimum change", strategy.lower())
        self.assertEqual(cwe, "CWE-20")

    def test_longest_key_wins(self):
        # "use-after-free" (14 chars) should beat "auth" (4 chars) when both match
        _strategy, cwe = _match_strategy("use-after-free-auth-bypass")
        self.assertEqual(cwe, "CWE-416")


class IsPatchableTests(unittest.TestCase):
    """Unit tests for _is_patchable."""

    def test_confirmed_validate_status(self):
        self.assertTrue(_is_patchable({"validate_status": "confirmed"}))

    def test_confirmed_status(self):
        self.assertTrue(_is_patchable({"status": "confirmed"}))

    def test_fix_now_status(self):
        self.assertTrue(_is_patchable({"status": "fix_now"}))

    def test_poc_confirmed_flag(self):
        self.assertTrue(_is_patchable({"poc_confirmed": True}))

    def test_poc_confirmed_false_with_raw_status(self):
        self.assertFalse(_is_patchable({"poc_confirmed": False, "status": "raw"}))

    def test_rejected_is_not_patchable(self):
        self.assertFalse(_is_patchable({"status": "rejected"}))

    def test_needs_more_info_is_not_patchable(self):
        self.assertFalse(_is_patchable({"status": "needs-more-info"}))

    def test_empty_finding_is_not_patchable(self):
        self.assertFalse(_is_patchable({}))

    def test_case_insensitive_status(self):
        self.assertTrue(_is_patchable({"status": "CONFIRMED"}))


class BuildPatchCandidatesTests(unittest.TestCase):
    """Integration tests for build_patch_candidates."""

    def _confirmed_finding(self, **kwargs) -> dict:
        base = {
            "snippet_id": "sha256:abc:def",
            "class": "buffer-overflow",
            "severity": "HIGH",
            "status": "confirmed",
            "file": "src/parser.c",
            "lines": [10, 30],
        }
        base.update(kwargs)
        return base

    def test_returns_candidate_for_confirmed_finding(self):
        findings = [self._confirmed_finding()]
        candidates = build_patch_candidates(findings)
        self.assertEqual(len(candidates), 1)
        c = candidates[0]
        self.assertEqual(c["status"], "candidate")
        self.assertEqual(c["cwe"], "CWE-120")
        self.assertEqual(c["severity"], "HIGH")
        self.assertIn("bounds check", c["fix_strategy"].lower())
        self.assertIn("AddressSanitizer", c["verification_plan"])

    def test_skips_raw_findings_by_default(self):
        findings = [
            self._confirmed_finding(status="raw"),
            self._confirmed_finding(status="confirmed"),
        ]
        candidates = build_patch_candidates(findings)
        self.assertEqual(len(candidates), 1)

    def test_include_all_overrides_filter(self):
        findings = [
            self._confirmed_finding(status="raw"),
            self._confirmed_finding(status="rejected"),
        ]
        candidates = build_patch_candidates(findings, include_all=True)
        self.assertEqual(len(candidates), 2)

    def test_snippet_db_populates_code_region(self):
        snippet_db = {
            "sha256:abc:def": {
                "content": "void foo(char *buf) { strcpy(dst, buf); }",
                "file": "src/parser.c",
            }
        }
        findings = [self._confirmed_finding()]
        candidates = build_patch_candidates(findings, snippet_db)
        self.assertIn("strcpy", candidates[0]["code_region"])

    def test_missing_snippet_gives_empty_code_region(self):
        findings = [self._confirmed_finding(snippet_id="nonexistent")]
        candidates = build_patch_candidates(findings)
        self.assertEqual(candidates[0]["code_region"], "")

    def test_poc_confirmed_flag_triggers_candidate(self):
        findings = [
            {
                "snippet_id": "s1",
                "class": "null-deref",
                "severity": "MEDIUM",
                "status": "raw",
                "poc_confirmed": True,
            }
        ]
        candidates = build_patch_candidates(findings)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["cwe"], "CWE-476")

    def test_patch_id_is_unique_per_candidate(self):
        findings = [
            self._confirmed_finding(snippet_id="s1"),
            self._confirmed_finding(snippet_id="s2"),
        ]
        candidates = build_patch_candidates(findings)
        ids = [c["patch_id"] for c in candidates]
        self.assertEqual(len(ids), len(set(ids)))

    def test_empty_findings_returns_empty_list(self):
        self.assertEqual(build_patch_candidates([]), [])

    def test_severity_is_normalised_to_uppercase(self):
        findings = [self._confirmed_finding(severity="high")]
        candidates = build_patch_candidates(findings)
        self.assertEqual(candidates[0]["severity"], "HIGH")

    def test_file_falls_back_to_snippet_db(self):
        snippet_db = {"s1": {"file": "lib/foo.c", "content": ""}}
        findings = [
            {
                "snippet_id": "s1",
                "class": "auth",
                "severity": "CRITICAL",
                "status": "confirmed",
            }
        ]
        candidates = build_patch_candidates(findings, snippet_db)
        self.assertEqual(candidates[0]["file"], "lib/foo.c")

    def test_lines_falls_back_to_snippet_db(self):
        snippet_db = {"s1": {"lines": [5, 20], "content": ""}}
        findings = [
            {
                "snippet_id": "s1",
                "class": "xss",
                "severity": "HIGH",
                "status": "confirmed",
            }
        ]
        candidates = build_patch_candidates(findings, snippet_db)
        self.assertEqual(candidates[0]["lines"], [5, 20])

    def test_domain_field_used_when_class_absent(self):
        findings = [
            {
                "snippet_id": "s1",
                "domain": "sql-injection",
                "severity": "HIGH",
                "status": "confirmed",
            }
        ]
        candidates = build_patch_candidates(findings)
        self.assertEqual(candidates[0]["cwe"], "CWE-89")

    def test_none_snippet_db_is_safe(self):
        findings = [self._confirmed_finding()]
        candidates = build_patch_candidates(findings, None)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["code_region"], "")

    def test_all_required_keys_present(self):
        findings = [self._confirmed_finding()]
        c = build_patch_candidates(findings)[0]
        for key in (
            "patch_id",
            "finding_id",
            "snippet_id",
            "file",
            "lines",
            "vuln_class",
            "severity",
            "cwe",
            "fix_strategy",
            "code_region",
            "verification_plan",
            "status",
        ):
            self.assertIn(key, c, f"missing key: {key}")


if __name__ == "__main__":
    unittest.main()
