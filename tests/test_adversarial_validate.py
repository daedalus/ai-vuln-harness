"""Adversarial tests for stages/validate.py — compile/run edge cases.

Covers empty source, compiler bombs, C++ detection tricks,
API-by-design boundary conditions, and signal detection edge cases.
"""

import unittest

from ai_vuln_harness.stages.validate import (
    _contains_vuln_signal,
    _is_c_or_cpp,
    build_validate_prompt,
    is_api_by_design,
    parse_validate_xml,
    recompile_and_run_unvalidated_vulnerable_snippet,
    requires_trace_before_fix_now,
)


class ValidateEmptySourceTests(unittest.TestCase):
    """Empty or minimal source code edge cases."""

    def test_empty_snippet_string(self):
        finding = {"unvalidated_vulnerable_snippet": ""}
        snippet = {"file": "x.c", "language": "c"}
        out = recompile_and_run_unvalidated_vulnerable_snippet(finding, snippet)
        self.assertFalse(out["compile_attempted"])

    def test_only_whitespace_snippet(self):
        finding = {"unvalidated_vulnerable_snippet": "   \n\n  \t  "}
        snippet = {"file": "x.c", "language": "c"}
        out = recompile_and_run_unvalidated_vulnerable_snippet(finding, snippet)
        self.assertFalse(out["compile_attempted"])

    def test_only_comments_source_attempts_compile(self):
        finding = {"unvalidated_vulnerable_snippet": "// just a comment\n/* block */"}
        snippet = {"file": "x.c", "language": "c"}
        out = recompile_and_run_unvalidated_vulnerable_snippet(finding, snippet)
        self.assertTrue(out["compile_attempted"])

    def test_key_not_present_in_finding(self):
        finding = {"class": "overflow"}
        snippet = {"file": "x.c", "language": "c"}
        out = recompile_and_run_unvalidated_vulnerable_snippet(finding, snippet)
        self.assertFalse(out["compile_attempted"])


class ValidateCppDetectionTests(unittest.TestCase):
    """Edge cases in C/C++ language detection."""

    def test_cpp_suffix_variants(self):
        for ext in [".cc", ".cpp", ".cxx", ".c++"]:
            snippet = {"file": f"x{ext}", "language": "c"}
            self.assertTrue(_is_c_or_cpp(snippet), f"{ext} should be C++")

    def test_unknown_suffix_with_c_language(self):
        snippet = {"file": "x.cl", "language": "c"}
        self.assertTrue(_is_c_or_cpp(snippet))

    def test_unknown_suffix_no_language(self):
        snippet = {"file": "x.js"}
        self.assertFalse(_is_c_or_cpp(snippet))

    def test_missing_file_key(self):
        snippet = {"language": "c"}
        self.assertTrue(_is_c_or_cpp(snippet))

    def test_case_insensitive_language(self):
        snippet = {"file": "x.C", "language": "C"}
        self.assertTrue(_is_c_or_cpp(snippet))


class ValidateApiByDesignTests(unittest.TestCase):
    """Boundary conditions for API-by-design detection."""

    def test_none_fields(self):
        self.assertFalse(is_api_by_design({}, {}))

    def test_format_string_class_with_printf_name(self):
        finding = {"class": "format-string"}
        snippet = {"name": "my_printf_impl"}
        self.assertTrue(is_api_by_design(finding, snippet))

    def test_by_design_in_desc(self):
        finding = {"desc": "this is by design behavior"}
        snippet = {"name": "random_function"}
        self.assertTrue(is_api_by_design(finding, snippet))

    def test_case_insensitive_class(self):
        finding = {"class": "Format-String"}
        snippet = {"name": "printf_wrapper"}
        self.assertTrue(is_api_by_design(finding, snippet))


class ValidateVulnSignalTests(unittest.TestCase):
    """Edge cases in vulnerability signal detection."""

    def test_exit_code_zero_no_markers(self):
        self.assertFalse(_contains_vuln_signal("normal output", 0))

    def test_exit_code_nonzero_is_not_vuln_by_itself(self):
        self.assertFalse(
            _contains_vuln_signal("clean output", 1),
            "exit code 1 is not a vulnerability signal",
        )

    def test_exit_code_signal_negative_is_vuln(self):
        self.assertTrue(
            _contains_vuln_signal("segfault", -11),
            "negative exit code indicates signal termination",
        )

    def test_address_sanitizer_found(self):
        self.assertTrue(
            _contains_vuln_signal("SUMMARY: AddressSanitizer: heap-buffer-overflow", 0)
        )

    def test_sigsegv_found(self):
        self.assertTrue(_contains_vuln_signal("Segmentation fault (core dumped)", 0))

    def test_stack_smashing(self):
        self.assertTrue(_contains_vuln_signal("stack smashing detected ***", 0))

    def test_use_after_free(self):
        self.assertTrue(_contains_vuln_signal("ERROR: Use-after-free", 0))

    def test_case_insensitive_marker(self):
        self.assertTrue(_contains_vuln_signal("HEAP-BUFFER-OVERFLOW", 0))

    def test_valgrind_marker_found(self):
        self.assertTrue(
            _contains_vuln_signal(
                "==123== Invalid read of size 4\n==123== ERROR SUMMARY: 1 errors",
                0,
            )
        )


class ValidateRequiresTraceTests(unittest.TestCase):
    """Edge cases for trace requirement logic."""

    def test_library_target_no_trace(self):
        self.assertTrue(requires_trace_before_fix_now(True, False))

    def test_library_target_with_trace(self):
        self.assertFalse(requires_trace_before_fix_now(True, True))

    def test_non_library_target(self):
        self.assertFalse(requires_trace_before_fix_now(False, False))


class ValidatePromptEdgeTests(unittest.TestCase):
    """Edge cases in prompt construction."""

    def test_prompt_with_empty_fields(self):
        prompt = build_validate_prompt({}, {})
        self.assertIn("DISPROVE", prompt)
        self.assertIn("Try JSON first", prompt)

    def test_prompt_with_special_chars_in_desc(self):
        finding = {"snippet_id": "<script>", "class": "alert(1)", "desc": "drop table;"}
        snippet = {"file": "$HOME/test", "lines": "1-10", "content": "void pwn() {}"}
        prompt = build_validate_prompt(finding, snippet)
        self.assertIn("drop table;", prompt)


class ValidateCompileAdversarialTests(unittest.TestCase):
    """Compile-related adversarial patterns."""

    def test_trigraphs_source(self):
        finding = {
            "unvalidated_vulnerable_snippet": "??=include <stdio.h>\nint main() { return 0; }"
        }
        snippet = {"file": "x.c", "language": "c"}
        out = recompile_and_run_unvalidated_vulnerable_snippet(finding, snippet)
        self.assertIsInstance(out["compile_attempted"], bool)

    def test_path_traversal_attempt_in_snippet(self):
        finding = {
            "unvalidated_vulnerable_snippet": '#include "../../../../etc/passwd"\nint main() { return 0; }'
        }
        snippet = {"file": "x.c", "language": "c"}
        out = recompile_and_run_unvalidated_vulnerable_snippet(finding, snippet)
        self.assertIsInstance(out["compile_attempted"], bool)


class ValidateAdversarialSourcesTests(unittest.TestCase):
    """Adversarial edge cases for build_validate_prompt."""

    def test_prompt_with_code_injection_in_fields(self):
        finding = {
            "snippet_id": "s1",
            "class": "overflow",
            "desc": "test",
            "call_path": ["main", "sink"],
        }
        snippet = {
            "file": "test.c",
            "lines": "1-10",
            "content": "void sink() {\n  strcpy(buf, attacker);\n}",
        }
        prompt = build_validate_prompt(finding, snippet)
        self.assertIn("DISPROVE", prompt)
        self.assertIn("strcpy", prompt)
        self.assertIn("test.c", prompt)

    def test_prompt_xss_injection_fields(self):
        finding = {
            "desc": "<script>alert(1)</script>",
            "class": '"><script>',
        }
        snippet = {
            "content": "void foo() {}",
        }
        prompt = build_validate_prompt(finding, snippet)
        self.assertIn("DISPROVE", prompt)


class FormatPromptTests(unittest.TestCase):
    """Tests for format_prompt and system prompt loading."""

    def test_format_prompt_fills_placeholder(self):
        from ai_vuln_harness.stages.runtime import format_prompt

        result = format_prompt("Hello {name}", name="World")
        self.assertEqual(result, "Hello World")

    def test_format_prompt_missing_key_left_as_is(self):
        from ai_vuln_harness.stages.runtime import format_prompt

        result = format_prompt("Hello {name}")
        self.assertEqual(result, "Hello {name}")

    def test_format_prompt_multiple_keys(self):
        from ai_vuln_harness.stages.runtime import format_prompt

        result = format_prompt("{a} {b}", a="1", b="2")
        self.assertEqual(result, "1 2")

    def test_format_prompt_empty_template(self):
        from ai_vuln_harness.stages.runtime import format_prompt

        result = format_prompt("")
        self.assertEqual(result, "")

    def test_system_prompt_contains_pipeline_context(self):
        from ai_vuln_harness.stages.runtime import SYSTEM_PROMPT

        self.assertIn("Pipeline context", SYSTEM_PROMPT)
        self.assertIn("Engagement context", SYSTEM_PROMPT)
        self.assertIn("{engagement_context}", SYSTEM_PROMPT)

    def test_hunt_prompt_contains_quality_tiers(self):
        from ai_vuln_harness.stages.runtime import HUNT_SYSTEM_PROMPT

        self.assertIn("HIGH VALUE", HUNT_SYSTEM_PROMPT)
        self.assertIn("{attack_class}", HUNT_SYSTEM_PROMPT)

    def test_validate_prompt_contains_criteria(self):
        from ai_vuln_harness.stages.runtime import VALIDATE_SYSTEM_PROMPT

        self.assertIn("Validation criteria", VALIDATE_SYSTEM_PROMPT)
        self.assertIn("ALL of these criteria", VALIDATE_SYSTEM_PROMPT)
        self.assertIn("XML", VALIDATE_SYSTEM_PROMPT)


class ParseValidateXmlTests(unittest.TestCase):
    """XML fallback parsing for validate output."""

    def test_valid_xml(self):
        raw = """<validate_result><status>confirmed</status><reason>reachable via user input</reason><criteria><evidentiary>PASS</evidentiary><reproducible>PASS</reproducible><not_by_design>PASS</not_by_design><project_code>FAIL</project_code><consistent>PASS</consistent></criteria></validate_result>"""
        result = parse_validate_xml(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["reason"], "reachable via user input")
        self.assertEqual(result["criteria"]["evidentiary"], "PASS")
        self.assertEqual(result["criteria"]["project_code"], "FAIL")

    def test_xml_with_newlines(self):
        raw = """<validate_result>
  <status>rejected</status>
  <reason>no attacker control</reason>
  <criteria>
    <evidentiary>FAIL</evidentiary>
    <reproducible>FAIL</reproducible>
    <not_by_design>PASS</not_by_design>
    <project_code>PASS</project_code>
    <consistent>FAIL</consistent>
  </criteria>
</validate_result>"""
        result = parse_validate_xml(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "rejected")
        self.assertEqual(result["reason"], "no attacker control")

    def test_missing_status_returns_none(self):
        raw = "<foo>bar</foo>"
        result = parse_validate_xml(raw)
        self.assertIsNone(result)

    def test_xml_vs_json_preference(self):
        import json as _json

        xml = "<validate_result><status>confirmed</status><reason>xml</reason></validate_result>"
        json_str = '{"status": "rejected", "reason": "json"}'
        parsed_xml = parse_validate_xml(xml)
        parsed_json, _ = _json.loads(json_str), False
        self.assertEqual(parsed_xml["status"], "confirmed")
        self.assertEqual(parsed_json["status"], "rejected")
        self.assertNotEqual(parsed_xml["status"], parsed_json["status"])

    def test_unknown_tags_ignored(self):
        raw = """<validate_result><status>needs-more-info</status><reason>test</reason><extra>should be ignored</extra></validate_result>"""
        result = parse_validate_xml(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "needs-more-info")

    def test_no_reason_tag(self):
        raw = "<validate_result><status>confirmed</status></validate_result>"
        result = parse_validate_xml(raw)
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["reason"], "")


if __name__ == "__main__":
    unittest.main()
