"""Tests for the PBT (Property-Based Testing) stage."""

import unittest
from pathlib import Path
from unittest.mock import patch

from ai_vuln_harness.stages.pbt import (
    _build_pbt_prompt,
    _compile_harness,
    _contains_vuln_signal,
    _generate_fallback_harness,
    _repair_json_output,
    _run_harness,
    run_pbt_on_finding,
    run_pbt_on_findings,
)


class _Proc:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class BuildPbtPromptTests(unittest.TestCase):
    def test_basic_prompt_structure(self):
        finding = {
            "class": "buffer-overflow",
            "desc": "buffer overflow through gets()",
            "suspicious_points": [
                {
                    "function": "test_func",
                    "file": "src/test.c",
                    "sink_source_type": "buffer-overflow",
                }
            ],
        }
        snippet = {
            "name": "test_func",
            "file": "src/test.c",
            "content": "void test_func() { char buf[10]; gets(buf); }",
        }
        prompt = _build_pbt_prompt(finding, snippet)
        self.assertIn("buffer-overflow", prompt)
        self.assertIn("test_func", prompt)
        self.assertIn("void test_func()", prompt)
        self.assertIn("harness_source", prompt)

    def test_fallback_when_no_suspicious_points(self):
        finding = {"class": "unknown", "desc": ""}
        snippet = {"name": "nope", "file": "?", "content": ""}
        prompt = _build_pbt_prompt(finding, snippet)
        self.assertIn("unknown", prompt)


class ContainsVulnSignalTests(unittest.TestCase):
    def test_detects_asan_signal(self):
        self.assertTrue(_contains_vuln_signal("heap-buffer-overflow", 1))

    def test_detects_negative_exit(self):
        self.assertTrue(_contains_vuln_signal("anything", -11))

    def test_clean_output(self):
        self.assertFalse(_contains_vuln_signal("all good", 0))

    def test_case_insensitive(self):
        self.assertTrue(_contains_vuln_signal("Heap-Buffer-Overflow", 1))

    def test_no_false_positive_on_innocent_text(self):
        self.assertFalse(_contains_vuln_signal("completed successfully", 0))


class RepairJsonOutputTests(unittest.TestCase):
    def test_valid_json(self):
        raw = '{"invariant": "x", "harness_source": "int main(){}"}'
        obj, repaired = _repair_json_output(raw)
        self.assertEqual(obj["invariant"], "x")
        self.assertFalse(repaired)

    def test_code_block_wrapping(self):
        raw = '```json\n{"invariant": "y"}\n```'
        obj, _ = _repair_json_output(raw)
        self.assertEqual(obj.get("invariant"), "y")

    def test_brace_balancing_fallback(self):
        raw = 'some text before { "invariant": "z" } after'
        obj, repaired = _repair_json_output(raw)
        self.assertEqual(obj.get("invariant"), "z")
        self.assertTrue(repaired)

    def test_fallback_to_raw_when_unparseable(self):
        raw = "not json at all"
        obj, repaired = _repair_json_output(raw)
        self.assertIsInstance(obj, dict)
        self.assertTrue(repaired)


class GenerateFallbackHarnessTests(unittest.TestCase):
    def test_buffer_overflow_sink(self):
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {"sink_source_type": "buffer-overflow", "function": "f"}
            ],
        }
        snippet = {"file": "x.c", "name": "f", "content": "void f(){}"}
        harness = _generate_fallback_harness(finding, snippet)
        self.assertIn("test_buffer_overflow", harness)
        self.assertIn("int main(void)", harness)
        self.assertIn("#include <stdlib.h>", harness)

    def test_use_after_free_sink(self):
        finding = {
            "class": "use-after-free",
            "suspicious_points": [
                {"sink_source_type": "use-after-free", "function": "f"}
            ],
        }
        snippet = {"file": "x.c", "name": "f", "content": "void f(){}"}
        harness = _generate_fallback_harness(finding, snippet)
        self.assertIn("test_use_after_free", harness)

    def test_format_string_sink(self):
        finding = {
            "class": "format-string",
            "suspicious_points": [
                {"sink_source_type": "format-string", "function": "f"}
            ],
        }
        snippet = {"file": "x.c", "name": "f", "content": "void f(){}"}
        harness = _generate_fallback_harness(finding, snippet)
        self.assertIn("test_format_string", harness)

    def test_generic_sink_fallback(self):
        finding = {
            "class": "other",
            "suspicious_points": [{"sink_source_type": "other-type", "function": "f"}],
        }
        snippet = {"file": "x.c", "name": "f", "content": "void f(){}"}
        harness = _generate_fallback_harness(finding, snippet)
        self.assertIn("test_generic", harness)


class CompileHarnessTests(unittest.TestCase):
    @patch("ai_vuln_harness.stages.pbt.subprocess.run")
    def test_compile_success(self, run_mock):
        run_mock.return_value = _Proc(returncode=0, stdout="", stderr="")
        result = _compile_harness("int main(){return 0;}", timeout=10)
        self.assertTrue(result["compile_succeeded"])
        self.assertIn("pbt_harness.bin", result.get("binary_path", ""))

    @patch("ai_vuln_harness.stages.pbt.subprocess.run")
    def test_compile_failure(self, run_mock):
        run_mock.return_value = _Proc(returncode=1, stdout="", stderr="error: syntax")
        result = _compile_harness("bad code", timeout=10)
        self.assertFalse(result["compile_succeeded"])
        self.assertIn("syntax", result.get("stderr", ""))


class RunHarnessTests(unittest.TestCase):
    @patch("ai_vuln_harness.stages.pbt.subprocess.run")
    def test_run_vuln_observed(self, run_mock):
        run_mock.return_value = _Proc(
            returncode=1,
            stdout="",
            stderr="heap-buffer-overflow",
        )
        tmpdir = Path("/tmp")
        bin_path = tmpdir / "pbt_harness.bin"
        bin_path.write_text("")
        result = _run_harness(str(bin_path), timeout=10, iterations=100)
        self.assertTrue(result["run_succeeded"])
        self.assertTrue(result["vulnerability_observed"])

    @patch("ai_vuln_harness.stages.pbt.subprocess.run")
    def test_run_clean(self, run_mock):
        run_mock.return_value = _Proc(
            returncode=0,
            stdout="all good",
            stderr="",
        )
        tmpdir = Path("/tmp")
        bin_path = tmpdir / "pbt_harness.bin"
        bin_path.write_text("")
        result = _run_harness(str(bin_path), timeout=10, iterations=100)
        self.assertTrue(result["run_succeeded"])
        self.assertFalse(result["vulnerability_observed"])


class RunPbtOnFindingTests(unittest.TestCase):
    def test_skipped_when_no_snippet_content(self):
        finding = {}
        snippet = {}
        result = run_pbt_on_finding(
            finding, snippet, enable_llm=False, pbt_iterations=50
        )
        self.assertTrue(result["pbt_skipped"])
        self.assertEqual(result["pbt_confidence_boost"], 0.0)

    @patch("ai_vuln_harness.stages.pbt._compile_harness")
    @patch("ai_vuln_harness.stages.pbt._run_harness")
    def test_fallback_harness_compile_success_and_falsify(
        self, run_harness_mock, compile_harness_mock
    ):
        compile_harness_mock.return_value = {
            "compile_succeeded": True,
            "stderr": "",
            "binary_path": "/tmp/pbt_test_bin",
        }
        run_harness_mock.return_value = {
            "run_succeeded": True,
            "exit_code": 1,
            "stdout": "",
            "stderr": "heap-buffer-overflow",
            "vulnerability_observed": True,
        }
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {
                    "function": "f",
                    "file": "x.c",
                    "sink_source_type": "buffer-overflow",
                    "confidence": 0.5,
                    "rationale": "x",
                    "evidence_links": [],
                }
            ],
        }
        snippet = {"content": "void f(){}", "file": "x.c", "name": "f"}
        result = run_pbt_on_finding(
            finding, snippet, enable_llm=False, pbt_iterations=50
        )
        self.assertTrue(result["pbt_compile_succeeded"])
        self.assertTrue(result["pbt_falsified"])
        self.assertAlmostEqual(result["pbt_confidence_boost"], 0.2)

    @patch("ai_vuln_harness.stages.pbt._compile_harness")
    @patch("ai_vuln_harness.stages.pbt._run_harness")
    def test_no_falsify_when_clean_run(self, run_harness_mock, compile_harness_mock):
        compile_harness_mock.return_value = {
            "compile_succeeded": True,
            "stderr": "",
            "binary_path": "/tmp/pbt_test_bin",
        }
        run_harness_mock.return_value = {
            "run_succeeded": True,
            "exit_code": 0,
            "stdout": "all passed",
            "stderr": "",
            "vulnerability_observed": False,
        }
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {
                    "function": "f",
                    "file": "x.c",
                    "sink_source_type": "buffer-overflow",
                    "confidence": 0.5,
                    "rationale": "x",
                    "evidence_links": [],
                }
            ],
        }
        snippet = {"content": "void f(){}", "file": "x.c", "name": "f"}
        result = run_pbt_on_finding(
            finding, snippet, enable_llm=False, pbt_iterations=50
        )
        self.assertTrue(result["pbt_compile_succeeded"])
        self.assertFalse(result["pbt_falsified"])
        self.assertAlmostEqual(result["pbt_confidence_boost"], -0.1)


class RunPbtOnFindingsTests(unittest.TestCase):
    def test_empty_findings(self):
        result = run_pbt_on_findings([], {}, enable_llm=False)
        self.assertEqual(result, [])

    @patch("ai_vuln_harness.stages.pbt.run_pbt_on_finding")
    def test_only_valid_findings_processed(self, mock_pbt):
        mock_pbt.return_value = {
            "pbt_invariant": "",
            "pbt_harness_source": "",
            "pbt_compile_succeeded": False,
            "pbt_compile_error": "",
            "pbt_run_succeeded": False,
            "pbt_falsified": False,
            "pbt_iterations_run": 500,
            "pbt_exit_code": None,
            "pbt_stdout": "",
            "pbt_stderr": "",
            "pbt_skipped": False,
            "pbt_confidence_boost": 0.0,
        }
        finding = {
            "class": "buffer-overflow",
            "snippet_id": "s1",
            "suspicious_points": [
                {
                    "function": "f",
                    "file": "x.c",
                    "lines": [10, 15],
                    "sink_source_type": "buffer-overflow",
                    "confidence": 0.5,
                    "rationale": "x",
                    "evidence_links": [],
                }
            ],
        }
        snippet_db = {
            "s1": {"content": "void f(){}", "file": "x.c", "name": "f"},
        }
        result = run_pbt_on_findings([finding], snippet_db, enable_llm=False)
        self.assertEqual(len(result), 1)
        self.assertIn("pbt_confidence_boost", result[0])
        self.assertIn("pbt_invariant", result[0])

    def test_max_findings_respected(self):
        findings = []
        for i in range(10):
            findings.append(
                {
                    "class": "buffer-overflow",
                    "snippet_id": f"s{i}",
                    "suspicious_points": [
                        {
                            "function": "f",
                            "file": "x.c",
                            "sink_source_type": "buffer-overflow",
                            "confidence": 0.5,
                            "rationale": "x",
                            "evidence_links": [],
                        }
                    ],
                }
            )
        snippet_db = {
            f"s{i}": {"content": "void f(){}", "file": "x.c", "name": "f"}
            for i in range(10)
        }
        with patch(
            "ai_vuln_harness.stages.pbt.run_pbt_on_finding",
            return_value={
                "pbt_invariant": "",
                "pbt_harness_source": "",
                "pbt_compile_succeeded": False,
                "pbt_compile_error": "",
                "pbt_run_succeeded": False,
                "pbt_falsified": False,
                "pbt_iterations_run": 500,
                "pbt_exit_code": None,
                "pbt_stdout": "",
                "pbt_stderr": "",
                "pbt_skipped": False,
                "pbt_confidence_boost": 0.0,
                "pbt_adjusted_confidence": False,
            },
        ):
            result = run_pbt_on_findings(
                findings, snippet_db, enable_llm=False, max_findings=5
            )
            self.assertLessEqual(len(result), 10)


if __name__ == "__main__":
    unittest.main()
