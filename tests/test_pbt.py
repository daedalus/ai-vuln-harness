"""Tests for the PBT (Property-Based Testing) stage — multi-language support."""

import unittest
from pathlib import Path
from unittest.mock import patch

from ai_vuln_harness.stages.pbt import (
    _FALLBACK_TEMPLATES,
    _VULN_MARKERS,
    _build_pbt_prompt,
    _compile_harness,
    _contains_vuln_signal,
    _extract_falsifying_example,
    _generate_fallback_harness,
    _generate_hypothesis_harness,
    _hypothesis_available,
    _repair_json_output,
    _run_harness,
    _toolchain_available,
    run_pbt_on_finding,
    run_pbt_on_findings,
)


class _Proc:
    def __init__(self, returncode: int, stdout: str = "", stderr: str = ""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class ToolchainAvailableTests(unittest.TestCase):
    @patch("ai_vuln_harness.stages.pbt.shutil.which")
    def test_toolchain_available_for_c(self, which_mock):
        which_mock.return_value = "/usr/bin/gcc"
        ok, msg = _toolchain_available("c")
        self.assertTrue(ok)

    @patch("ai_vuln_harness.stages.pbt.shutil.which")
    def test_toolchain_missing(self, which_mock):
        which_mock.return_value = None
        ok, msg = _toolchain_available("rust")
        self.assertFalse(ok)
        self.assertIn("rustc", msg)

    @patch("ai_vuln_harness.stages.pbt.shutil.which")
    def test_unknown_language_falls_back(self, which_mock):
        which_mock.return_value = None
        ok, msg = _toolchain_available("nonexistent")
        self.assertTrue(ok)


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
        prompt = _build_pbt_prompt(finding, snippet, "c")
        self.assertIn("buffer-overflow", prompt)
        self.assertIn("test_func", prompt)
        self.assertIn("void test_func()", prompt)
        self.assertIn("harness_source", prompt)
        self.assertIn("c", prompt)

    def test_python_language_in_prompt(self):
        finding = {"class": "buffer-overflow", "desc": "", "suspicious_points": []}
        snippet = {"name": "f", "file": "test.py", "content": "def f(): pass"}
        prompt = _build_pbt_prompt(finding, snippet, "python")
        self.assertIn("python", prompt)

    def test_rust_language_in_prompt(self):
        finding = {"class": "use-after-free", "desc": "", "suspicious_points": []}
        snippet = {"name": "f", "file": "test.rs", "content": "fn f() {}"}
        prompt = _build_pbt_prompt(finding, snippet, "rust")
        self.assertIn("rust", prompt)

    def test_fallback_when_no_suspicious_points(self):
        finding = {"class": "unknown", "desc": ""}
        snippet = {"name": "nope", "file": "?", "content": ""}
        prompt = _build_pbt_prompt(finding, snippet, "c")
        self.assertIn("unknown", prompt)


class ContainsVulnSignalTests(unittest.TestCase):
    def test_detects_asan_signal_for_c(self):
        self.assertTrue(_contains_vuln_signal("heap-buffer-overflow", 1, "c"))

    def test_detects_negative_exit(self):
        self.assertTrue(_contains_vuln_signal("anything", -11, "c"))

    def test_clean_output(self):
        self.assertFalse(_contains_vuln_signal("all good", 0, "c"))

    def test_case_insensitive(self):
        self.assertTrue(_contains_vuln_signal("Heap-Buffer-Overflow", 1, "c"))

    def test_no_false_positive_on_innocent_text(self):
        self.assertFalse(_contains_vuln_signal("completed successfully", 0, "c"))

    def test_detects_rust_panic(self):
        self.assertTrue(_contains_vuln_signal("panicked at", 1, "rust"))

    def test_detects_go_panic(self):
        self.assertTrue(_contains_vuln_signal("panic: runtime error", 1, "go"))

    def test_detects_go_race(self):
        self.assertTrue(_contains_vuln_signal("data race detected", 1, "go"))

    def test_detects_python_traceback(self):
        self.assertTrue(
            _contains_vuln_signal("Traceback (most recent call last)", 1, "python")
        )

    def test_detects_js_typeerror(self):
        self.assertTrue(
            _contains_vuln_signal("TypeError: undefined is not", 1, "javascript")
        )

    def test_detects_cpp_terminate(self):
        self.assertTrue(
            _contains_vuln_signal("terminate called after throwing", 1, "cpp")
        )

    def test_language_specific_markers_isolated(self):
        self.assertFalse(_contains_vuln_signal("panicked at", 1, "c"))
        self.assertFalse(_contains_vuln_signal("heap-buffer-overflow", 1, "rust"))


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
    def test_buffer_overflow_sink_c(self):
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {"sink_source_type": "buffer-overflow", "function": "f"}
            ],
        }
        snippet = {"file": "x.c", "name": "f", "content": "void f(){}"}
        harness = _generate_fallback_harness(finding, snippet, "c")
        self.assertIn("test_buffer_overflow", harness)
        self.assertIn("int main(void)", harness)
        self.assertIn("#include <stdlib.h>", harness)

    def test_use_after_free_sink_c(self):
        finding = {
            "class": "use-after-free",
            "suspicious_points": [
                {"sink_source_type": "use-after-free", "function": "f"}
            ],
        }
        snippet = {"file": "x.c", "name": "f", "content": "void f(){}"}
        harness = _generate_fallback_harness(finding, snippet, "c")
        self.assertIn("test_use_after_free", harness)

    def test_format_string_sink_c(self):
        finding = {
            "class": "format-string",
            "suspicious_points": [
                {"sink_source_type": "format-string", "function": "f"}
            ],
        }
        snippet = {"file": "x.c", "name": "f", "content": "void f(){}"}
        harness = _generate_fallback_harness(finding, snippet, "c")
        self.assertIn("test_format_string", harness)

    def test_generic_sink_fallback_c(self):
        finding = {
            "class": "other",
            "suspicious_points": [{"sink_source_type": "other-type", "function": "f"}],
        }
        snippet = {"file": "x.c", "name": "f", "content": "void f(){}"}
        harness = _generate_fallback_harness(finding, snippet, "c")
        self.assertIn("test_generic", harness)

    def test_cpp_fallback(self):
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {"sink_source_type": "buffer-overflow", "function": "f"}
            ],
        }
        snippet = {"file": "x.cpp", "name": "f", "content": "void f(){}"}
        harness = _generate_fallback_harness(finding, snippet, "cpp")
        self.assertIn("std::vector", harness)

    def test_rust_fallback(self):
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {"sink_source_type": "buffer-overflow", "function": "f"}
            ],
        }
        snippet = {"file": "x.rs", "name": "f", "content": "fn f() {}"}
        harness = _generate_fallback_harness(finding, snippet, "rust")
        self.assertIn('extern "C"', harness)
        self.assertIn("fn main()", harness)

    def test_go_fallback(self):
        finding = {
            "class": "nil-pointer",
            "suspicious_points": [{"sink_source_type": "nil-pointer", "function": "f"}],
        }
        snippet = {"file": "x.go", "name": "f", "content": "func f() {}"}
        harness = _generate_fallback_harness(finding, snippet, "go")
        self.assertIn("package main", harness)
        self.assertIn("testNilPointer", harness)

    def test_python_fallback(self):
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {"sink_source_type": "buffer-overflow", "function": "f"}
            ],
        }
        snippet = {"file": "x.py", "name": "f", "content": "def f(): pass"}
        harness = _generate_fallback_harness(finding, snippet, "python")
        self.assertIn("def test_buffer_overflow", harness)

    def test_javascript_fallback(self):
        finding = {
            "class": "nil-pointer",
            "suspicious_points": [{"sink_source_type": "nil-pointer", "function": "f"}],
        }
        snippet = {"file": "x.js", "name": "f", "content": "function f() {}"}
        harness = _generate_fallback_harness(finding, snippet, "javascript")
        self.assertIn("testNullPointer", harness)

    def test_typescript_fallback(self):
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {"sink_source_type": "buffer-overflow", "function": "f"}
            ],
        }
        snippet = {"file": "x.ts", "name": "f", "content": "function f(): void {}"}
        harness = _generate_fallback_harness(finding, snippet, "typescript")
        self.assertIn("function testGeneric", harness)

    def test_unknown_language_falls_back_to_c(self):
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {"sink_source_type": "buffer-overflow", "function": "f"}
            ],
        }
        snippet = {"file": "x.xyz", "name": "f", "content": "void f(){}"}
        harness = _generate_fallback_harness(finding, snippet, "unknown")
        self.assertIn("test_buffer_overflow", harness)


class CompileHarnessTests(unittest.TestCase):
    @patch("ai_vuln_harness.stages.pbt.subprocess.run")
    def test_compile_success_c(self, run_mock):
        run_mock.return_value = _Proc(returncode=0, stdout="", stderr="")
        result = _compile_harness("int main(){return 0;}", timeout=10, language="c")
        self.assertTrue(result["compile_succeeded"])
        self.assertIn("pbt_harness.bin", result.get("binary_path", ""))

    @patch("ai_vuln_harness.stages.pbt.subprocess.run")
    def test_compile_failure_c(self, run_mock):
        run_mock.return_value = _Proc(returncode=1, stdout="", stderr="error: syntax")
        result = _compile_harness("bad code", timeout=10, language="c")
        self.assertFalse(result["compile_succeeded"])
        self.assertIn("syntax", result.get("stderr", ""))

    @patch("ai_vuln_harness.stages.pbt.subprocess.run")
    def test_compile_python_interpreted(self, _run_mock):
        result = _compile_harness("print('hello')", timeout=10, language="python")
        self.assertTrue(result["compile_succeeded"])
        self.assertIn(".py", result.get("binary_path", ""))

    @patch("ai_vuln_harness.stages.pbt.subprocess.run")
    def test_compile_go(self, run_mock):
        run_mock.return_value = _Proc(returncode=0, stdout="", stderr="")
        result = _compile_harness(
            "package main; func main() {}", timeout=10, language="go"
        )
        self.assertTrue(result["compile_succeeded"])


class RunHarnessTests(unittest.TestCase):
    @patch("ai_vuln_harness.stages.pbt.subprocess.run")
    def test_run_vuln_observed_c(self, run_mock):
        run_mock.return_value = _Proc(
            returncode=1,
            stdout="",
            stderr="heap-buffer-overflow",
        )
        tmpdir = Path("/tmp")
        bin_path = tmpdir / "pbt_harness.bin"
        bin_path.write_text("")
        result = _run_harness(str(bin_path), timeout=10, iterations=100, language="c")
        self.assertTrue(result["run_succeeded"])
        self.assertTrue(result["vulnerability_observed"])

    @patch("ai_vuln_harness.stages.pbt.subprocess.run")
    def test_run_clean_c(self, run_mock):
        run_mock.return_value = _Proc(
            returncode=0,
            stdout="all good",
            stderr="",
        )
        tmpdir = Path("/tmp")
        bin_path = tmpdir / "pbt_harness.bin"
        bin_path.write_text("")
        result = _run_harness(str(bin_path), timeout=10, iterations=100, language="c")
        self.assertTrue(result["run_succeeded"])
        self.assertFalse(result["vulnerability_observed"])

    @patch("ai_vuln_harness.stages.pbt.subprocess.run")
    def test_run_python_interpreted(self, run_mock):
        run_mock.return_value = _Proc(
            returncode=1,
            stdout="",
            stderr="Traceback",
        )
        tmpdir = Path("/tmp")
        src_path = tmpdir / "pbt_harness.py"
        src_path.write_text("")
        result = _run_harness(
            str(src_path), timeout=10, iterations=100, language="python"
        )
        self.assertTrue(result["run_succeeded"])
        self.assertTrue(result["vulnerability_observed"])

    @patch("ai_vuln_harness.stages.pbt.subprocess.run")
    def test_run_go_panic(self, run_mock):
        run_mock.return_value = _Proc(
            returncode=2,
            stdout="",
            stderr="panic: runtime error: index out of range",
        )
        tmpdir = Path("/tmp")
        bin_path = tmpdir / "pbt_harness.bin"
        bin_path.write_text("")
        result = _run_harness(str(bin_path), timeout=10, iterations=100, language="go")
        self.assertTrue(result["run_succeeded"])
        self.assertTrue(result["vulnerability_observed"])


class VulnMarkersDictTests(unittest.TestCase):
    def test_all_languages_have_markers(self):
        expected = {"c", "cpp", "rust", "go", "python", "javascript", "typescript"}
        self.assertEqual(set(_VULN_MARKERS.keys()), expected)

    def test_all_markers_are_nonempty(self):
        for lang, markers in _VULN_MARKERS.items():
            with self.subTest(lang=lang):
                self.assertGreater(len(markers), 0)


class FallbackTemplatesDictTests(unittest.TestCase):
    def test_all_languages_have_templates(self):
        expected = {"c", "cpp", "rust", "go", "python", "javascript", "typescript"}
        self.assertEqual(set(_FALLBACK_TEMPLATES.keys()), expected)

    def test_all_templates_have_default(self):
        for lang, templates in _FALLBACK_TEMPLATES.items():
            with self.subTest(lang=lang):
                self.assertIn("__default__", templates)


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
        snippet = {"content": "void f(){}", "file": "x.c", "name": "f", "language": "c"}
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
        snippet = {"content": "void f(){}", "file": "x.c", "name": "f", "language": "c"}
        result = run_pbt_on_finding(
            finding, snippet, enable_llm=False, pbt_iterations=50
        )
        self.assertTrue(result["pbt_compile_succeeded"])
        self.assertFalse(result["pbt_falsified"])
        self.assertAlmostEqual(result["pbt_confidence_boost"], -0.1)

    @patch("ai_vuln_harness.stages.pbt._compile_harness")
    @patch("ai_vuln_harness.stages.pbt._run_harness")
    def test_python_finding_uses_python_language(
        self, run_harness_mock, compile_harness_mock
    ):
        compile_harness_mock.return_value = {
            "compile_succeeded": True,
            "stderr": "",
            "binary_path": "/tmp/pbt_harness.py",
        }
        run_harness_mock.return_value = {
            "run_succeeded": True,
            "exit_code": 1,
            "stdout": "",
            "stderr": "Traceback",
            "vulnerability_observed": True,
        }
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {
                    "function": "f",
                    "file": "x.py",
                    "sink_source_type": "buffer-overflow",
                    "confidence": 0.5,
                    "rationale": "x",
                    "evidence_links": [],
                }
            ],
        }
        snippet = {
            "content": "def f(): pass",
            "file": "x.py",
            "name": "f",
            "language": "python",
        }
        result = run_pbt_on_finding(
            finding, snippet, enable_llm=False, pbt_iterations=50
        )
        self.assertTrue(result["pbt_falsified"])
        self.assertAlmostEqual(result["pbt_confidence_boost"], 0.2)

    @patch("ai_vuln_harness.stages.pbt._compile_harness")
    @patch("ai_vuln_harness.stages.pbt._run_harness")
    def test_rust_finding_uses_rust_language(
        self, run_harness_mock, compile_harness_mock
    ):
        compile_harness_mock.return_value = {
            "compile_succeeded": True,
            "stderr": "",
            "binary_path": "/tmp/pbt_harness.bin",
        }
        run_harness_mock.return_value = {
            "run_succeeded": True,
            "exit_code": 1,
            "stdout": "",
            "stderr": "panicked at",
            "vulnerability_observed": True,
        }
        finding = {
            "class": "use-after-free",
            "suspicious_points": [
                {
                    "function": "f",
                    "file": "x.rs",
                    "sink_source_type": "use-after-free",
                    "confidence": 0.5,
                    "rationale": "x",
                    "evidence_links": [],
                }
            ],
        }
        snippet = {
            "content": "fn f() {}",
            "file": "x.rs",
            "name": "f",
            "language": "rust",
        }
        result = run_pbt_on_finding(
            finding, snippet, enable_llm=False, pbt_iterations=50
        )
        self.assertTrue(result["pbt_falsified"])


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
            "s1": {
                "content": "void f(){}",
                "file": "x.c",
                "name": "f",
                "language": "c",
            },
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
            f"s{i}": {
                "content": "void f(){}",
                "file": "x.c",
                "name": "f",
                "language": "c",
            }
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

    @patch("ai_vuln_harness.stages.pbt.run_pbt_on_finding")
    def test_multi_language_findings_all_processed(self, mock_pbt):
        mock_pbt.return_value = {
            "pbt_skipped": False,
            "pbt_falsified": False,
            "pbt_confidence_boost": 0.0,
            "pbt_invariant": "",
            "pbt_compile_succeeded": True,
            "pbt_iterations_run": 500,
        }
        findings = [
            {
                "class": "buffer-overflow",
                "snippet_id": "s1",
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
            },
            {
                "class": "use-after-free",
                "snippet_id": "s2",
                "suspicious_points": [
                    {
                        "function": "f",
                        "file": "x.rs",
                        "sink_source_type": "use-after-free",
                        "confidence": 0.5,
                        "rationale": "x",
                        "evidence_links": [],
                    }
                ],
            },
            {
                "class": "buffer-overflow",
                "snippet_id": "s3",
                "suspicious_points": [
                    {
                        "function": "f",
                        "file": "x.py",
                        "sink_source_type": "buffer-overflow",
                        "confidence": 0.5,
                        "rationale": "x",
                        "evidence_links": [],
                    }
                ],
            },
        ]
        snippet_db = {
            "s1": {
                "content": "void f(){}",
                "file": "x.c",
                "name": "f",
                "language": "c",
            },
            "s2": {
                "content": "fn f() {}",
                "file": "x.rs",
                "name": "f",
                "language": "rust",
            },
            "s3": {
                "content": "def f(): pass",
                "file": "x.py",
                "name": "f",
                "language": "python",
            },
        }
        result = run_pbt_on_findings(findings, snippet_db, enable_llm=False)
        self.assertEqual(len(result), 3)


class HypothesisAvailableTests(unittest.TestCase):
    def test_hypothesis_is_importable(self):
        self.assertTrue(_hypothesis_available())


class GenerateHypothesisHarnessTests(unittest.TestCase):
    def test_generate_buffer_overflow(self):
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {"sink_source_type": "buffer-overflow", "function": "f"}
            ],
        }
        snippet = {"file": "x.py", "name": "f", "content": "def f(): pass"}
        harness = _generate_hypothesis_harness(finding, snippet)
        self.assertIn("hypothesis", harness)
        self.assertIn("test_buffer_overflow", harness)
        self.assertIn("PBT(H)", harness)

    def test_generate_null_pointer(self):
        finding = {
            "class": "nil-pointer",
            "suspicious_points": [{"sink_source_type": "nil-pointer", "function": "f"}],
        }
        snippet = {"file": "x.py", "name": "f", "content": "def f(): pass"}
        harness = _generate_hypothesis_harness(finding, snippet)
        self.assertIn("hypothesis", harness)
        self.assertIn("test_null_pointer", harness)

    def test_generate_generic_fallback(self):
        finding = {
            "class": "unknown",
            "suspicious_points": [{"sink_source_type": "unknown", "function": "f"}],
        }
        snippet = {"file": "x.py", "name": "f", "content": "def f(): pass"}
        harness = _generate_hypothesis_harness(finding, snippet)
        self.assertIn("hypothesis", harness)
        self.assertIn("test_generic", harness)

    def test_hypothesis_harnesses_are_valid_syntax(self):
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {"sink_source_type": "buffer-overflow", "function": "f"}
            ],
        }
        snippet = {"file": "x.py", "name": "f", "content": "def f(): pass"}
        harness = _generate_hypothesis_harness(finding, snippet)
        compile(harness, "<test>", "exec")


class ExtractFalsifyingExampleTests(unittest.TestCase):
    def test_extract_hypothesis_output(self):
        text = "some text\nFalsifying example: test_buffer_overflow(write_sz=257)\nmore"
        self.assertEqual(
            _extract_falsifying_example(text),
            "Falsifying example: test_buffer_overflow(write_sz=257)",
        )

    def test_extract_case_insensitive(self):
        text = "falsifying example: test(x=1)"
        self.assertEqual(
            _extract_falsifying_example(text), "falsifying example: test(x=1)"
        )

    def test_extract_not_found(self):
        self.assertEqual(_extract_falsifying_example("no match here"), "")

    def test_extract_empty_string(self):
        self.assertEqual(_extract_falsifying_example(""), "")


@patch("ai_vuln_harness.stages.pbt.subprocess.run")
class HypothesisRunHarnessTests(unittest.TestCase):
    def test_hypothesis_run_via_extra_env(self, run_mock):
        run_mock.return_value = _Proc(
            returncode=1,
            stdout="",
            stderr="Falsifying example: test_buffer_overflow(write_sz=257)",
        )
        tmpdir = Path("/tmp")
        bin_path = tmpdir / "pbt_harness.py"
        bin_path.write_text("")
        try:
            result = _run_harness(
                str(bin_path),
                timeout=10,
                iterations=100,
                language="python",
                extra_env={"PBT_HYPOTHESIS_EXAMPLES": "500"},
            )
        finally:
            bin_path.unlink(missing_ok=True)
        self.assertTrue(result["vulnerability_observed"])
        self.assertIn("falsifying example", result["stderr"].lower())

    def test_hypothesis_run_clean(self, run_mock):
        run_mock.return_value = _Proc(returncode=0, stdout="no overflow", stderr="")
        tmpdir = Path("/tmp")
        bin_path = tmpdir / "pbt_harness.py"
        bin_path.write_text("")
        try:
            result = _run_harness(
                str(bin_path),
                timeout=10,
                iterations=100,
                language="python",
                extra_env={"PBT_HYPOTHESIS_EXAMPLES": "500"},
            )
        finally:
            bin_path.unlink(missing_ok=True)
        self.assertFalse(result["vulnerability_observed"])


@patch("ai_vuln_harness.stages.pbt.subprocess.run")
class HypothesisPbtIntegrationTests(unittest.TestCase):
    def test_hypothesis_enabled_field_in_result(self, run_mock):
        run_mock.return_value = _Proc(returncode=0, stdout="ok", stderr="")
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {
                    "function": "f",
                    "file": "x.py",
                    "sink_source_type": "buffer-overflow",
                    "confidence": 0.5,
                    "rationale": "x",
                    "evidence_links": [],
                }
            ],
        }
        snippet = {
            "content": "def f(): pass",
            "file": "x.py",
            "name": "f",
            "language": "python",
        }
        result = run_pbt_on_finding(
            finding,
            snippet,
            enable_llm=False,
            language="python",
            enable_hypothesis=True,
            hypothesis_max_examples=500,
        )
        self.assertIn("pbt_hypothesis_falsified", result)
        self.assertIn("pbt_hypothesis_falsifying_example", result)
        self.assertIsInstance(result["pbt_hypothesis_falsified"], bool)
        self.assertIsInstance(result["pbt_hypothesis_falsifying_example"], str)

    def test_hypothesis_disabled_skips_run(self, run_mock):
        run_mock.return_value = _Proc(returncode=0, stdout="ok", stderr="")
        finding = {
            "class": "buffer-overflow",
            "suspicious_points": [
                {
                    "function": "f",
                    "file": "x.py",
                    "sink_source_type": "buffer-overflow",
                    "confidence": 0.5,
                    "rationale": "x",
                    "evidence_links": [],
                }
            ],
        }
        snippet = {
            "content": "def f(): pass",
            "file": "x.py",
            "name": "f",
            "language": "python",
        }
        result = run_pbt_on_finding(
            finding,
            snippet,
            enable_llm=False,
            language="python",
            enable_hypothesis=False,
        )
        self.assertFalse(result["pbt_hypothesis_falsified"])
        self.assertEqual(result["pbt_hypothesis_falsifying_example"], "")


class VulnMarkersHypothesisTests(unittest.TestCase):
    def test_falsifying_example_in_markers(self):
        markers = _VULN_MARKERS.get("python", ())
        self.assertIn("falsifying example", markers)


if __name__ == "__main__":
    unittest.main()
