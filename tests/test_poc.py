"""Tests for poc.py — PoC generation functions.

Covers the pure-logic helpers that build PoC JSON and generate source code.
The compilation/execution paths require gcc and are tested separately.
"""

from __future__ import annotations

from ai_vuln_harness.stages.poc import (
    _autogen_source,
    _lang_from_snippet,
    _source_ext,
    build_poc_json,
)


class TestLangFromSnippet:
    def test_returns_language(self):
        assert _lang_from_snippet({"language": "python"}) == "python"

    def test_defaults_to_c(self):
        assert _lang_from_snippet({}) == "c"


class TestSourceExt:
    def test_known_lang(self):
        assert _source_ext("c") == ".c"
        assert _source_ext("python") == ".py"

    def test_unknown_lang(self):
        assert _source_ext("unknown") == ".txt"


class TestBuildPocJson:
    def test_returns_expected_structure(self, sample_snippet):
        finding = {
            "snippet_id": "sha256:abc123:def456",
            "class": "buffer-overflow",
            "severity": "HIGH",
            "desc": "gets() used unsafely",
            "call_path": [],
        }
        poc = build_poc_json(finding, sample_snippet)
        assert poc["schema_version"] == "v1"
        assert "poc-" in poc["poc_id"]
        assert poc["finding"]["class"] == "buffer-overflow"
        assert poc["result"]["status"] == "incomplete"
        assert poc["result"]["verdict"] == "needs-more-info"

    def test_includes_test_case(self, sample_snippet):
        finding = {
            "snippet_id": "s1",
            "class": "overflow",
            "severity": "LOW",
            "desc": "desc",
            "call_path": [],
        }
        poc = build_poc_json(finding, sample_snippet)
        assert len(poc["test_cases"]) == 1
        tc = poc["test_cases"][0]
        assert tc["expected"]["crash"] is True

    def test_compiler_info_for_c(self, sample_snippet):
        finding = {
            "snippet_id": "s1",
            "class": "x",
            "severity": "LOW",
            "desc": "d",
            "call_path": [],
        }
        poc = build_poc_json(finding, sample_snippet)
        assert "gcc" in poc["harness"]["compiler"][0]
        assert "-fsanitize=address" in poc["harness"]["compiler"]


class TestAutogenSource:
    def test_generates_c_source(self, sample_snippet):
        finding = {
            "snippet_id": "s1",
            "class": "x",
            "severity": "LOW",
            "desc": "desc",
            "call_path": [],
        }
        src = _autogen_source(finding, sample_snippet)
        assert "void test_func()" in src
        assert "gets(buf)" in src
        assert "main(void)" in src
        assert "fprintf(stderr" in src

    def test_generates_python_source(self):
        finding = {
            "snippet_id": "s1",
            "class": "x",
            "severity": "LOW",
            "desc": "d",
            "call_path": [],
        }
        snippet = {
            "language": "python",
            "name": "handler",
            "content": "def handler(): pass",
        }
        src = _autogen_source(finding, snippet)
        assert "def handler()" in src
        assert 'sys.stderr.write("Test completed' in src

    def test_unknown_lang_returns_content_as_is(self):
        finding = {
            "snippet_id": "s1",
            "class": "x",
            "severity": "LOW",
            "desc": "d",
            "call_path": [],
        }
        snippet = {"language": "brainfuck", "name": "bf", "content": "+[->+<]"}
        src = _autogen_source(finding, snippet)
        assert src == "+[->+<]"


class TestApplyCorrection:
    """Tests for _apply_correction (self-correction on build failures)."""

    def test_adds_stdio_h_for_implicit_declaration(self):
        from ai_vuln_harness.stages.poc import _apply_correction
        from pathlib import Path
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "test.c"
            src.write_text("int main() { printf(\"hello\"); return 0; }")
            _apply_correction(str(src), "implicit declaration of function printf", 0)
            content = src.read_text()
            assert "#include <stdio.h>" in content

    def test_adds_stdlib_h_for_malloc(self):
        from ai_vuln_harness.stages.poc import _apply_correction
        from pathlib import Path
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "test.c"
            src.write_text("int main() { char *p = malloc(10); return 0; }")
            _apply_correction(str(src), "implicit declaration of function malloc", 0)
            content = src.read_text()
            assert "#include <stdlib.h>" in content

    def test_no_change_when_pattern_not_found(self):
        from ai_vuln_harness.stages.poc import _apply_correction
        from pathlib import Path
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "test.c"
            original = "int main() { return 0; }"
            src.write_text(original)
            _apply_correction(str(src), "some unrelated error", 0)
            assert src.read_text() == original

    def test_handles_missing_file(self):
        from ai_vuln_harness.stages.poc import _apply_correction
        # Should not raise
        _apply_correction("/nonexistent/file.c", "error", 0)


class TestProcessFindingsSignature:
    """Tests for process_findings signature and parameters."""

    def test_has_self_correction_param(self):
        from ai_vuln_harness.stages.poc import process_findings
        import inspect
        sig = inspect.signature(process_findings)
        assert "self_correction" in sig.parameters
        assert "max_retries" in sig.parameters
        assert sig.parameters["self_correction"].default is True
        assert sig.parameters["max_retries"].default == 3
