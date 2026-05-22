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
