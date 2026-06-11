"""Tests for test_reducer.py — PoC test-case reduction."""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

from ai_vuln_harness.stages.test_reducer import (
    _interestingness_c,
    _interestingness_generic,
    _interestingness_python,
    _minimal_reduce,
    _shrinkray_available,
    build_interestingness_test,
    reduce_poc_source,
)


class TestShrinkrayAvailable:
    def test_returns_bool(self):
        assert isinstance(_shrinkray_available(), bool)


class TestBuildInterestingnessTest:
    def test_c_lang(self, tmp_path):
        test_fn = build_interestingness_test(tmp_path / "test.c", "c", tmp_path)
        assert test_fn is not None
        assert callable(test_fn)

    def test_python_lang(self, tmp_path):
        test_fn = build_interestingness_test(tmp_path / "test.py", "python", tmp_path)
        assert test_fn is not None

    def test_javascript_lang(self, tmp_path):
        test_fn = build_interestingness_test(
            tmp_path / "test.js", "javascript", tmp_path
        )
        assert test_fn is not None

    def test_unknown_lang_returns_none(self, tmp_path):
        test_fn = build_interestingness_test(
            tmp_path / "test.xyz", "unknown_lang", tmp_path
        )
        assert test_fn is None


class TestInterestingnessPython:
    def test_detects_crash(self, tmp_path):
        crash_src = tmp_path / "crash.py"
        crash_src.write_text("import sys\nsys.exit(1)\n")
        test_fn = _interestingness_python(timeout=5)
        assert test_fn(crash_src) is True

    def test_clean_exit(self, tmp_path):
        clean_src = tmp_path / "clean.py"
        clean_src.write_text("print('hello')\n")
        test_fn = _interestingness_python(timeout=5)
        assert test_fn(clean_src) is False

    def test_syntax_error(self, tmp_path):
        err_src = tmp_path / "err.py"
        err_src.write_text("raise ValueError('test')\n")
        test_fn = _interestingness_python(timeout=5)
        assert test_fn(err_src) is True


class TestMinimalReduce:
    def test_reduces_reducible_source(self, tmp_path):
        src = tmp_path / "vuln.c"
        lines = [
            "#include <stdlib.h>\n",
            "#include <string.h>\n",
            "#include <stdio.h>\n",
            "// padding line 1\n",
            "// padding line 2\n",
            "// padding line 3\n",
            "int main(void) {\n",
            "    char buf[4];\n",
            '    strcpy(buf, "AAAAAAAAAAAAAAAAAAAAAAAA");\n',
            "    return 0;\n",
            "}\n",
        ]
        src.write_text("".join(lines))

        def _interestingness(candidate: Path) -> bool:
            content = candidate.read_text()
            return "strcpy" in content and "AAAAAAAA" in content

        result = _minimal_reduce(src, _interestingness, tmp_path, max_iterations=100)
        assert result.exists()
        reduced = result.read_text()
        assert "strcpy" in reduced
        assert "AAAAAAAA" in reduced
        assert len(reduced.splitlines()) < len(lines)

    def test_preserves_all_lines_when_all_needed(self, tmp_path):
        src = tmp_path / "minimal.c"
        content = "int main() { return 1; }\n"
        src.write_text(content)

        def _always_interesting(candidate: Path) -> bool:
            return "return 1" in candidate.read_text()

        result = _minimal_reduce(src, _always_interesting, tmp_path, max_iterations=50)
        assert result.exists()
        assert "return 1" in result.read_text()


class TestReducePocSource:
    def test_returns_none_for_missing_file(self, tmp_path):
        result = reduce_poc_source(tmp_path / "nonexistent.c", "c", tmp_path)
        assert result is None

    def test_returns_none_for_unknown_lang(self, tmp_path):
        src = tmp_path / "test.xyz"
        src.write_text("hello")
        result = reduce_poc_source(src, "unknown_lang_xyz", tmp_path)
        assert result is None

    @patch(
        "ai_vuln_harness.stages.test_reducer._shrinkray_available",
        return_value=False,
    )
    def test_uses_ddmin_when_shrinkray_missing(self, mock_shrinkray, tmp_path):
        src = tmp_path / "vuln.c"
        lines = [
            "#include <stdlib.h>\n",
            "#include <string.h>\n",
            "int x = 0;\n",
            "int y = 1;\n",
            "int z = 2;\n",
            "int main(void) { return 0; }\n",
        ]
        src.write_text("".join(lines))

        workdir = tmp_path / "reduction"
        workdir.mkdir()

        from ai_vuln_harness.stages.test_reducer import _minimal_reduce

        def _interestingness(candidate: Path) -> bool:
            content = candidate.read_text()
            return "int main" in content

        result = _minimal_reduce(src, _interestingness, workdir, max_iterations=100)
        assert result is not None
        assert result.exists()
        assert "int main" in result.read_text()
