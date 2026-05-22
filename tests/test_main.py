"""Tests for __main__.py module entry point."""

from __future__ import annotations

import pytest


class TestMainModule:
    """Verify the __main__.py module structure."""

    def test_module_imports(self):
        import ai_vuln_harness.__main__ as m

        assert m is not None

    def test_module_has_main(self):
        import ai_vuln_harness.__main__ as m

        assert callable(m.main)

    def test_main_is_run_main(self):
        import ai_vuln_harness.__main__ as m
        from ai_vuln_harness.run import main as run_main

        assert m.main is run_main
