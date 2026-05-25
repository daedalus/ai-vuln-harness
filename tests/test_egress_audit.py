"""Tests for EgressAuditContext and ScopeViolationError in stages/poc.py.

Covers:
- Raises ScopeViolationError on out-of-scope absolute paths.
- Raises ScopeViolationError on network-adjacent tokens (curl, wget, nc).
- Raises ScopeViolationError on shell-exec tokens with -c flag.
- Passes on allowed binary execution inside output_dir subtree.
- subprocess.run is restored after context exit (no side effects).
"""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from ai_vuln_harness.stages.poc import EgressAuditContext, ScopeViolationError


class TestEgressAuditContextPasses(unittest.TestCase):
    """EgressAuditContext allows permitted commands."""

    def test_allowed_binary_inside_output_dir(self):
        """Running a binary inside output_dir should be allowed."""
        with tempfile.TemporaryDirectory() as td:
            output_dir = Path(td)
            binary = output_dir / "test_binary"
            binary.touch()
            binary.chmod(0o755)

            captured: list[object] = []

            def mock_run(cmd: object, **_kwargs: object) -> object:
                captured.append(cmd)
                return type(
                    "CompletedProcess",
                    (),
                    {"returncode": 0, "stdout": "", "stderr": ""},
                )()

            with patch("subprocess.run", side_effect=mock_run):
                with EgressAuditContext(output_dir, sandbox_prefix=None):
                    subprocess.run([str(binary)], capture_output=True, text=True)

            self.assertEqual(len(captured), 1)

    def test_sandbox_prefix_allowed(self):
        """Sandbox prefix tokens are allowed unconditionally."""
        with tempfile.TemporaryDirectory() as td:
            output_dir = Path(td)
            binary = output_dir / "test_binary"

            captured: list[object] = []

            def mock_run(cmd: object, **_kwargs: object) -> object:
                captured.append(cmd)
                return type(
                    "CompletedProcess",
                    (),
                    {"returncode": 0, "stdout": "", "stderr": ""},
                )()

            with patch("subprocess.run", side_effect=mock_run):
                with EgressAuditContext(output_dir, sandbox_prefix=["firejail", "--"]):
                    subprocess.run(
                        ["firejail", "--", str(binary)],
                        capture_output=True,
                        text=True,
                    )

            self.assertEqual(len(captured), 1)

    def test_subprocess_run_restored_after_context(self):
        """subprocess.run is restored to original after context exit."""
        original = subprocess.run
        with tempfile.TemporaryDirectory() as td:
            with EgressAuditContext(Path(td)):
                pass
        self.assertIs(subprocess.run, original)

    def test_subprocess_run_restored_on_exception(self):
        """subprocess.run is restored even when an exception occurs inside context."""
        original = subprocess.run
        with tempfile.TemporaryDirectory() as td:
            try:
                with EgressAuditContext(Path(td)):
                    raise RuntimeError("test error")
            except RuntimeError:
                pass
        self.assertIs(subprocess.run, original)


class TestEgressAuditContextBlocked(unittest.TestCase):
    """EgressAuditContext raises ScopeViolationError on forbidden commands."""

    def test_curl_raises_scope_violation(self):
        """curl token raises ScopeViolationError."""
        with tempfile.TemporaryDirectory() as td:
            output_dir = Path(td)
            with self.assertRaises(ScopeViolationError):
                with EgressAuditContext(output_dir):
                    subprocess.run(
                        ["curl", "https://example.com"],
                        capture_output=True,
                        text=True,
                    )

    def test_wget_raises_scope_violation(self):
        """wget token raises ScopeViolationError."""
        with tempfile.TemporaryDirectory() as td:
            output_dir = Path(td)
            with self.assertRaises(ScopeViolationError):
                with EgressAuditContext(output_dir):
                    subprocess.run(
                        ["wget", "https://example.com"],
                        capture_output=True,
                        text=True,
                    )

    def test_nc_raises_scope_violation(self):
        """nc (netcat) token raises ScopeViolationError."""
        with tempfile.TemporaryDirectory() as td:
            output_dir = Path(td)
            with self.assertRaises(ScopeViolationError):
                with EgressAuditContext(output_dir):
                    subprocess.run(
                        ["nc", "-lvp", "4444"],
                        capture_output=True,
                        text=True,
                    )

    def test_out_of_scope_path_raises_scope_violation(self):
        """Absolute path outside output_dir raises ScopeViolationError."""
        with tempfile.TemporaryDirectory() as td:
            output_dir = Path(td)
            with self.assertRaises(ScopeViolationError):
                with EgressAuditContext(output_dir):
                    subprocess.run(
                        ["/etc/passwd"],
                        capture_output=True,
                        text=True,
                    )

    def test_bash_with_c_raises_scope_violation(self):
        """bash -c raises ScopeViolationError (shell execution pattern)."""
        with tempfile.TemporaryDirectory() as td:
            output_dir = Path(td)
            with self.assertRaises(ScopeViolationError):
                with EgressAuditContext(output_dir):
                    subprocess.run(
                        ["bash", "-c", "echo pwned"],
                        capture_output=True,
                        text=True,
                    )

    def test_python3_with_c_raises_scope_violation(self):
        """python3 -c raises ScopeViolationError (shell execution pattern)."""
        with tempfile.TemporaryDirectory() as td:
            output_dir = Path(td)
            with self.assertRaises(ScopeViolationError):
                with EgressAuditContext(output_dir):
                    subprocess.run(
                        ["python3", "-c", "import os; os.system('id')"],
                        capture_output=True,
                        text=True,
                    )

    def test_path_outside_output_dir_with_relative_traversal(self):
        """Relative path traversal outside output_dir raises ScopeViolationError."""
        with tempfile.TemporaryDirectory() as td:
            output_dir = Path(td) / "subdir"
            output_dir.mkdir()
            with self.assertRaises(ScopeViolationError):
                with EgressAuditContext(output_dir):
                    subprocess.run(
                        ["../../../bin/sh"],
                        capture_output=True,
                        text=True,
                    )

    def test_scope_violation_error_is_exception(self):
        """ScopeViolationError is a proper Exception subclass."""
        self.assertTrue(issubclass(ScopeViolationError, Exception))


if __name__ == "__main__":
    unittest.main()
