"""Tests for sandbox.py — SandboxManager (Docker / subprocess fallback)."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

from pathlib import Path

import pytest

from ai_vuln_harness.sandbox import SandboxManager, _docker_reachable, _resolve_workdir


class TestSandboxManagerInit:
    def test_backend_subprocess_no_docker(self):
        mgr = SandboxManager(backend="subprocess")
        assert not mgr.available()

    @patch("ai_vuln_harness.sandbox._check_dep", return_value=False)
    def test_backend_docker_dep_missing(self, mock_dep):
        mgr = SandboxManager(backend="docker")
        assert not mgr.available()
        mock_dep.assert_called_once()

    @patch("ai_vuln_harness.sandbox._check_dep", return_value=True)
    @patch("ai_vuln_harness.sandbox._docker_reachable", return_value=True)
    def test_backend_docker_ready(self, mock_reach, mock_dep):
        mgr = SandboxManager(backend="docker")
        assert mgr.available()

    @patch("ai_vuln_harness.sandbox._check_dep", return_value=True)
    @patch("ai_vuln_harness.sandbox._docker_reachable", return_value=False)
    def test_backend_docker_not_reachable(self, mock_reach, mock_dep):
        mgr = SandboxManager(backend="docker")
        assert not mgr.available()


class TestSandboxManagerExecuteFallback:
    """When Docker is unavailable, execute() uses subprocess."""

    @patch("ai_vuln_harness.sandbox._check_dep", return_value=False)
    def test_subprocess_ok(self, mock_dep):
        mgr = SandboxManager(backend="docker")
        assert not mgr.available()

        with patch.object(subprocess, "run") as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = "hello"
            mock_proc.stderr = ""
            mock_run.return_value = mock_proc

            result = mgr.execute(["echo", "hello"], timeout=5)

        assert result["returncode"] == 0
        assert result["stdout"] == "hello"
        assert result["stderr"] == ""

    @patch("ai_vuln_harness.sandbox._check_dep", return_value=False)
    def test_subprocess_timeout(self, mock_dep):
        mgr = SandboxManager(backend="docker")

        with patch.object(subprocess, "run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="test", timeout=1)
            result = mgr.execute(["sleep", "10"], timeout=1)

        assert result["returncode"] == -1
        assert "failed" in result["stderr"]


class TestSandboxManagerExecuteDocker:
    """When Docker is available, execute() uses docker run."""

    @patch("ai_vuln_harness.sandbox._check_dep", return_value=True)
    @patch("ai_vuln_harness.sandbox._docker_reachable", return_value=True)
    @patch.object(subprocess, "run")
    def test_docker_run_success(self, mock_run, mock_reach, mock_dep):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "docker_output"
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        mgr = SandboxManager(backend="docker")
        result = mgr.execute(["./binary"], timeout=5, language="c")

        assert result["returncode"] == 0
        assert result["stdout"] == "docker_output"

        # verify docker run was called
        docker_cmd = mock_run.call_args[0][0]
        assert docker_cmd[0] == "docker"
        assert docker_cmd[1] == "run"

    @patch("ai_vuln_harness.sandbox._check_dep", return_value=True)
    @patch("ai_vuln_harness.sandbox._docker_reachable", return_value=True)
    @patch.object(subprocess, "run")
    def test_docker_run_env_passed(self, mock_run, mock_reach, mock_dep):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        mgr = SandboxManager(backend="docker")
        mgr.execute(
            ["python3", "script.py"],
            timeout=5,
            env={"PBT_ITERATIONS": "100"},
            language="python",
        )

        docker_cmd = mock_run.call_args[0][0]
        assert "-e" in docker_cmd
        assert "PBT_ITERATIONS=100" in docker_cmd

    @patch("ai_vuln_harness.sandbox._check_dep", return_value=True)
    @patch("ai_vuln_harness.sandbox._docker_reachable", return_value=True)
    @patch.object(subprocess, "run")
    def test_docker_language_maps_to_image(self, mock_run, mock_reach, mock_dep):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc

        mgr = SandboxManager(backend="docker")
        mgr.execute(["./binary"], timeout=5, language="rust")

        docker_cmd = mock_run.call_args[0][0]
        assert "rust:slim-bookworm" in docker_cmd

    @patch("ai_vuln_harness.sandbox._check_dep", return_value=True)
    @patch("ai_vuln_harness.sandbox._docker_reachable", return_value=True)
    @patch.object(subprocess, "run")
    def test_docker_run_exception_fallback(self, mock_run, mock_reach, mock_dep):
        mock_run.side_effect = OSError("docker daemon not responding")

        mgr = SandboxManager(backend="docker")
        result = mgr.execute(["echo", "hi"], timeout=5)

        assert result["returncode"] == -1
        assert "failed" in result["stderr"]


class TestResolveWorkdir:
    def test_absolute_path(self):
        result = _resolve_workdir(["/usr/bin/echo", "hi"])
        assert str(result) == "/usr/bin"

    def test_relative_path(self):
        cwd = str(Path.cwd())
        result = _resolve_workdir(["./binary"])
        assert str(result) == cwd

    def test_empty_cmd_defaults_cwd(self):
        with patch("pathlib.Path.cwd", return_value="/home/user"):
            result = _resolve_workdir([])
            assert str(result) == "/home/user"


class TestDockerReachable:
    @patch.object(subprocess, "run")
    def test_docker_available(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_run.return_value = mock_proc
        assert _docker_reachable()

    @patch.object(subprocess, "run")
    def test_docker_not_available(self, mock_run):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_run.return_value = mock_proc
        assert not _docker_reachable()

    @patch.object(subprocess, "run", side_effect=FileNotFoundError)
    def test_docker_not_installed(self, mock_run):
        assert not _docker_reachable()
