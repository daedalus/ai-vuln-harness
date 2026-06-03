"""Sandbox manager for Docker-isolated code execution.

Wraps ``llm_sandbox[mcp-docker]`` when available; falls back to plain
``subprocess.run()``.  The manager mounts the binary's parent directory
into the container so compiled executables are accessible, and maps
language names to appropriate Docker images.
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

_SANDBOX_DEP_AVAILABLE: bool | None = None

_LANGUAGE_TO_IMAGE: dict[str, str] = {
    "python": "python:3.11-slim",
    "javascript": "node:20-slim",
    "typescript": "node:20-slim",
    "c": "gcc:latest",
    "cpp": "gcc:latest",
    "rust": "rust:slim-bookworm",
    "go": "golang:1.23-alpine",
}


def _check_dep() -> bool:
    global _SANDBOX_DEP_AVAILABLE
    if _SANDBOX_DEP_AVAILABLE is not None:
        return _SANDBOX_DEP_AVAILABLE
    try:
        import llm_sandbox  # noqa: F401

        _SANDBOX_DEP_AVAILABLE = True
    except ImportError:
        logger.warning("llm-sandbox not installed; falling back to subprocess")
        _SANDBOX_DEP_AVAILABLE = False
    return _SANDBOX_DEP_AVAILABLE


class SandboxManager:
    """Sandboxed execution via Docker or subprocess fallback.

    Usage::

        mgr = SandboxManager(backend="docker")
        if mgr.available():
            result = mgr.execute(["./binary"], timeout=30, language="c")
    """

    def __init__(self, backend: str = "docker") -> None:
        self.backend = backend
        self._docker_ok = False
        if backend == "docker":
            self._docker_ok = _check_dep() and _docker_reachable()
        if self._docker_ok:
            logger.info("[sandbox] Docker backend ready")
        else:
            logger.info("[sandbox] subprocess fallback (backend=%s)", backend)

    def available(self) -> bool:
        return self._docker_ok

    def execute(
        self,
        cmd: list[str],
        *,
        timeout: int,
        env: dict[str, str] | None = None,
        language: str = "python",
    ) -> dict:
        """Run *cmd* and return ``{returncode, stdout, stderr}``."""
        if self._docker_ok:
            return self._run_via_docker(
                cmd, timeout=timeout, env=env, language=language
            )
        return self._run_via_subprocess(cmd, timeout=timeout, env=env)

    # ── Docker path ──────────────────────────────────────────────

    def _run_via_docker(
        self,
        cmd: list[str],
        *,
        timeout: int,
        env: dict[str, str] | None = None,
        language: str = "python",
    ) -> dict:
        workdir, image = (
            _resolve_workdir(cmd),
            _LANGUAGE_TO_IMAGE.get(language, "python:3.11-slim"),
        )
        docker_cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{workdir}:/workspace:ro",
            "-w",
            "/workspace",
        ]
        for k, v in sorted((env or {}).items()):
            docker_cmd.extend(["-e", f"{k}={v}"])
        docker_cmd.append(image)
        docker_cmd.extend(cmd)
        try:
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except Exception:
            logger.exception("[sandbox] Docker execution failed")
            return {"returncode": -1, "stdout": "", "stderr": "docker execution failed"}
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }

    # ── Subprocess fallback ──────────────────────────────────────

    @staticmethod
    def _run_via_subprocess(
        cmd: list[str],
        *,
        timeout: int,
        env: dict[str, str] | None = None,
    ) -> dict:
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                env=dict(env) if env else None,
            )
        except Exception:
            logger.exception("[sandbox] subprocess execution failed")
            return {
                "returncode": -1,
                "stdout": "",
                "stderr": "subprocess execution failed",
            }
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }


# ── Helpers ──────────────────────────────────────────────────────


def _resolve_workdir(cmd: list[str]) -> Path:
    """Parent directory of the first command argument (the binary/script)."""
    if not cmd:
        return Path.cwd()
    p = Path(cmd[0])
    return p.parent.resolve() if not p.is_absolute() else p.parent


def _docker_reachable() -> bool:
    try:
        proc = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return proc.returncode == 0
    except Exception:
        return False
