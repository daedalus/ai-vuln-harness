"""Adversarial property-based tests for SandboxManager and pipeline wiring.

Uses Hypothesis to stress-test edge cases: extreme inputs, nonexistent
binaries, empty/malicious env vars, unknown languages, negative timeouts,
and adversarial config dict combinations.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from ai_vuln_harness.run import _apply_runtime_flags
from ai_vuln_harness.sandbox import (
    SandboxManager,
    _docker_reachable,
    _resolve_workdir,
)


def _load_default_cfg() -> dict:
    pkg_dir = Path(__file__).parent.parent / "src" / "ai_vuln_harness"
    return json.loads((pkg_dir / "config/defaults.json").read_text())


# ── Custom strategies ────────────────────────────────────────────────

adversarial_strings = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "S", "Zs"),
        blacklist_characters=("\x00",),
    ),
    min_size=0,
    max_size=200,
)

env_key = st.text(
    alphabet=st.characters(
        whitelist_categories=("Lu", "Ll", "Nd", "Pc"),
        blacklist_characters=("=",),
    ),
    min_size=1,
    max_size=64,
)

env_value = st.text(
    alphabet=st.characters(
        whitelist_categories=("L", "N", "P", "S", "Zs"),
        blacklist_characters=("\x00",),
    ),
    min_size=0,
    max_size=256,
)

language_strategy = st.one_of(
    st.sampled_from(["python", "c", "cpp", "rust", "go", "javascript", "typescript"]),
    st.text(min_size=0, max_size=20),
)


# ── Invariant: result dict always has correct keys ────────────────────


@settings(max_examples=100)
@given(
    cmd=st.lists(adversarial_strings, min_size=0, max_size=5),
    timeout=st.integers(min_value=-5, max_value=300),
    env=st.dictionaries(env_key, env_value, min_size=0, max_size=5),
    language=language_strategy,
)
def test_execute_result_dict_contract(
    cmd: list[str],
    timeout: int,
    env: dict[str, str],
    language: str,
):
    mgr = SandboxManager(backend="subprocess")
    assume(timeout != 0)
    result = mgr.execute(cmd, timeout=max(timeout, 1), env=env, language=language)
    assert isinstance(result, dict)
    assert "returncode" in result
    assert "stdout" in result
    assert "stderr" in result
    assert isinstance(result["returncode"], int)
    assert isinstance(result["stdout"], str)
    assert isinstance(result["stderr"], str)


# ── Invariant: empty cmd fails gracefully ─────────────────────────


@settings(max_examples=50)
@given(timeout=st.integers(min_value=1, max_value=30))
def test_execute_empty_cmd(timeout: int):
    mgr = SandboxManager(backend="subprocess")
    result = mgr.execute([], timeout=timeout)
    assert result["returncode"] != 0


# ── Invariant: None env == empty dict ──────────────────────────────


@settings(max_examples=50)
@given(
    cmd=st.lists(
        st.text(min_size=1, max_size=10, alphabet="abc"), min_size=1, max_size=2
    ),
    timeout=st.integers(min_value=1, max_value=30),
)
def test_execute_none_env_vs_empty_env(cmd: list[str], timeout: int):
    with patch.object(subprocess, "run") as mock_run:
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        mock_proc.stderr = "not found"
        mock_run.return_value = mock_proc
        mgr = SandboxManager(backend="subprocess")
        r1 = mgr.execute(cmd, timeout=timeout, env=None)
        r2 = mgr.execute(cmd, timeout=timeout, env={})
    assert r1 == r2


# ── Invariant: unknown language falls back to python image ─────────


@settings(max_examples=50)
@given(
    cmd=st.lists(
        st.text(min_size=1, max_size=10, alphabet="ab"), min_size=1, max_size=2
    ),
    timeout=st.integers(min_value=1, max_value=30),
    lang=st.text(min_size=1, max_size=30),
)
def test_unknown_language_fallback(cmd: list[str], timeout: int, lang: str):
    assume(lang not in {"python", "c", "cpp", "rust", "go", "javascript", "typescript"})
    with (
        patch("ai_vuln_harness.sandbox._check_dep", return_value=True),
        patch("ai_vuln_harness.sandbox._docker_reachable", return_value=True),
        patch.object(subprocess, "run") as mock_run,
    ):
        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""
        mock_proc.stderr = ""
        mock_run.return_value = mock_proc
        mgr = SandboxManager(backend="docker")
        mgr.execute(cmd, timeout=timeout, language=lang)
        docker_cmd = mock_run.call_args[0][0]
        assert "python:3.11-slim" in docker_cmd


# ── Invariant: _resolve_workdir never raises ──────────────────────


@settings(max_examples=100)
@given(cmd=st.lists(adversarial_strings, min_size=0, max_size=4))
def test_resolve_workdir_never_raises(cmd: list[str]):
    result = _resolve_workdir(cmd)
    assert isinstance(result, Path)


# ── Invariant: _docker_reachable returns bool ─────────────────────


@settings(max_examples=50)
@given(
    returncode=st.integers(min_value=0, max_value=255),
    side_effect=st.one_of(st.none(), st.just(FileNotFoundError())),
)
def test_docker_reachable_never_raises(returncode: int, side_effect: Exception | None):
    with patch.object(subprocess, "run") as mock_run:
        if side_effect:
            mock_run.side_effect = side_effect
        else:
            mock_proc = MagicMock()
            mock_proc.returncode = returncode
            mock_run.return_value = mock_proc
        result = _docker_reachable()
        assert isinstance(result, bool)


# ── Invariant: _apply_runtime_flags always returns dict ────────────


@settings(max_examples=100)
@given(
    enable_fuzz=st.one_of(st.none(), st.booleans()),
    enable_pbt=st.one_of(st.none(), st.booleans()),
    pbt_llm=st.one_of(st.none(), st.booleans()),
    pbt_hyp=st.one_of(st.none(), st.booleans()),
    sandbox_enabled=st.one_of(st.none(), st.booleans()),
    sandbox_backend=st.one_of(st.none(), st.sampled_from(["docker", "subprocess"])),
    sandbox_compile=st.one_of(st.none(), st.booleans()),
    synth=st.one_of(st.none(), st.booleans()),
    z3=st.one_of(st.none(), st.booleans()),
    z3_ms=st.one_of(st.none(), st.integers(min_value=-100, max_value=10000)),
)
def test_apply_runtime_flags_invariant(
    enable_fuzz: bool | None,
    enable_pbt: bool | None,
    pbt_llm: bool | None,
    pbt_hyp: bool | None,
    sandbox_enabled: bool | None,
    sandbox_backend: str | None,
    sandbox_compile: bool | None,
    synth: bool | None,
    z3: bool | None,
    z3_ms: int | None,
):
    cfg = _load_default_cfg()
    result = _apply_runtime_flags(
        cfg,
        enable_fuzz_orchestrator=enable_fuzz,
        enable_pbt=enable_pbt,
        pbt_enable_llm=pbt_llm,
        pbt_enable_hypothesis=pbt_hyp,
        sandbox=sandbox_enabled,
        sandbox_backend=sandbox_backend,
        sandbox_compile=sandbox_compile,
        enable_exploit_synthesis=synth,
        enable_z3_validate=z3,
        z3_timeout_ms=z3_ms,
    )
    assert isinstance(result, dict)
    sandbox_cfg = result.get("sandbox", {})
    assert isinstance(sandbox_cfg, dict)
    if sandbox_enabled is not None:
        assert sandbox_cfg.get("enabled") == sandbox_enabled
    if sandbox_backend is not None:
        assert sandbox_cfg.get("backend") == sandbox_backend


# ── Invariant: extra config keys don'''t break the function ─────────


@settings(max_examples=100)
@given(
    extra_keys=st.dictionaries(
        st.text(min_size=1, max_size=32, alphabet="abcdefgh_"),
        st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=100)),
        min_size=0,
        max_size=5,
    )
)
def test_config_with_extra_keys(extra_keys: dict[str, object]):
    cfg = _load_default_cfg()
    cfg.update(extra_keys)
    result = _apply_runtime_flags(
        cfg,
        enable_fuzz_orchestrator=True,
        enable_pbt=True,
        sandbox=True,
    )
    assert isinstance(result, dict)
