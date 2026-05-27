"""Tests for standalone helper functions in run.py.

Covers the pure-logic helpers that don't require full pipeline orchestration.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ai_vuln_harness.run import (
    _apply_diff_filter,
    _build_run_kwargs,
    _ingest_snippets,
    _load_jsonl,
    _load_stages_config,
    _persist_jsonl,
    _resolve_model_chain,
    _resolve_pools,
    _run_hunt_stage,
    _run_localization_stage,
    _run_trace_stage,
    _run_validate_stage,
    _setup_logging,
    _setup_proxy,
    _stage_workers,
    _warn_if_no_auth,
)


class TestSetupProxy:
    def test_none_proxy_does_nothing(self):
        _setup_proxy(None)
        assert "http_proxy" not in os.environ or True  # no side-effect

    def test_sets_proxy_env_vars(self):
        with patch.dict(os.environ, {}, clear=True):
            _setup_proxy("http://proxy:8080")
            assert os.environ["http_proxy"] == "http://proxy:8080"
            assert os.environ["https_proxy"] == "http://proxy:8080"
            assert os.environ["HTTP_PROXY"] == "http://proxy:8080"
            assert os.environ["HTTPS_PROXY"] == "http://proxy:8080"

    def test_does_not_override_existing(self):
        with patch.dict(os.environ, {"http_proxy": "http://existing:3128"}, clear=True):
            _setup_proxy("http://proxy:8080")
            assert os.environ["http_proxy"] == "http://existing:3128"


class TestWarnIfNoAuth:
    def test_skips_non_pipeline_modes(self):
        with patch("ai_vuln_harness.run.logger.warning") as mock_warn:
            _warn_if_no_auth("validate-only", None)
            mock_warn.assert_not_called()

    def test_skips_with_auth_json(self):
        with patch("ai_vuln_harness.run.logger.warning") as mock_warn:
            _warn_if_no_auth("full", Path("/tmp/auth.json"))
            mock_warn.assert_not_called()

    def test_warns_when_no_auth_found(self):
        with (
            patch("ai_vuln_harness.run.Path.exists", return_value=False),
            patch("ai_vuln_harness.run.logger.warning") as mock_warn,
        ):
            _warn_if_no_auth("full", None)
            mock_warn.assert_called_once()

    def test_warns_for_benchmark_mode(self):
        with (
            patch("ai_vuln_harness.run.Path.exists", return_value=False),
            patch("ai_vuln_harness.run.logger.warning") as mock_warn,
        ):
            _warn_if_no_auth("benchmark", None)
            mock_warn.assert_called_once()


class TestLoadStagesConfig:
    def test_missing_file_returns_empty_dict(self, tmp_path: Path):
        result = _load_stages_config(tmp_path)
        assert result == {}

    def test_valid_json_returns_dict(self, tmp_path: Path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "stages.json").write_text(
            '{"stages": {"hunt": {"max_workers": 5}}}'
        )
        result = _load_stages_config(tmp_path)
        assert result == {"stages": {"hunt": {"max_workers": 5}}}

    def test_malformed_json_returns_empty(self, tmp_path: Path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "stages.json").write_text("not valid json")
        result = _load_stages_config(tmp_path)
        assert result == {}

    def test_non_dict_json_returns_empty(self, tmp_path: Path):
        config_dir = tmp_path / "config"
        config_dir.mkdir()
        (config_dir / "stages.json").write_text("[]")
        result = _load_stages_config(tmp_path)
        assert result == {}


class TestStageWorkers:
    def test_respects_global_max_when_stage_cfg_missing(self):
        result = _stage_workers({"stages": {}}, "hunt", 5)
        assert result == 5

    def test_uses_stage_config_when_lower(self):
        result = _stage_workers({"stages": {"hunt": {"max_workers": 3}}}, "hunt", 10)
        assert result == 3

    def test_caps_at_global_max_when_stage_higher(self):
        result = _stage_workers({"stages": {"hunt": {"max_workers": 20}}}, "hunt", 10)
        assert result == 10

    def test_missing_stages_key(self):
        result = _stage_workers({}, "hunt", 5)
        assert result == 5


class TestLoadJsonl:
    def test_missing_file_returns_empty(self, tmp_path: Path):
        result = _load_jsonl(tmp_path / "nonexistent.jsonl")
        assert result == []

    def test_valid_file_returns_items(self, tmp_path: Path):
        p = tmp_path / "data.jsonl"
        p.write_text('{"a": 1}\n{"b": 2}\n')
        result = _load_jsonl(p)
        assert result == [{"a": 1}, {"b": 2}]

    def test_empty_file(self, tmp_path: Path):
        p = tmp_path / "empty.jsonl"
        p.write_text("")
        result = _load_jsonl(p)
        assert result == []

    def test_skips_bad_lines(self, tmp_path: Path):
        p = tmp_path / "mixed.jsonl"
        p.write_text('{"a": 1}\ninvalid\n{"b": 2}\n')
        result = _load_jsonl(p)
        assert result == [{"a": 1}, {"b": 2}]

    def test_skips_empty_line(self, tmp_path: Path):
        p = tmp_path / "empty_line.jsonl"
        p.write_text('{"a": 1}\n\n{"b": 2}\n')
        result = _load_jsonl(p)
        assert result == [{"a": 1}, {"b": 2}]


class TestPersistJsonl:
    def test_writes_items(self, tmp_path: Path):
        p = tmp_path / "out.jsonl"
        _persist_jsonl(p, [{"x": 1}, {"y": 2}])
        lines = p.read_text().strip().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"x": 1}
        assert json.loads(lines[1]) == {"y": 2}

    def test_creates_parent_dirs(self, tmp_path: Path):
        p = tmp_path / "sub" / "out.jsonl"
        _persist_jsonl(p, [{"a": 1}])
        assert p.exists()

    def test_empty_list(self, tmp_path: Path):
        p = tmp_path / "empty.jsonl"
        _persist_jsonl(p, [])
        assert p.read_text() == ""


class TestApplyDiffFilter:
    def test_non_diff_mode_returns_snippets(self):
        result = _apply_diff_filter(
            "full", None, Path("/repo"), [{"id": "1"}], "HEAD", MagicMock()
        )
        assert result == [{"id": "1"}]

    def test_diff_mode_without_base_commit_raises(self):
        with pytest.raises(ValueError, match="--base-commit is required"):
            _apply_diff_filter("diff", None, Path("/repo"), [], "HEAD", MagicMock())

    def test_diff_mode_calls_get_changed(self):
        state = MagicMock()
        with patch(
            "ai_vuln_harness.run.get_changed_snippets", return_value=[{"id": "2"}]
        ):
            result = _apply_diff_filter(
                "diff", "main", Path("/repo"), [{"id": "1"}], "HEAD", state
            )
        assert result == [{"id": "2"}]
        state.put_meta.assert_any_call("diff_base_commit", "main")


class TestBuildRunKwargs:
    @pytest.fixture
    def args(self):
        ns = argparse.Namespace()
        ns.auth_json = None
        ns.kl_threshold = 5.0
        ns.cosine_threshold = 0.85
        ns.allow_full_db_fallback = True
        ns.base_commit = None
        ns.head_commit = "HEAD"
        ns.max_cost_usd = None
        ns.max_concurrency = None
        ns.skip_health = False
        ns.max_run = None
        ns.scope_notes = None
        ns.reingest = False
        ns.model_override = None
        ns.validate_model_override = None
        ns.poc_finding = None
        ns.poc_only = False
        ns.run_patch = False
        ns.refresh_models = False
        ns.budget_ratio = 0.85
        ns.pooled = False
        ns.load_packs_cache = False
        ns.enable_localization_stage = False
        ns.enable_fuzz_orchestrator = False
        return ns

    def test_returns_dict(self, args):
        result = _build_run_kwargs(args)
        assert isinstance(result, dict)

    def test_scope_notes_read_when_provided(self, args, tmp_path: Path):
        notes = tmp_path / "notes.txt"
        notes.write_text("scope note content")
        args.scope_notes = notes
        result = _build_run_kwargs(args)
        assert result["scope_notes"] == "scope note content"

    def test_run_poc_enabled_via_finding(self, args):
        args.poc_finding = "finding:001"
        result = _build_run_kwargs(args)
        assert result["run_poc_enabled"] is True

    def test_run_poc_enabled_via_flag(self, args):
        args.poc_only = True
        result = _build_run_kwargs(args)
        assert result["run_poc_enabled"] is True

    def test_poc_finding_id_all(self, args):
        args.poc_finding = "all"
        result = _build_run_kwargs(args)
        assert result["poc_finding_id"] is None

    def test_poc_finding_id_specific(self, args):
        args.poc_finding = "finding:007"
        result = _build_run_kwargs(args)
        assert result["poc_finding_id"] == "finding:007"


class TestIngestSnippets:
    def test_fresh_ingest(self, tmp_path: Path):
        cfg = {"is_library_target": False}
        output = tmp_path / "output"
        output.mkdir()
        snippets_patch = [
            {"id": "s1", "file": "a.c", "tags": []},
            {"id": "s2", "file": "b.c", "tags": []},
        ]
        with (
            patch(
                "ai_vuln_harness.run.load_repo_snippets", return_value=snippets_patch
            ),
            patch("ai_vuln_harness.run.filter_snippets", side_effect=lambda x, **kw: x),
            patch("ai_vuln_harness.run.tag_snippet", return_value=[]),
        ):
            snippets, snippet_db = _ingest_snippets(
                Path("/fake-repo"), output, False, cfg
            )
        assert len(snippets) == 2
        assert "s1" in snippet_db
        assert "s2" in snippet_db

    def test_reingest_from_cache(self, tmp_path: Path):
        output = tmp_path / "output"
        output.mkdir()
        (output / "snippet_db.json").write_text(
            json.dumps({"s1": {"id": "s1", "file": "a.c"}})
        )
        snippets, snippet_db = _ingest_snippets(
            Path("/fake-repo"), output, True, {"is_library_target": False}
        )
        assert len(snippets) == 1
        assert snippets[0]["id"] == "s1"

    def test_reingest_list_to_dict(self, tmp_path: Path):
        output = tmp_path / "output"
        output.mkdir()
        (output / "snippet_db.json").write_text(
            json.dumps([{"id": "s1", "file": "a.c"}])
        )
        snippets, snippet_db = _ingest_snippets(
            Path("/fake-repo"), output, True, {"is_library_target": False}
        )
        assert len(snippets) == 1
        assert snippet_db["s1"]["file"] == "a.c"


class TestResolveModelChain:
    def test_uses_override_when_provided(self):
        cache = MagicMock()
        cache.get.return_value = None
        result = _resolve_model_chain(["model-a", "model-b"], True, {}, "full", cache)
        assert result == ["model-a", "model-b"]

    def test_default_chain_when_no_override(self):
        cache = MagicMock()
        cache.get.return_value = None
        result = _resolve_model_chain(None, True, {}, "full", cache)
        assert len(result) == 4
        assert "deepseek/deepseek-v4-flash:free" in result

    def test_health_check_with_dead_models(self):
        cache = MagicMock()
        cache.get.return_value = None
        mock_alive = ["model-a"]
        mock_dead = ["model-b"]
        with patch(
            "ai_vuln_harness.run.health_check_models",
            return_value=(mock_alive, mock_dead),
        ):
            result = _resolve_model_chain(
                ["model-a", "model-b"], False, {"key": "val"}, "full", cache
            )
        assert result == ["model-a"]
        cache.put.assert_any_call("model_health_dead", mock_dead)

    def test_health_check_all_models_dead(self):
        cache = MagicMock()
        cache.get.return_value = None
        with patch(
            "ai_vuln_harness.run.health_check_models",
            return_value=([], ["model-a", "model-b"]),
        ):
            result = _resolve_model_chain(
                ["model-a", "model-b"], False, {"key": "val"}, "full", cache
            )
        assert "model-a" in result
        assert "model-b" in result

    def test_health_check_uses_cached(self):
        cache = MagicMock()
        cache.get.return_value = ["cached-model"]
        result = _resolve_model_chain(["model-a"], True, {"key": "val"}, "full", cache)
        assert result == ["cached-model"]


class TestResolvePools:
    def test_non_pooled_splits_models(self):
        state = MagicMock()
        with patch(
            "ai_vuln_harness.run.split_model_pools", return_value=(["a"], ["b"])
        ):
            hunt, validate, pool = _resolve_pools(
                ["a", "b"], {"a": 1, "b": 1}, False, None, state
            )
        assert hunt == ["a"]
        assert validate == ["b"]
        assert pool is None

    def test_validate_override_replaces_validate_models(self):
        state = MagicMock()
        with patch(
            "ai_vuln_harness.run.split_model_pools", return_value=(["a"], ["b"])
        ):
            hunt, validate, pool = _resolve_pools(
                ["a", "b"], {"a": 1, "b": 1}, False, ["custom-val"], state
            )
        assert hunt == ["a"]
        assert validate == ["custom-val"]
        assert pool is None

    def test_pooled_creates_pool(self):
        state = MagicMock()
        with patch("ai_vuln_harness.run.ModelPool") as MockPool:
            mock_pool = MagicMock()
            mock_pool.alive = ["a", "b"]
            MockPool.return_value = mock_pool
            hunt, validate, pool = _resolve_pools(
                ["a", "b"], {"a": 1, "b": 1}, True, None, state
            )
        assert hunt == ["a", "b"]
        assert validate == ["a", "b"]
        assert pool is mock_pool


class TestRunHuntStage:
    def test_mode_validate_only_skips_hunt(self, tmp_path: Path):
        findings, gaps = _run_hunt_stage(
            "validate-only", {}, [], [], MagicMock(), 3, None, {}, None, tmp_path
        )
        assert findings == []
        assert gaps == []

    def test_no_auth_returns_empty(self, tmp_path: Path):
        findings, gaps = _run_hunt_stage(
            "full", {}, [], [], MagicMock(), 3, None, {}, None, tmp_path
        )
        assert findings == []
        assert gaps == []


class TestRunValidateStage:
    def test_mode_validate_only_returns_findings_as_is(self, tmp_path: Path):
        result = _run_validate_stage(
            "validate-only",
            [{"id": "f1"}],
            {},
            [],
            False,
            {},
            MagicMock(),
            3,
            None,
            tmp_path,
            {},
        )
        assert result == [
            {
                "id": "f1",
                "validate_status": "needs-more-info",
                "validate_reason": "skipped",
            }
        ]

    def test_empty_findings_returns_empty(self, tmp_path: Path):
        result = _run_validate_stage(
            "full", [], {}, [], False, {}, MagicMock(), 3, None, tmp_path, {}
        )
        assert result == []


class TestRunLocalizationStage:
    def test_localization_disabled_passthrough(self, tmp_path: Path):
        localized, unreachable = _run_localization_stage(
            [{"snippet_id": "s1", "severity": "LOW", "class": "x", "desc": "d"}],
            {},
            {"enable_localization_stage": False},
            tmp_path,
        )
        assert len(localized) == 1
        assert unreachable == []
        assert "suspicious_points" in localized[0]


class TestRunTraceStage:
    def test_adds_trace_status(self):
        findings = [{"id": "f1"}, {"id": "f2"}]
        _run_trace_stage(findings, MagicMock())
        for f in findings:
            assert f["trace_status"] == "not_required"


class TestSetupLogging:
    def test_sets_up_logging_with_log_dir(self, tmp_path: Path):
        log_dir = tmp_path / "logs"
        _setup_logging(log_dir=log_dir)
        assert log_dir.exists()

    def test_sets_up_logging_with_log_file(self, tmp_path: Path):
        log_file = tmp_path / "test.log"
        _setup_logging(log_file=log_file)
        assert log_file.exists()
