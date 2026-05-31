"""Red-team break tests for templates/v1.

Targeted PoCs for bugs found during adversarial code audit.
Each test demonstrates a specific vulnerability, crash, or logic error.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ── Module imports under test ────────────────────────────────────────────────
from ai_vuln_harness.stages.runtime import (
    JsonCache,
    load_auth_config,
    CrossRunRegression,
    split_model_pools,
)
from ai_vuln_harness.stages.contracts import validate_subset_schema, standardize_finding
from ai_vuln_harness.stages.suppressions import SuppressionRegistry
from ai_vuln_harness.stages.parser import parse_findings
from ai_vuln_harness.stages.voting import merge_hunter_outputs
from ai_vuln_harness.stages.shield import (
    build_call_graph,
    verify_call_path,
    deduplicate_semantic,
    detect_hallucination,
    detect_hallucination_kl,
    cosine_similarity,
    _normalise,
    _token_freqs,
    kl_divergence,
)
from ai_vuln_harness.stages.validate import is_api_by_design, _contains_vuln_signal
from ai_vuln_harness.stages.report import (
    bucket_finding,
    _downgrade_severity,
    deduplicate,
)
from ai_vuln_harness.stages.coordinator import build_context_packs
from ai_vuln_harness.stages.recon import _scan_git_security_patches, _find_sibling_files
from ai_vuln_harness.stages.ingestor import tag_snippet


# ===================================================================
# 1. JsonCache — crashes on array JSON file                  HIGH
# ===================================================================
class JsonCacheArrayCrashFixed(unittest.TestCase):
    def test_cache_file_with_array_returns_none(self):
        d = tempfile.mkdtemp()
        path = Path(d) / "cache.json"
        path.write_text("[]")
        cache = JsonCache(path)
        self.assertIsNone(
            cache.get("anything"),
            "FIXED: array cache file returns None instead of crashing",
        )


# ===================================================================
# 2. is_api_by_design — false positive on innocent names     MEDIUM
# ===================================================================
class IsApiByDesignFixedFalsePositives(unittest.TestCase):
    def test_write_secret_no_longer_api_by_design(self):
        finding = {"class": "overflow", "desc": "buffer overflow in write_secret"}
        snippet = {"name": "write_secret", "content": "int write_secret() { ... }"}
        self.assertFalse(
            is_api_by_design(finding, snippet),
            "FIXED: write_secret is not a standard API name",
        )

    def test_execute_payload_no_longer_api_by_design(self):
        finding = {"class": "overflow", "desc": "overflow in execute_payload"}
        snippet = {
            "name": "execute_payload",
            "content": "void execute_payload() { ... }",
        }
        self.assertFalse(
            is_api_by_design(finding, snippet),
            "FIXED: execute_payload is not a standard API name",
        )

    def test_read_etc_passwd_no_longer_api_by_design(self):
        finding = {"class": "overflow", "desc": "overflow in read_etc_passwd"}
        snippet = {
            "name": "read_etc_passwd",
            "content": "void read_etc_passwd() { ... }",
        }
        self.assertFalse(
            is_api_by_design(finding, snippet),
            "FIXED: read_etc_passwd is not a standard API name",
        )

    def test_read_config_no_longer_api(self):
        finding = {"class": "path-traversal", "desc": "read config file"}
        snippet = {"name": "read_config", "content": "int read_config() { ... }"}
        self.assertFalse(
            is_api_by_design(finding, snippet),
            "FIXED: read_config is not a standard API name",
        )

    def test_exact_printf_still_api_by_design(self):
        finding = {"class": "format-string", "desc": "format string in printf"}
        snippet = {
            "name": "printf",
            "content": "int printf(const char *fmt, ...) { ... }",
        }
        self.assertTrue(
            is_api_by_design(finding, snippet),
            "printf is still correctly API-by-design",
        )

    def test_exact_write_still_api_by_design(self):
        finding = {"class": "overflow", "desc": "buffer overflow in write"}
        snippet = {"name": "write", "content": "ssize_t write(int fd, ...) { ... }"}
        self.assertTrue(
            is_api_by_design(finding, snippet), "write is still correctly API-by-design"
        )


# ===================================================================
# 3. SuppressionRegistry._key — delimiter collision          LOW
# ===================================================================
class SuppressionKeyCollisionFixed(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = Path(self.tmp) / "suppressions.json"

    def test_delimiter_no_longer_collides(self):
        reg = SuppressionRegistry(self.path)
        reg.add({"snippet_id": "a::", "class": "b", "validate_reason": "fp1"})
        reg.add({"snippet_id": "a", "class": "::b", "validate_reason": "fp2"})
        self.assertEqual(
            len(reg), 2, "FIXED: distinct (snippet_id, class) pairs no longer collide"
        )


# ===================================================================
# 4. parse_findings — deeply nested objects not reached     MEDIUM
# ===================================================================
class ParseFindingsDeeplyNestedFixed(unittest.TestCase):
    def test_finding_inside_nested_object_now_extracted(self):
        text = json.dumps(
            {
                "outer": {
                    "inner": {
                        "snippet_id": "s1",
                        "class": "overflow",
                        "severity": "HIGH",
                        "desc": "deep",
                        "status": "raw",
                        "poc_confirmed": False,
                    }
                }
            }
        )
        f, g = parse_findings(text)
        self.assertEqual(
            len(f), 1, "FIXED: nested findings are now extracted recursively"
        )


# ===================================================================
# 5. split_model_pools — duplicate models in input          LOW
# ===================================================================
class SplitModelPoolsDuplicatesFixed(unittest.TestCase):
    def test_duplicate_models_deduplicated(self):
        hunt, validate = split_model_pools(["deepseek", "deepseek", "qwen"])
        self.assertEqual(
            hunt.count("deepseek"), 1, "FIXED: duplicate models are deduplicated"
        )


# ===================================================================
# 6. validate_subset_schema — accepts tuples as arrays     LOW
# ===================================================================
class ValidateSubsetSchemaTuple(unittest.TestCase):
    def test_tuple_not_detected_as_array(self):
        schema = {"type": "array", "items": {"type": "string"}}
        errors = validate_subset_schema((1, 2, 3), schema)
        self.assertIn("expected array", errors[0])


# ===================================================================
# 7. load_auth_config — loads same file twice when explicit  LOW
#     path matches default path
# ===================================================================
class AuthConfigDedup(unittest.TestCase):
    def setUp(self):
        self._env_patch = patch.dict(
            os.environ,
            {
                "OPENROUTER_API_KEY": "",
                "GROQ_API_KEY": "",
                "CEREBRAS_API_KEY": "",
                "GOOGLE_API_KEY": "",
                "ZEN_API_KEY": "",
            },
        )
        self._env_patch.start()

    def tearDown(self):
        self._env_patch.stop()

    def test_exact_path_same_as_default_loaded_once(self):
        d = tempfile.mkdtemp()
        auth_file = Path(d) / "auth.json"
        auth_file.write_text(json.dumps({"openrouter": "sk-test"}))
        # If explicit_path == script_dir / 'auth.json', it's loaded twice
        config = load_auth_config(explicit_path=auth_file, script_dir=Path(d))
        self.assertEqual(config.get("openrouter"), "sk-test")


# ===================================================================
# 8. Cosine similarity — NaN from zero vectors              MEDIUM
# ===================================================================
class CosineSimilarityNan(unittest.TestCase):
    def test_zero_vector_produces_zero(self):
        result = cosine_similarity([0.0, 0.0], [0.0, 0.0])
        self.assertEqual(result, 0.0)

    def test_single_zero_vector_produces_zero(self):
        result = cosine_similarity([1.0, 0.0], [0.0, 0.0])
        self.assertEqual(result, 0.0)


# ===================================================================
# 9. deduplicate_semantic — single finding doesn't crash    LOW
# ===================================================================
class DeduplicateSemanticEdge(unittest.TestCase):
    def test_single_finding_returns_unchanged(self):
        findings = [
            {
                "snippet_id": "s1",
                "class": "overflow",
                "severity": "HIGH",
                "desc": "test overflow",
            }
        ]
        result = deduplicate_semantic(findings, threshold=0.85)
        self.assertEqual(len(result), 1)

    def test_empty_desc_does_not_crash(self):
        findings = [
            {"snippet_id": "s1", "class": "overflow", "severity": "HIGH", "desc": ""},
            {"snippet_id": "s2", "class": "overflow", "severity": "HIGH", "desc": ""},
        ]
        result = deduplicate_semantic(findings, threshold=0.85)
        self.assertEqual(len(result), 2)  # two different snippet_ids kept


# ===================================================================
# 10. detect_hallucination — missing_desc ratio logic       LOW
# ===================================================================
class HallucinationDescRatio(unittest.TestCase):
    def test_empty_desc_tokens_does_not_crash(self):
        snippet = {"content": "void foo() { int x; }"}
        finding = {"desc": "ab", "call_path": []}  # tokens < 4 chars → none extracted
        detected, reason = detect_hallucination(finding, snippet)
        self.assertFalse(detected)


# ===================================================================
# 11. is_api_by_design — 'xss' in class falsely matches     MEDIUM
#     due to overly broad patterns
# ===================================================================
class IsApiByDesignBroadMatchFixed(unittest.TestCase):
    def test_execute_query_no_longer_false_positive(self):
        finding = {"class": "xss", "desc": "xss in execute_query"}
        snippet = {"name": "execute_query", "content": "def execute_query(sql): pass"}
        self.assertFalse(
            is_api_by_design(finding, snippet),
            "FIXED: execute_query is not a standard API name",
        )


# ===================================================================
# 12. CrossRunRegression — empty history                     LOW
# ===================================================================
class CrossRunRegressionEmpty(unittest.TestCase):
    def test_no_history_no_drift(self):
        d = tempfile.mkdtemp()
        path = Path(d) / "history.jsonl"
        crr = CrossRunRegression(path)
        signals = crr.detect_drift(window=5, threshold=0.15)
        self.assertEqual(signals, [])

    def test_single_record_no_drift(self):
        d = tempfile.mkdtemp()
        path = Path(d) / "history.jsonl"
        path.write_text(
            '{"timestamp": "t1", "total_findings": 5, "class_counts": {"x": 5}}\n'
        )
        crr = CrossRunRegression(path)
        signals = crr.detect_drift(window=5, threshold=0.15)
        self.assertEqual(signals, [])


# ===================================================================
# 13. detect_hallucination — missing path name edge case    MEDIUM
# ===================================================================
class HallucinationPathRatioFixed(unittest.TestCase):
    def test_four_char_desc_tokens_now_checked(self):
        snippet = {"content": "int x = 0;"}
        finding = {"desc": "size error bug data state", "call_path": []}
        detected, _ = detect_hallucination(finding, snippet)
        self.assertTrue(
            detected, 'FIXED: 4-5 char desc tokens like "size" now trigger desc check'
        )

    def test_three_char_call_path_names_now_checked(self):
        snippet = {"content": "void foo() { int x; }"}
        finding = {"desc": "bug in code", "call_path": ["len", "bar"]}
        detected, reason = detect_hallucination(finding, snippet)
        self.assertTrue(
            detected,
            'FIXED: 3-char call_path names like "len"/"bar" now trigger path check',
        )


# ===================================================================
# 14. standardize_finding — doesn't set snippet_id default  LOW
# ===================================================================
class StandardizeFindingMissingSnippetId(unittest.TestCase):
    def test_missing_snippet_id_is_not_set(self):
        result = standardize_finding({"class": "overflow", "severity": "HIGH"})
        self.assertNotIn("snippet_id", result)


# ===================================================================
# 15. _contains_vuln_signal — non-zero exit code triggers   LOW
#     even for benign exits
# ===================================================================
class ContainsVulnSignalEdgeFixed(unittest.TestCase):
    def test_exit_code_1_no_longer_vuln(self):
        self.assertFalse(
            _contains_vuln_signal("all good", 1), "FIXED: exit code 1 is not a signal"
        )

    def test_exit_code_neg_one_still_vuln(self):
        self.assertTrue(_contains_vuln_signal("", -1))


# ===================================================================
# 16. build_call_graph — empty names produce empty key       LOW
# ===================================================================
class BuildCallGraphEdge(unittest.TestCase):
    def test_no_name_no_id_does_not_add_to_graph(self):
        snippets = [{"callees": ["foo"]}]
        graph = build_call_graph(snippets)
        self.assertEqual(graph, {})


# ===================================================================
# 17. merge_hunter_outputs — empty snippet_id skipped       LOW
# ===================================================================
class MergeHunterOutputsEdge(unittest.TestCase):
    def test_empty_snippet_id_skipped(self):
        outputs = [
            [{"snippet_id": "", "class": "overflow", "severity": "HIGH"}],
            [{"snippet_id": "", "class": "overflow", "severity": "HIGH"}],
        ]
        promoted, suppressed = merge_hunter_outputs(outputs, min_votes=2)
        self.assertEqual(len(promoted), 0)

    def test_single_run_returns_all_with_vote_count_1(self):
        outputs = [[{"snippet_id": "s1", "class": "overflow", "severity": "HIGH"}]]
        promoted, suppressed = merge_hunter_outputs(outputs, min_votes=2)
        self.assertEqual(len(promoted), 1)
        self.assertEqual(promoted[0]["vote_count"], 1)


# ===================================================================
# 18. build_context_packs — negative token_count crashes     MEDIUM
# ===================================================================
class BuildContextPacksNegativeToken(unittest.TestCase):
    def test_negative_token_count_does_not_crash(self):
        snippets = [{"file": "a.c", "token_count": -100}]
        tasks = [
            {
                "task_id": "t1",
                "domain": "mem",
                "attack_class": "mem",
                "target_files": ["a.c"],
                "rationale": "r",
                "priority": "high",
            }
        ]
        packs = build_context_packs(snippets, tasks, budget_tokens=100)
        self.assertEqual(len(packs), 1)


# ===================================================================
# 19. bucket_finding — missing severity                      LOW
# ===================================================================
class BucketFindingEdge(unittest.TestCase):
    def test_missing_severity_defaults_to_backlog(self):
        f = {
            "snippet_id": "s1",
            "class": "overflow",
            "desc": "d",
            "status": "raw",
            "poc_confirmed": False,
        }
        bucket, _ = bucket_finding(f, trace_required=False)
        self.assertEqual(bucket, "backlog")

    def test_missing_status_defaults_to_backlog(self):
        f = {
            "snippet_id": "s1",
            "class": "overflow",
            "severity": "CRITICAL",
            "desc": "d",
            "poc_confirmed": True,
        }
        bucket, _ = bucket_finding(f, trace_required=False)
        self.assertEqual(bucket, "backlog")


# ===================================================================
# 20. _scan_git_security_patches — only checks 500 commits   MEDIUM
# ===================================================================
class GitScanLimit(unittest.TestCase):
    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_phase1_checks_2000_commits(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        _scan_git_security_patches("/repo")
        call_args = mock_run.call_args[0][0]
        self.assertIn("--max-count=2000", call_args)

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_security_commit_beyond_window_missed(self, mock_run):
        security_commits = "\n".join(f"abc{i} feat: commit {i}" for i in range(500))
        # No security pattern in first 500
        mock_run.return_value = MagicMock(returncode=0, stdout=security_commits)
        result = _scan_git_security_patches("/repo")
        self.assertEqual(result, set())


# ===================================================================
# 21. _find_sibling_files — patched file with extension-only name LOW
# ===================================================================
class FindSiblingFilesEdge(unittest.TestCase):
    def test_patched_file_with_no_stem(self):
        # Path('.gitignore').stem = '.gitignore', parent = '.'
        patched = {".gitignore"}
        all_files = {".gitignore", "src/", "Makefile"}
        result = _find_sibling_files(patched, all_files)
        self.assertIsInstance(result, set)


# ===================================================================
# 22. tag_snippet — case sensitivity of printf pattern       LOW
# ===================================================================
class TagSnippetCaseEdge(unittest.TestCase):
    def test_uppercase_printf_still_matches(self):
        tags = tag_snippet({"content": 'PRINTF("hello")'})
        self.assertIn("format-string", tags)

    def test_lowercase_printf_matches(self):
        tags = tag_snippet({"content": 'printf("hello")'})
        self.assertIn("format-string", tags)


# ===================================================================
# 23. kl_divergence — epsilon prevents inf but can overflow  LOW
# ===================================================================
class KlDivergenceEdge(unittest.TestCase):
    def test_identical_distributions_produce_zero(self):
        d = {"a": 0.5, "b": 0.5}
        self.assertAlmostEqual(kl_divergence(d, d), 0.0)

    def test_disjoint_vocab_very_large_kl(self):
        p = {"a": 1.0}
        q = {"b": 1.0}
        kl = kl_divergence(p, q)
        # epsilon = 1e-8, so KL = 1.0 * log(1.0 / 1e-8) = log(1e8) ≈ 18.42
        self.assertAlmostEqual(kl, 18.420680743952367, places=4)


# ===================================================================
# 24. _load_history — malformed JSON line skipped            LOW
# ===================================================================
class LoadHistoryMalformed(unittest.TestCase):
    def test_corrupt_line_skipped_quietly(self):
        d = tempfile.mkdtemp()
        path = Path(d) / "history.jsonl"
        path.write_text(
            '{"valid": true, "class_counts": {"x": 1}}\nnot json\n{"valid": true, "class_counts": {"y": 1}}\n'
        )
        crr = CrossRunRegression(path)
        history = crr._load_history()
        self.assertEqual(len(history), 2)


# ===================================================================
# 25. Cosine similarity — vector length mismatch raises       LOW
# ===================================================================
class CosineSimilarityMismatch(unittest.TestCase):
    def test_different_lengths_raise_value_error(self):
        with self.assertRaises(ValueError):
            cosine_similarity([1.0, 0.0], [1.0])


# ===================================================================
# 26. parse_findings — list-only JSON returns empty findings  MEDIUM
# ===================================================================
class ParseFindingsListOnly(unittest.TestCase):
    def test_flat_list_of_findings_parsed_correctly(self):
        text = json.dumps(
            [
                {
                    "snippet_id": "s1",
                    "class": "overflow",
                    "severity": "HIGH",
                    "desc": "d",
                    "status": "raw",
                    "poc_confirmed": False,
                },
            ]
        )
        f, g = parse_findings(text)
        self.assertEqual(len(f), 1)

    def test_list_of_nondicts_produces_no_findings(self):
        text = json.dumps([1, 2, 3])
        f, g = parse_findings(text)
        self.assertEqual(len(f), 0)


# ===================================================================
# 27. deduplicate — duplicate keys with different file paths  LOW
# ===================================================================
class DeduplicateEdge(unittest.TestCase):
    def test_same_class_diff_file_not_deduped(self):
        findings = [
            {
                "snippet_id": "s1",
                "class": "overflow",
                "severity": "HIGH",
                "file": "a.c",
            },
            {
                "snippet_id": "s2",
                "class": "overflow",
                "severity": "HIGH",
                "file": "b.c",
            },
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 2)


# ===================================================================
# 28. verify_call_path — empty graph returns true           LOW
# ===================================================================
class VerifyCallPathEdge(unittest.TestCase):
    def test_empty_graph_returns_true(self):
        ok, reason = verify_call_path({"call_path": ["main", "foo"]}, {})
        self.assertTrue(ok)
        self.assertEqual(reason, "no-graph-data")

    def test_single_node_in_graph(self):
        graph = {"main": set()}
        ok, reason = verify_call_path({"call_path": ["main"]}, graph)
        self.assertTrue(ok)
        self.assertEqual(reason, "single-node-present")


# ===================================================================
# 29. _downgrade_severity — unknown severity              LOW
# ===================================================================
class DowngradeSeverityEdge(unittest.TestCase):
    def test_unknown_severity_goes_to_informational(self):
        self.assertEqual(_downgrade_severity("GODLIKE"), "INFORMATIONAL")

    def test_critical_downgrades_to_high(self):
        self.assertEqual(_downgrade_severity("CRITICAL"), "HIGH")


# ===================================================================
# 30. detect_hallucination_kl — content is None           LOW
# ===================================================================
class DetectHallucinationKlNoneSnippet(unittest.TestCase):
    def test_snippet_with_no_content(self):
        snippet = {}
        finding = {"desc": "bug in bar", "call_path": ["bar"]}
        detected, reason = detect_hallucination_kl(finding, snippet)
        self.assertFalse(detected)
        self.assertEqual(reason, "no-snippet-content")

    def test_no_content_with_present_q_counts(self):
        snippet = {"content": ""}
        finding = {"desc": "bug in bar", "call_path": ["bar"]}
        detected, reason = detect_hallucination_kl(finding, snippet)
        self.assertFalse(detected)
        self.assertEqual(reason, "no-snippet-content")

    def test_no_desc_still_no_crash(self):
        snippet = {"content": "void foo() { int x; }"}
        finding = {"desc": "", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet)
        self.assertFalse(detected)


class KlDivergenceEdgeProbs(unittest.TestCase):
    def test_empty_normalise_returns_empty_dict(self):
        result = _normalise(__import__("collections").Counter())
        self.assertEqual(result, {})

    def test_empty_token_freqs_returns_empty_counter(self):
        result = _token_freqs("   ")
        self.assertEqual(result, __import__("collections").Counter())


if __name__ == "__main__":
    unittest.main()
