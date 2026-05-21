"""Additional adversarial tests across all subsystems not covered by
existing adversarial test files.

Focuses on:
- Shield: call graph cycles, self-loops, case-tricks, boundary thresholds
- Runtime: class_distribution fallback chain, CrossRunRegression extremes
- Deepening: parser coercion paths, voting float keys, suppressions
  concurrency patterns, contracts missing-type schemas
"""

import json
import math
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from stages.contracts import standardize_finding, validate_subset_schema
from stages.coordinator import build_context_packs
from stages.ingestor import (
    detect_external_input,
    detect_integer_arith_untrusted,
    filter_snippets,
    should_exclude_path,
    tag_snippet,
)
from stages.parser import _extract_objects, parse_findings
from stages.report import _downgrade_severity, bucket_finding, deduplicate
from stages.runtime import (
    CrossRunRegression,
    _kl_divergence,
    class_distribution,
    js_divergence,
    load_auth_config,
    split_model_pools,
)
import json as _json

from stages.shield import (
    _reachable_from,
    annotate_call_path_verification,
    annotate_hallucination,
    build_call_graph,
    detect_hallucination,
    detect_hallucination_kl,
    filter_unreachable,
    verify_call_path,
)
from stages.suppressions import SuppressionRegistry
from stages.validate import (
    _contains_vuln_signal,
    _is_c_or_cpp,
    is_api_by_design,
    requires_trace_before_fix_now,
)
from stages.voting import merge_hunter_outputs


# ===================================================================
# SHIELD — call graph adversarial
# ===================================================================

class ShieldCallGraphCycleTests(unittest.TestCase):
    """Call graphs with cycles, self-loops, and edge-case names."""

    def test_cycle_in_graph(self):
        snippets = [
            {'name': 'a', 'callees': ['b']},
            {'name': 'b', 'callees': ['c']},
            {'name': 'c', 'callees': ['a']},
        ]
        g = build_call_graph(snippets)
        self.assertIn('a', g)
        self.assertIn('b', g['a'])
        self.assertIn('c', g['b'])
        self.assertIn('a', g['c'])

    def test_self_loop_node(self):
        snippets = [{'name': 'recurse', 'callees': ['recurse']}]
        g = build_call_graph(snippets)
        self.assertIn('recurse', g['recurse'])

    def test_call_path_with_cycle_verified(self):
        graph = {'a': {'b'}, 'b': {'c'}, 'c': {'a'}}
        ok, reason = verify_call_path({'call_path': ['a', 'b', 'c', 'a']}, graph)
        self.assertTrue(ok)
        self.assertIn('verified', reason)

    def test_graph_with_no_names(self):
        snippets = [{'callees': ['x']}, {'name': ''}]
        g = build_call_graph(snippets)
        self.assertIsInstance(g, dict)

    def test_name_from_id_fallback(self):
        snippets = [{'id': 'handler_a', 'callees': ['helper_b']}]
        g = build_call_graph(snippets)
        self.assertIn('handler_a', g)

    def test_case_mismatch_in_path_verified(self):
        graph = {'http_handler': {'parse_request'}}
        ok, reason = verify_call_path({'call_path': ['HTTP_Handler', 'Parse_Request']}, graph)
        self.assertTrue(ok)


class ShieldReachabilityEdgeTests(unittest.TestCase):
    """Static reachability with adversarial entry points/targets."""

    def test_entry_case_insensitive(self):
        graph = {'main': {'handler'}, 'handler': {'sink'}}
        r, u = filter_unreachable(
            [{'snippet_id': 'sink', 'call_path': ['sink']}],
            graph, ['Main'],
        )
        self.assertEqual(len(r), 1)

    def test_target_from_call_path_not_snippet_id(self):
        graph = {'entry': {'a'}, 'a': {'b'}}
        r, u = filter_unreachable(
            [{'snippet_id': 'orphan', 'call_path': ['entry', 'a', 'b']}],
            graph, ['entry'],
        )
        self.assertEqual(len(r), 1)

    def test_unreachable_due_to_max_hops(self):
        graph = {'a': {'b'}, 'b': {'c'}, 'c': {'d'}, 'd': {'e'}}
        r, u = filter_unreachable(
            [{'snippet_id': 'e', 'call_path': ['e']}],
            graph, ['a'], max_hops=2,
        )
        self.assertEqual(len(u), 1)

    def test_empty_targets_set_reachable_as_fail_open(self):
        graph = {'main': {'helper'}}
        r, u = filter_unreachable(
            [{'snippet_id': ''}], graph, ['main'],
        )
        self.assertEqual(len(u), 1)

    def test_non_string_entry_points(self):
        graph = {'main': {'sink'}}
        with self.assertRaises(AttributeError):
            filter_unreachable(
                [{'snippet_id': 'sink', 'call_path': ['sink']}],
                graph, [42],
            )

    def test_annotate_call_path_all_missing(self):
        graph = {}
        findings = [{'no_call_path_here': True}]
        result = annotate_call_path_verification(findings, graph)
        self.assertIn('call_path_verified', result[0])
        self.assertIn('call_path_reason', result[0])


class ShieldHallucinationBoundaryTests(unittest.TestCase):
    """Boundary conditions for the basic detect_hallucination."""

    def test_exactly_60_percent_desc_tokens_missing(self):
        snippet = {'content': 'void aaa_111() { }'}
        finding = {'desc': 'aaa_111 bbb_222 ccc_333', 'call_path': []}
        detected, reason = detect_hallucination(finding, snippet)
        self.assertTrue(detected)
        self.assertIn('desc tokens', reason)

    def test_exactly_40_percent_desc_tokens_missing_passes(self):
        snippet = {'content': 'void aaa_111() { bbb_222(); ccc_333(); }'}
        finding = {'desc': 'aaa_111 bbb_222 ccc_333 ddd_444', 'call_path': []}
        detected, reason = detect_hallucination(finding, snippet)
        self.assertFalse(detected)

    def test_exactly_70_percent_path_names_missing(self):
        snippet = {'content': 'void aaa_111() { }'}
        finding = {'desc': '', 'call_path': ['aaa_111', 'xxx_yyy', 'zzz_www', 'vvv_uuu', 'ttt_sss']}
        detected, reason = detect_hallucination(finding, snippet)
        self.assertTrue(detected)
        self.assertIn('call_path', reason)

    def test_call_path_names_mostly_present(self):
        snippet = {'content': 'void aaa_111() { bbb_222(); ccc_333(); }'}
        finding = {'desc': '', 'call_path': ['aaa_111', 'bbb_222', 'ccc_333', 'extra_func']}
        detected, reason = detect_hallucination(finding, snippet)
        self.assertFalse(detected)

    def test_desc_with_only_short_tokens_skipped(self):
        snippet = {'content': 'void long_function_name() { }'}
        finding = {'desc': 'a b c d', 'call_path': []}
        detected, reason = detect_hallucination(finding, snippet)
        self.assertFalse(detected)
        self.assertEqual(reason, 'ok')

    def test_hallucinated_with_callers_callees_matching(self):
        snippet = {'content': 'void sink_func() { }', 'callers': ['main']}
        finding = {'desc': '', 'call_path': ['main', 'sink_func']}
        detected, reason = detect_hallucination(finding, snippet)
        self.assertFalse(detected)

    def test_hallucinated_desc_but_call_path_ok(self):
        snippet = {'content': 'void real_func() { real_helper(); }'}
        finding = {'desc': 'fake_function hallucinated_bug', 'call_path': ['real_func', 'real_helper']}
        detected, reason = detect_hallucination(finding, snippet)
        self.assertTrue(detected)
        self.assertIn('desc tokens', reason)


class ShieldKlEdgeTests(unittest.TestCase):
    """Additional KL-divergence hallucination detection edge cases."""

    def test_kl_infinite_threshold_blocks_all(self):
        snippet = {'content': 'void real_func() { }'}
        finding = {'desc': 'completely unrelated fake overflow', 'call_path': []}
        detected, _ = detect_hallucination_kl(finding, snippet, threshold=1e9)
        self.assertFalse(detected)

    def test_kl_threshold_equal_to_zero_still_flags_at_zero(self):
        snippet = {'content': 'real_func overflow_here'}
        finding = {'desc': 'real_func overflow_here', 'call_path': []}
        detected, _ = detect_hallucination_kl(finding, snippet, threshold=0.0)
        self.assertTrue(detected)


class ShieldDeduplicateEdgeTests(unittest.TestCase):
    """Edge cases for semantic deduplication."""

    def test_single_token_descriptions(self):
        findings = [
            {'snippet_id': 'a', 'desc': 'overflow', 'severity': 'HIGH'},
            {'snippet_id': 'b', 'desc': 'overflow', 'severity': 'MEDIUM'},
        ]
        from stages.shield import deduplicate_semantic
        result = deduplicate_semantic(findings, threshold=1.0)
        self.assertEqual(len(result), 1)

    def test_no_common_vocab_at_all(self):
        findings = [
            {'snippet_id': 'a', 'desc': 'aaaa_1111', 'severity': 'HIGH'},
            {'snippet_id': 'b', 'desc': 'bbbb_2222', 'severity': 'HIGH'},
        ]
        from stages.shield import deduplicate_semantic
        result = deduplicate_semantic(findings, threshold=0.0)
        self.assertEqual(len(result), 1)

    def test_cosine_empty_vectors(self):
        from stages.shield import cosine_similarity
        self.assertEqual(cosine_similarity([], []), 0.0)


# ===================================================================
# RUNTIME — class_distribution, CrossRunRegression, auth
# ===================================================================

class RuntimeClassDistributionTests(unittest.TestCase):
    """Adversarial edge cases for class_distribution."""

    def test_empty_findings(self):
        result = class_distribution([])
        self.assertEqual(result, Counter())

    def test_none_findings_list(self):
        result = class_distribution([{}])
        self.assertEqual(result.get('unknown'), 1)

    def test_class_key_fallbacks(self):
        f1 = {'class': 'overflow'}
        f2 = {'attack_class': 'uaf'}
        f3 = {'cwe_id': 'CWE-119'}
        f4 = {}
        result = class_distribution([f1, f2, f3, f4])
        self.assertEqual(result['overflow'], 1)
        self.assertEqual(result['uaf'], 1)
        self.assertEqual(result['cwe-119'], 1)
        self.assertEqual(result['unknown'], 1)

    def test_class_key_precedence(self):
        f = {'class': 'overflow', 'attack_class': 'uaf'}
        result = class_distribution([f])
        self.assertEqual(result['overflow'], 1)
        self.assertNotIn('uaf', result)

    def test_none_values_in_keys(self):
        f = {'class': None, 'attack_class': None}
        result = class_distribution([f])
        self.assertEqual(result['unknown'], 1)


class RuntimeCrossRunRegressionEdgeTests(unittest.TestCase):
    """Adversarial CrossRunRegression edge cases."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / 'history.jsonl'

    def tearDown(self):
        self._tmp.cleanup()

    def test_detect_drift_with_window_larger_than_history(self):
        r = CrossRunRegression(self.path)
        r.record_run('t1', [{'class': 'a'}])
        r.record_run('t2', [{'class': 'a'}])
        signals = r.detect_drift(window=100, threshold=0.15)
        self.assertEqual(signals, [])

    def test_record_run_with_metadata(self):
        r = CrossRunRegression(self.path)
        record = r.record_run('t1', [{'class': 'a'}], metadata={'version': 'v2'})
        self.assertEqual(record['metadata']['version'], 'v2')

    def test_record_run_empty_findings(self):
        r = CrossRunRegression(self.path)
        record = r.record_run('t1', [])
        self.assertEqual(record['total_findings'], 0)
        self.assertEqual(record['class_counts'], {})

    def test_js_divergence_identical(self):
        p = {'a': 0.5, 'b': 0.5}
        q = {'a': 0.5, 'b': 0.5}
        self.assertAlmostEqual(js_divergence(p, q), 0.0)

    def test_js_divergence_different(self):
        p = {'a': 1.0}
        q = {'b': 1.0}
        self.assertGreater(js_divergence(p, q), 0.0)

    def test_kl_divergence_all_zeros(self):
        self.assertEqual(_kl_divergence({}, {}), 0.0)

    def test_drift_all_runs_empty(self):
        r = CrossRunRegression(self.path)
        for i in range(5):
            r.record_run(f't{i}', [])
        signals = r.detect_drift(window=5, threshold=0.01)
        self.assertEqual(signals, [])


class RuntimeSplitModelPoolsEdgeTests(unittest.TestCase):
    """Edge cases for split_model_pools."""

    def test_no_preferred_models(self):
        hunt, validate = split_model_pools(['gpt-4', 'claude-3'])
        self.assertEqual(len(hunt), 1)
        self.assertEqual(len(validate), 1)

    def test_preferred_hunt_only(self):
        hunt, validate = split_model_pools(['deepseek-v2', 'gpt-4'])
        self.assertIn('deepseek-v2', hunt)

    def test_preferred_validate_only(self):
        hunt, validate = split_model_pools(['nemotron-4', 'gpt-4'])
        self.assertGreater(len(hunt), 0)
        self.assertGreater(len(validate), 0)

    def test_duplicate_model_names(self):
        hunt, validate = split_model_pools(['deepseek', 'deepseek', 'gpt-4'])
        self.assertEqual(len(hunt), 1, 'duplicates are deduplicated')
        self.assertEqual(len(validate), 1)

    def test_model_with_substring_match_caught(self):
        hunt, validate = split_model_pools(['notdeepseek', 'gpt-4'])
        self.assertIn('notdeepseek', hunt)


class RuntimeAuthEnvEdgeTests(unittest.TestCase):
    """Auth config resolution with env var overrides."""

    def setUp(self):
        self._env_backup = {}
        for env_var in ('OPENROUTER_API_KEY', 'GROQ_API_KEY', 'CEREBRAS_API_KEY'):
            self._env_backup[env_var] = __import__('os').environ.get(env_var)

    def tearDown(self):
        import os
        for k, v in self._env_backup.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_env_var_overrides_file(self):
        import os
        os.environ['OPENROUTER_API_KEY'] = 'env-key'
        tmp = tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w')
        tmp.write(json.dumps({'openrouter': 'file-key'}))
        tmp.close()
        path = Path(tmp.name)
        result = load_auth_config(explicit_path=path)
        self.assertEqual(result.get('openrouter'), 'env-key')
        path.unlink()

    def test_env_var_empty_string_ignored(self):
        import os
        os.environ['OPENROUTER_API_KEY'] = ''
        result = load_auth_config()
        self.assertNotIn('openrouter', result)

    def test_explicit_path_used_when_provided(self):
        tmp = tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w')
        tmp.write(json.dumps({'groq': 'explicit-key'}))
        tmp.close()
        path = Path(tmp.name)
        result = load_auth_config(explicit_path=path, skip_global_fallback=True)
        self.assertEqual(result.get('groq'), 'explicit-key')
        path.unlink()


# ===================================================================
# PARSER — coercion paths and mixed formats
# ===================================================================

class ParserCoercionPathTests(unittest.TestCase):
    """Tests that exercise each JSON parsing fallback path."""

    def test_json_line_after_extraction_fails(self):
        """Line-by-line path after _extract_objects returns nothing."""
        text = 'not json\n{"snippet_id": "s1", "class": "x", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false}'
        f, g = parse_findings(text)
        self.assertGreaterEqual(len(f), 1)

    def test_mixed_formats_all_paths(self):
        text = (
            'some text\n'
            '{"snippet_id": "a", "class": "x", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false}\n'
            'more text\n'
        )
        f, g = parse_findings(text)
        self.assertGreaterEqual(len(f), 1)

    def test_extract_objects_with_deeply_nested_lists(self):
        text = '[{"snippet_id": "deep", "class": "x", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false, "extra": {"nested": "data"}}]'
        f, g = parse_findings(text)
        self.assertGreaterEqual(len(f), 1)

    def test_finding_nested_inside_list_inside_dict(self):
        text = _json.dumps({"metadata": "scan", "results": [{"snippet_id": "s2", "class": "overflow", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": False}]})
        f, g = parse_findings(text)
        self.assertEqual(len(f), 1)

    def test_finding_with_done_and_snippet(self):
        text = '{"snippet_id": "s1", "class": "x", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false, "done": true}'
        f, g = parse_findings(text)
        self.assertEqual(len(f), 0)
        self.assertEqual(len(g), 1)

    def test_finding_with_coverage_gap_and_snippet(self):
        text = _json.dumps([
            {"snippet_id": "s1", "class": "x", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": False},
            {"coverage_gap": "mem", "reason": "no files"},
        ])
        f, g = parse_findings(text)
        self.assertEqual(len(f), 1)
        self.assertEqual(len(g), 1)


class ParserObjectExtractionEdgeTests(unittest.TestCase):
    """Edge cases for _extract_objects."""

    def test_text_with_no_braces(self):
        objs = _extract_objects('just plain text with no json at all')
        self.assertEqual(objs, [])

    def test_text_with_unmatched_opening_brace(self):
        objs = _extract_objects('{"unclosed json:')
        self.assertEqual(objs, [])

    def test_text_with_only_empty_brace(self):
        objs = _extract_objects('{}')
        self.assertEqual(len(objs), 1)
        self.assertEqual(objs[0], {})


# ===================================================================
# VOTING — deeper adversarial scenarios
# ===================================================================

class VotingAdvancedEdgeTests(unittest.TestCase):
    """More adversarial merge scenarios."""

    def test_hundred_runs_minimal_overlap(self):
        def mk(sid):
            return {'snippet_id': sid, 'class': 'overflow', 'severity': 'HIGH'}
        runs = [[mk('shared')] + [mk(f'unique_{i}_{j}') for j in range(100)] for i in range(100)]
        promoted, suppressed = merge_hunter_outputs(runs, min_votes=50)
        self.assertEqual(len(promoted), 1)

    def test_all_empty_runs_some_none(self):
        promoted, suppressed = merge_hunter_outputs([None, [], None, []], min_votes=1)
        self.assertEqual(promoted, [])

    def test_finding_no_severity_key(self):
        f = {'snippet_id': 'a', 'class': 'overflow'}
        promoted, suppressed = merge_hunter_outputs([[f], [f]], min_votes=2)
        self.assertEqual(len(promoted), 1)

    def test_all_findings_empty_class(self):
        f = {'snippet_id': 'a', 'class': '', 'severity': 'HIGH'}
        promoted, suppressed = merge_hunter_outputs([[f], [f]], min_votes=2)
        self.assertEqual(len(promoted), 1)

    def test_vote_count_annotated(self):
        f = {'snippet_id': 'a', 'class': 'overflow', 'severity': 'HIGH'}
        promoted, _ = merge_hunter_outputs([[f], [f], [f]], min_votes=2)
        self.assertEqual(promoted[0]['vote_count'], 3)


# ===================================================================
# SUPPRESSIONS — concurrency-style and edge patterns
# ===================================================================

class SuppressionAdvancedEdgeTests(unittest.TestCase):
    """More adversarial suppression patterns."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / 'sup.json'

    def tearDown(self):
        self._tmp.cleanup()

    def test_add_suppress_many_then_filter_empty(self):
        reg = SuppressionRegistry(self.path)
        reg.suppress_many([{'snippet_id': 'a', 'class': 'x'}])
        kept, suppressed = reg.filter([])
        self.assertEqual(kept, [])

    def test_add_and_filter_same_object_different_instance(self):
        reg = SuppressionRegistry(self.path)
        reg.add({'snippet_id': 'a', 'class': 'x'})
        kept, suppressed = reg.filter([{'snippet_id': 'a', 'class': 'x'}])
        self.assertEqual(len(suppressed), 1)

    def test_add_twice_same_key(self):
        reg = SuppressionRegistry(self.path)
        reg.add({'snippet_id': 'a', 'class': 'x'}, reason='first')
        reg.add({'snippet_id': 'a', 'class': 'x'}, reason='second')
        self.assertEqual(len(reg), 1)

    def test_missing_keys_in_add(self):
        reg = SuppressionRegistry(self.path)
        reg.add({}, reason='empty')
        self.assertEqual(len(reg), 1)


# ===================================================================
# CONTRACTS — missing fields and edge cases
# ===================================================================

class ContractsAdvancedEdgeTests(unittest.TestCase):
    """More adversarial schema validation scenarios."""

    def test_schema_with_no_type(self):
        schema = {'required': ['x']}
        errors = validate_subset_schema(42, schema)
        self.assertEqual(len(errors), 0)

    def test_schema_with_null_type(self):
        schema = {'type': None}
        errors = validate_subset_schema(42, schema)
        self.assertEqual(len(errors), 0)

    def test_standardize_with_none_input(self):
        with self.assertRaises(TypeError):
            standardize_finding(None)

    def test_array_of_objects_validation(self):
        schema = {'type': 'array', 'items': {'type': 'object', 'required': ['id']}}
        data = [{'id': 1}, {'id': 2}]
        errors = validate_subset_schema(data, schema)
        self.assertEqual(errors, [])

    def test_array_missing_required_in_item(self):
        schema = {'type': 'array', 'items': {'type': 'object', 'required': ['id']}}
        data = [{'id': 1}, {'name': 'no-id'}]
        errors = validate_subset_schema(data, schema)
        self.assertGreater(len(errors), 0)


# ===================================================================
# INGESTOR — deeper adversarial patterns
# ===================================================================

class IngestorDeeperEdgeTests(unittest.TestCase):
    """More adversarial ingestor edge cases."""

    def test_tag_snippet_binary_bytes(self):
        content = bytes(range(256)).decode('latin-1')
        tags = tag_snippet({'content': content})
        self.assertIsInstance(tags, list)

    def test_should_exclude_with_mixed_case_test(self):
        self.assertTrue(should_exclude_path('src/Test/foo.c'))

    def test_should_exclude_unrelated_path(self):
        self.assertFalse(should_exclude_path('src/network/foo.c'))

    def test_detect_external_input_binary(self):
        self.assertFalse(detect_external_input('\x00\x01\x02'))

    def test_detect_integer_arith_with_all_operators(self):
        cases = [
            ('size = len + 4; n = recv(fd, buf, len, 0);', True),
            ('size = len - 1; n = recv(fd, buf, len, 0);', True),
            ('size = len * 4; n = recv(fd, buf, len, 0);', True),
            ('size = len / 2; n = recv(fd, buf, len, 0);', True),
            ('size = len % 8; n = recv(fd, buf, len, 0);', True),
        ]
        for snippet, expected in cases:
            self.assertEqual(detect_integer_arith_untrusted(snippet), expected)

    def test_filter_snippets_all_missing_file(self):
        snippets = [{'content': 'a'}, {'content': 'b'}]
        result = filter_snippets(snippets)
        self.assertEqual(len(result), 2)


# ===================================================================
# COORDINATOR — deeper adversarial tests
# ===================================================================

class CoordinatorDeeperEdgeTests(unittest.TestCase):
    """More adversarial pack building scenarios."""

    def test_negative_token_count_in_snippet(self):
        snippets = [{'file': 'a.c', 'token_count': -50}]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow',
             'target_files': ['a.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs(snippets, tasks, budget_tokens=100)
        self.assertEqual(len(packs), 1)

    def test_budget_exactly_zero_with_one_snippet(self):
        snippets = [{'file': 'a.c', 'token_count': 0}]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow',
             'target_files': ['a.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs(snippets, tasks, budget_tokens=0)
        self.assertEqual(len(packs), 1)

    def test_all_snippets_exceed_budget_alone(self):
        snippets = [
            {'file': 'a.c', 'token_count': 200},
            {'file': 'b.c', 'token_count': 200},
        ]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow',
             'target_files': ['a.c', 'b.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs(snippets, tasks, budget_tokens=70)
        self.assertEqual(len(packs), 2)

    def test_recon_task_missing_priority(self):
        snippets = [{'file': 'a.c', 'token_count': 10}]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow',
             'target_files': ['a.c'], 'rationale': 'r'},
        ]
        packs = build_context_packs(snippets, tasks)
        self.assertEqual(len(packs), 1)


# ===================================================================
# REPORT — deeper adversarial bucketing
# ===================================================================

class ReportDeeperEdgeTests(unittest.TestCase):
    """More adversarial bucketing and dedup scenarios."""

    def test_empty_severity_downgraded_to_informational(self):
        self.assertEqual(_downgrade_severity(''), 'INFORMATIONAL')

    def test_critical_confirmed_with_full_path_fix_now(self):
        f = {
            'snippet_id': 's1', 'class': 'overflow', 'severity': 'CRITICAL',
            'status': 'confirmed', 'poc_confirmed': True, 'desc': 'd',
            'call_path': ['main', 'sink'], 'call_path_verified': True,
        }
        bucket, _ = bucket_finding(f, trace_required=False)
        self.assertEqual(bucket, 'fix_now')

    def test_backlog_because_medium_severity(self):
        f = {
            'snippet_id': 's1', 'class': 'overflow', 'severity': 'MEDIUM',
            'status': 'confirmed', 'poc_confirmed': True, 'desc': 'd',
            'call_path': ['main'], 'call_path_verified': True,
        }
        bucket, _ = bucket_finding(f, trace_required=False)
        self.assertEqual(bucket, 'backlog')

    def test_false_positive_rejected(self):
        f = {
            'snippet_id': 's1', 'class': 'overflow', 'severity': 'CRITICAL',
            'status': 'rejected', 'desc': 'd',
        }
        bucket, _ = bucket_finding(f, trace_required=False)
        self.assertEqual(bucket, 'false_positive')

    def test_dedup_none_file_and_lines(self):
        findings = [
            {'snippet_id': 's1', 'class': 'overflow', 'severity': 'HIGH'},
            {'snippet_id': 's1', 'class': 'overflow', 'severity': 'MEDIUM'},
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['severity'], 'HIGH')

    def test_dedup_with_varying_lines(self):
        findings = [
            {'snippet_id': 's1', 'class': 'overflow', 'severity': 'HIGH', 'file': 'a.c', 'lines': [10]},
            {'snippet_id': 's2', 'class': 'overflow', 'severity': 'MEDIUM', 'file': 'a.c', 'lines': [20]},
        ]
        result = deduplicate(findings)
        self.assertEqual(len(result), 2)


# ===================================================================
# VALIDATE — remaining adversarial scenarios
# ===================================================================

class ValidateDeeperEdgeTests(unittest.TestCase):
    """Additional validate edge cases."""

    def test_is_api_by_design_with_none_class(self):
        self.assertFalse(is_api_by_design({'class': None}, {'name': None}))

    def test_is_api_by_design_empty_desc(self):
        self.assertFalse(is_api_by_design({'desc': ''}, {'name': 'foo'}))

    def test_requires_trace_all_combinations(self):
        self.assertTrue(requires_trace_before_fix_now(True, False))
        self.assertFalse(requires_trace_before_fix_now(True, True))
        self.assertFalse(requires_trace_before_fix_now(False, False))
        self.assertFalse(requires_trace_before_fix_now(False, True))

    def test_contains_vuln_signal_ubsan_does_not_match(self):
        self.assertFalse(_contains_vuln_signal('runtime error: member access within misaligned address', 0))

    def test_contains_vuln_signal_stack_smashing(self):
        self.assertTrue(_contains_vuln_signal('*** stack smashing detected ***', 0))

    def test_is_c_or_cpp_capital_suffix(self):
        self.assertTrue(_is_c_or_cpp({'file': 'test.C'}))

    def test_is_c_or_cpp_no_suffix(self):
        self.assertFalse(_is_c_or_cpp({'file': 'test'}))


if __name__ == '__main__':
    unittest.main()
