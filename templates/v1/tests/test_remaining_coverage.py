"""Tests for the last uncovered lines across contracts, runtime, shield, parser."""

import math
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from stages.contracts import validate_subset_schema
from stages.parser import parse_findings
from stages.runtime import CrossRunRegression, _kl_divergence, load_auth_config
from stages.shield import (
    _normalise,
    _reachable_from,
    detect_hallucination,
    detect_hallucination_kl,
)


class ContractsBooleanAndEnumTests(unittest.TestCase):
    """Cover lines 27-28, 30-31, 36-37: boolean type check + enum validation."""

    def test_boolean_type_mismatch(self):
        schema = {"type": "boolean"}
        errors = validate_subset_schema("true", schema)
        self.assertGreater(len(errors), 0)

    def test_boolean_type_match(self):
        schema = {"type": "boolean"}
        self.assertEqual(validate_subset_schema(True, schema), [])

    def test_enum_in_data(self):
        schema = {"type": "string", "enum": ["a", "b", "c"]}
        errors = validate_subset_schema("d", schema)
        self.assertGreater(len(errors), 0)

    def test_object_type_mismatch(self):
        """line 27-28: expected object but got non-dict."""
        schema = {"type": "object"}
        errors = validate_subset_schema("not-a-dict", schema)
        self.assertGreater(len(errors), 0)

    def test_array_type_mismatch(self):
        """line 30-31: expected array but got non-list."""
        schema = {"type": "array"}
        errors = validate_subset_schema("not-a-list", schema)
        self.assertGreater(len(errors), 0)

    def test_enum_in_dict_property(self):
        schema = {
            "type": "object",
            "properties": {"status": {"type": "string", "enum": ["ok", "fail"]}},
        }
        errors = validate_subset_schema({"status": "unknown"}, schema)
        self.assertGreater(len(errors), 0)


class ShieldReachableFromTests(unittest.TestCase):
    """Cover lines 97, 102: visited skip + max_hops boundary."""

    def test_visited_node_skipped(self):
        graph = {"a": {"b"}, "b": {"c"}, "c": {"d"}}
        result = _reachable_from("a", {"d"}, graph, max_hops=6)
        self.assertTrue(result)

    def test_max_hops_boundary(self):
        graph = {"a": {"b"}, "b": {"c"}, "c": {"d"}, "d": {"e"}}
        result = _reachable_from("a", {"e"}, graph, max_hops=2)
        self.assertFalse(result)

    def test_target_at_exact_max_hops(self):
        graph = {"a": {"b"}, "b": {"c"}}
        result = _reachable_from("a", {"c"}, graph, max_hops=2)
        self.assertTrue(result)


class ShieldCallersCalleesTests(unittest.TestCase):
    """Cover line 181: callers/callees in detect_hallucination."""

    def test_callee_in_content_via_callees_list(self):
        snippet = {"content": "void outer() { }", "callees": ["inner_helper"]}
        finding = {"desc": "inner_helper called", "call_path": []}
        hallucinated, reason = detect_hallucination(finding, snippet)
        self.assertFalse(hallucinated, f"callee should be found: {reason}")

    def test_caller_in_content_via_callers_list(self):
        snippet = {"content": "void callee() { }", "callers": ["outer_func"]}
        finding = {"desc": "outer_func danger", "call_path": []}
        hallucinated, reason = detect_hallucination(finding, snippet)
        self.assertFalse(hallucinated, f"caller should be found: {reason}")


class ShieldNormaliseEmptyTests(unittest.TestCase):
    """Cover line 230: _normalise with empty counter."""

    def test_empty_counter_returns_empty(self):
        result = _normalise(Counter())
        self.assertEqual(result, {})


class ShieldDescTokensAbsentFromEmptyCodeTests(unittest.TestCase):
    """Cover line 279: desc tokens but empty code content."""

    def test_desc_tokens_absent_from_empty_code(self):
        snippet = {"content": ""}
        finding = {"desc": "buffer overflow in parser", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet)
        self.assertFalse(detected)
        self.assertIn("no-snippet-content", reason)

    def test_desc_present_code_empty_via_kl(self):
        snippet = {"content": "   "}
        finding = {"desc": "buffer overflow in parser", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet)
        self.assertTrue(detected)
        self.assertIn("desc-tokens-absent-from-empty-code", reason)


class ShieldUnionFindRankTieTests(unittest.TestCase):
    """Cover lines 389, 393: union-find rank branches."""

    def test_equal_rank_union(self):
        findings = [
            {
                "snippet_id": "a",
                "desc": "heap buffer overflow in parse",
                "severity": "HIGH",
            },
            {
                "snippet_id": "b",
                "desc": "heap buffer overflow in parse",
                "severity": "MEDIUM",
            },
        ]
        from stages.shield import deduplicate_semantic

        result = deduplicate_semantic(findings, threshold=1.0)
        self.assertEqual(len(result), 1)

    def test_three_equal_rank_unions(self):
        findings = [
            {"snippet_id": "a", "desc": "overflow in func", "severity": "LOW"},
            {"snippet_id": "b", "desc": "overflow in func", "severity": "MEDIUM"},
            {"snippet_id": "c", "desc": "overflow in func", "severity": "HIGH"},
        ]
        from stages.shield import deduplicate_semantic

        result = deduplicate_semantic(findings, threshold=1.0)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "HIGH")

    def test_rank_greater_than(self):
        """force rank[ra] > rank[rb] branch (line 391)."""
        findings = [
            {"snippet_id": "a", "desc": "same long text here pool", "severity": "LOW"},
            {
                "snippet_id": "b",
                "desc": "same long text here pool",
                "severity": "MEDIUM",
            },
            {"snippet_id": "c", "desc": "same long text here pool", "severity": "HIGH"},
        ]
        from stages.shield import deduplicate_semantic

        result = deduplicate_semantic(findings, threshold=1.0)
        self.assertEqual(len(result), 1)


class ShieldVisitedNodeSkipTests(unittest.TestCase):
    """Cover line 97: visited node continue in _reachable_from."""

    def test_visited_node_skipped_bfs(self):
        """Cycle a→b→a forces visited.skip at line 97."""
        graph = {"a": {"b"}, "b": {"a"}}
        result = _reachable_from("a", {"c"}, graph, max_hops=6)
        self.assertFalse(result)


class ParserLineCoverageTests(unittest.TestCase):
    """Cover lines 60, 77: non-dict items in array, blank line skip."""

    def test_non_dict_item_in_json_array(self):
        """line 60: non-dict items in parsed JSON list are skipped."""
        f, g = parse_findings(
            '[1, "string", {"snippet_id": "a", "class": "x", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false}]',
            domain="test",
        )
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["snippet_id"], "a")

    def test_blank_line_skipped_in_line_scan(self):
        """line 77: blank line skipped in line-by-line scan.

        Must have NO valid JSON objects anywhere so _extract_objects
        returns empty and we fall through to the line-by-line path.
        """
        f, g = parse_findings(
            "\n\n\njust some regular text\n\nwith no json\n", domain="test-dom"
        )
        self.assertEqual(len(f), 0)
        self.assertEqual(len(g), 0)


class RuntimeAuthErrorHandlingTests(unittest.TestCase):
    """Cover lines 89-90: JSONDecodeError/OSError in load_auth_config."""

    def test_corrupted_auth_json_skipped(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
        tmp.write("{invalid json!!!")
        tmp.close()
        path = Path(tmp.name)
        result = load_auth_config(explicit_path=path)
        self.assertEqual(result, {})
        path.unlink()

    def test_empty_auth_file(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w")
        tmp.write("{}")
        tmp.close()
        path = Path(tmp.name)
        result = load_auth_config(explicit_path=path)
        self.assertEqual(result, {})
        path.unlink()


class RuntimeKlDivergenceInfTests(unittest.TestCase):
    """Cover line 179: _kl_divergence returns inf when no q for p token."""

    def test_kl_divergence_returns_inf(self):
        p = {"token_a": 1.0}
        q = {}
        result = _kl_divergence(p, q)
        self.assertEqual(result, math.inf)

    def test_kl_divergence_finite(self):
        p = {"a": 0.5, "b": 0.5}
        q = {"a": 0.5, "b": 0.5}
        result = _kl_divergence(p, q)
        self.assertAlmostEqual(result, 0.0)


class RuntimeLoadHistoryEdgeTests(unittest.TestCase):
    """Cover lines 223, 228: _load_history edge cases."""

    def test_load_history_nonexistent_file(self):
        """line 223: file doesn't exist → return []."""
        path = Path(tempfile.mktemp(suffix=".jsonl"))
        r = CrossRunRegression(path)
        result = r.detect_drift()
        self.assertEqual(result, [])

    def test_load_history_empty_lines_mid_content(self):
        """line 228: empty line after strip in middle of content."""
        good = '{"timestamp": "t1", "total_findings": 1, "class_counts": {"a": 1}, "metadata": {}}\n'
        bad = "\n\n"
        more = '{"timestamp": "t2", "total_findings": 1, "class_counts": {"a": 1}, "metadata": {}}\n'
        tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w")
        tmp.write(good + bad + more)
        tmp.close()
        path = Path(tmp.name)
        r = CrossRunRegression(path)
        result = r.detect_drift()
        self.assertIsInstance(result, list)
        path.unlink()

    def test_load_history_garbage_lines_skipped(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False, mode="w")
        tmp.write(
            'garbage\nnot json\n{"timestamp": "t1", "total_findings": 0, "class_counts": {}, "metadata": {}}\n'
        )
        tmp.close()
        path = Path(tmp.name)
        r = CrossRunRegression(path)
        result = r.detect_drift()
        self.assertEqual(result, [])
        path.unlink()


if __name__ == "__main__":
    unittest.main()
