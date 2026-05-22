"""Tests for stages/shield.py — call-path verification, static reachability,
hallucination detection (token-overlap + KL-divergence), and semantic
deduplication (cosine similarity)."""

import math
import unittest

from ai_vuln_harness.stages.shield import (
    annotate_call_path_verification,
    annotate_hallucination,
    annotate_hallucination_kl,
    build_call_graph,
    cosine_similarity,
    deduplicate_semantic,
    detect_hallucination,
    detect_hallucination_kl,
    filter_unreachable,
    kl_divergence,
    verify_call_path,
)


class BuildCallGraphTests(unittest.TestCase):
    def test_empty_snippets(self):
        self.assertEqual(build_call_graph([]), {})

    def test_basic_graph(self):
        snippets = [
            {"name": "http_handler", "callees": ["parse_request", "auth_check"]},
            {"name": "parse_request", "callees": ["memcpy"]},
        ]
        g = build_call_graph(snippets)
        self.assertIn("http_handler", g)
        self.assertIn("parse_request", g["http_handler"])
        self.assertIn("auth_check", g["http_handler"])
        self.assertIn("memcpy", g["parse_request"])

    def test_names_lowercased(self):
        snippets = [{"name": "MyFunc", "callees": ["HelperA"]}]
        g = build_call_graph(snippets)
        self.assertIn("myfunc", g)
        self.assertIn("helpera", g["myfunc"])


class VerifyCallPathTests(unittest.TestCase):
    def setUp(self):
        self.graph = {
            "http_handler": {"parse_request", "auth_check"},
            "parse_request": {"memcpy"},
            "auth_check": {"validate_token"},
        }

    def test_empty_graph_returns_true(self):
        ok, reason = verify_call_path({"call_path": ["a", "b"]}, {})
        self.assertTrue(ok)
        self.assertEqual(reason, "no-graph-data")

    def test_empty_call_path_fails(self):
        ok, reason = verify_call_path({"call_path": []}, self.graph)
        self.assertFalse(ok)
        self.assertIn("empty", reason)

    def test_valid_path(self):
        ok, _ = verify_call_path(
            {"call_path": ["http_handler", "parse_request", "memcpy"]},
            self.graph,
        )
        self.assertTrue(ok)

    def test_invalid_hop(self):
        ok, reason = verify_call_path(
            {"call_path": ["http_handler", "memcpy"]},  # not a direct edge
            self.graph,
        )
        self.assertFalse(ok)
        self.assertIn("http_handler→memcpy", reason)

    def test_single_node_present(self):
        ok, reason = verify_call_path({"call_path": ["http_handler"]}, self.graph)
        self.assertTrue(ok)
        self.assertEqual(reason, "single-node-present")

    def test_single_node_absent(self):
        ok, _ = verify_call_path({"call_path": ["unknown_func"]}, self.graph)
        self.assertFalse(ok)


class AnnotateCallPathTests(unittest.TestCase):
    def test_annotation_added(self):
        graph = {"a": {"b"}, "b": set()}
        findings = [{"call_path": ["a", "b"]}, {"call_path": []}]
        result = annotate_call_path_verification(findings, graph)
        self.assertTrue(result[0]["call_path_verified"])
        self.assertFalse(result[1]["call_path_verified"])


class FilterUnreachableTests(unittest.TestCase):
    def setUp(self):
        self.graph = {
            "main": {"handler"},
            "handler": {"process"},
            "process": {"sink_func"},
        }

    def test_no_graph_all_pass(self):
        findings = [{"snippet_id": "x", "call_path": ["sink_func"]}]
        r, u = filter_unreachable(findings, {}, ["main"])
        self.assertEqual(r, findings)
        self.assertEqual(u, [])

    def test_no_entry_points_all_pass(self):
        findings = [{"snippet_id": "x", "call_path": ["sink_func"]}]
        r, u = filter_unreachable(findings, self.graph, [])
        self.assertEqual(r, findings)
        self.assertEqual(u, [])

    def test_reachable_finding(self):
        findings = [
            {"snippet_id": "sink_func", "call_path": ["main", "handler", "sink_func"]}
        ]
        r, u = filter_unreachable(findings, self.graph, ["main"])
        self.assertEqual(len(r), 1)
        self.assertEqual(u, [])

    def test_unreachable_finding(self):
        findings = [{"snippet_id": "orphan_func", "call_path": ["orphan_func"]}]
        r, u = filter_unreachable(findings, self.graph, ["main"])
        self.assertEqual(r, [])
        self.assertEqual(len(u), 1)
        self.assertEqual(u[0]["static_reachability"], "unreachable")


class DetectHallucinationTests(unittest.TestCase):
    def test_ok_when_no_content(self):
        finding = {"desc": "buffer overflow in foo_func", "call_path": ["foo_func"]}
        hallucinated, reason = detect_hallucination(finding, {})
        self.assertFalse(hallucinated)
        self.assertEqual(reason, "no-snippet-content")

    def test_matching_desc(self):
        snippet = {"content": "void foo_func() { char buffer[10]; overflow_here(); }"}
        finding = {
            "desc": "buffer overflow in foo_func via overflow_here",
            "call_path": ["foo_func"],
        }
        hallucinated, _ = detect_hallucination(finding, snippet)
        self.assertFalse(hallucinated)

    def test_mostly_absent_desc_tokens_flagged(self):
        snippet = {"content": "void foo() { int x = 1; }"}
        finding = {
            "desc": "allocate_memory_buffer causes heap_overflow through pointer_arithmetic_underflow",
            "call_path": [],
        }
        hallucinated, reason = detect_hallucination(finding, snippet)
        self.assertTrue(hallucinated)
        self.assertIn("desc tokens", reason)

    def test_mostly_absent_call_path_flagged(self):
        snippet = {"content": "void foo() { int x = 1; }"}
        finding = {
            "desc": "a bug",
            "call_path": [
                "nonexistent_func_alpha",
                "another_missing_func",
                "third_absent_func",
            ],
        }
        hallucinated, reason = detect_hallucination(finding, snippet)
        self.assertTrue(hallucinated)
        self.assertIn("call_path", reason)


class AnnotateHallucinationTests(unittest.TestCase):
    def test_annotations_added(self):
        snippet_db = {"sid1": {"content": "void foo_func() { memcpy(dst, src, len); }"}}
        findings = [
            {
                "snippet_id": "sid1",
                "desc": "foo_func memcpy overflow",
                "call_path": ["foo_func"],
            },
            {"snippet_id": "sid_missing", "desc": "some desc", "call_path": []},
        ]
        result = annotate_hallucination(findings, snippet_db)
        self.assertIn("hallucination_detected", result[0])
        self.assertIn("hallucination_detected", result[1])
        # Missing snippet → no-snippet-content → not hallucinated
        self.assertFalse(result[1]["hallucination_detected"])


# ---------------------------------------------------------------------------
# KL-divergence hallucination detection tests
# ---------------------------------------------------------------------------


class KlDivergenceTests(unittest.TestCase):
    def test_identical_distributions_zero(self):
        p = {"a": 0.5, "b": 0.5}
        q = {"a": 0.5, "b": 0.5}
        self.assertAlmostEqual(kl_divergence(p, q), 0.0, places=6)

    def test_different_distributions_positive(self):
        p = {"a": 0.9, "b": 0.1}
        q = {"a": 0.5, "b": 0.5}
        self.assertGreater(kl_divergence(p, q), 0.0)

    def test_missing_token_large_but_finite(self):
        p = {"a": 0.5, "b": 0.5}
        q = {"a": 1.0}
        kl = kl_divergence(p, q)
        self.assertGreater(kl, 5.0)
        self.assertNotEqual(kl, math.inf)


class DetectHallucinationKlTests(unittest.TestCase):
    def test_ok_when_no_content(self):
        finding = {"desc": "buffer overflow in foo_func", "call_path": ["foo_func"]}
        detected, reason = detect_hallucination_kl(finding, {})
        self.assertFalse(detected)
        self.assertEqual(reason, "no-snippet-content")

    def test_ok_when_no_desc(self):
        snippet = {"content": "void foo() { int x = 1; }"}
        detected, reason = detect_hallucination_kl({"desc": ""}, snippet)
        self.assertFalse(detected)
        self.assertEqual(reason, "no-desc")

    def test_matching_desc_low_kl(self):
        snippet = {"content": "void foo_func() { char buffer[10]; overflow_here(); }"}
        finding = {"desc": "foo_func buffer overflow_here via", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertFalse(detected)
        self.assertIn("KL=", reason)

    def test_hallucinated_desc_high_kl(self):
        snippet = {"content": "void x() { int y = 1; }"}
        finding = {
            "desc": "allocate_memory_buffer causes heap_overflow through pointer_arithmetic_underflow",
            "call_path": [],
        }
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertTrue(detected)
        self.assertIn("KL=", reason)

    def test_empty_desc_tokens(self):
        snippet = {"content": "void foo() { int x = 1; }"}
        detected, reason = detect_hallucination_kl({"desc": "a b c d"}, snippet)
        self.assertFalse(detected)
        self.assertEqual(reason, "no-desc-tokens")

    def test_only_desc_tokens_no_code_tokens(self):
        snippet = {"content": "int main() { return 0; }"}
        finding = {
            "desc": "heap_overflow_condition triggers double_free_vulnerability",
            "call_path": [],
        }
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertTrue(detected)


class AnnotateHallucinationKlTests(unittest.TestCase):
    def test_annotations_added(self):
        snippet_db = {"sid1": {"content": "void foo_func() { memcpy(dst, src, len); }"}}
        findings = [
            {
                "snippet_id": "sid1",
                "desc": "foo_func memcpy overflow",
                "call_path": ["foo_func"],
            },
            {"snippet_id": "sid_missing", "desc": "some desc", "call_path": []},
        ]
        result = annotate_hallucination_kl(findings, snippet_db)
        self.assertIn("hallucination_kl_detected", result[0])
        self.assertIn("hallucination_kl_detected", result[1])
        self.assertIn("hallucination_kl_reason", result[0])
        self.assertIn("hallucination_kl", result[0])


# ---------------------------------------------------------------------------
# Cosine similarity semantic deduplication tests
# ---------------------------------------------------------------------------


class CosineSimilarityTests(unittest.TestCase):
    def test_identical_vectors(self):
        a = [1.0, 0.0, 0.0]
        self.assertAlmostEqual(cosine_similarity(a, a), 1.0)

    def test_orthogonal_vectors(self):
        a = [1.0, 0.0]
        b = [0.0, 1.0]
        self.assertAlmostEqual(cosine_similarity(a, b), 0.0)

    def test_angle_45(self):
        a = [1.0, 0.0]
        b = [1.0, 1.0]
        expected = 1.0 / math.sqrt(2)
        self.assertAlmostEqual(cosine_similarity(a, b), expected)

    def test_length_mismatch_raises(self):
        with self.assertRaises(ValueError):
            cosine_similarity([1.0], [1.0, 2.0])


class DeduplicateSemanticTests(unittest.TestCase):
    def test_empty_findings(self):
        self.assertEqual(deduplicate_semantic([]), [])

    def test_similar_descriptions_collapsed(self):
        findings = [
            {
                "snippet_id": "a",
                "desc": "heap buffer overflow in parse_url via large input",
                "severity": "HIGH",
            },
            {
                "snippet_id": "b",
                "desc": "heap buffer overflow in parse_url via oversized input",
                "severity": "MEDIUM",
            },
        ]
        result = deduplicate_semantic(findings, threshold=0.5)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "HIGH")

    def test_dissimilar_descriptions_kept_separate(self):
        findings = [
            {
                "snippet_id": "a",
                "desc": "heap buffer overflow in parse_url",
                "severity": "HIGH",
            },
            {
                "snippet_id": "b",
                "desc": "format string vulnerability in log_message",
                "severity": "CRITICAL",
            },
        ]
        result = deduplicate_semantic(findings, threshold=0.8)
        self.assertEqual(len(result), 2)

    def test_highest_severity_kept_in_group(self):
        findings = [
            {
                "snippet_id": "a",
                "desc": "use after free in cleanup handler",
                "severity": "LOW",
            },
            {
                "snippet_id": "b",
                "desc": "use after free in cleanup_handler",
                "severity": "HIGH",
            },
            {
                "snippet_id": "c",
                "desc": "use after free in cleanup handler function",
                "severity": "MEDIUM",
            },
        ]
        result = deduplicate_semantic(findings, threshold=0.5)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "HIGH")
        self.assertEqual(result[0]["snippet_id"], "b")


if __name__ == "__main__":
    unittest.main()
