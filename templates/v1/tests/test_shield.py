"""Tests for stages/shield.py — call-path verification, static reachability,
and hallucination detection."""

import unittest

from stages.shield import (
    build_call_graph,
    verify_call_path,
    annotate_call_path_verification,
    filter_unreachable,
    detect_hallucination,
    annotate_hallucination,
)


class BuildCallGraphTests(unittest.TestCase):
    def test_empty_snippets(self):
        self.assertEqual(build_call_graph([]), {})

    def test_basic_graph(self):
        snippets = [
            {'name': 'http_handler', 'callees': ['parse_request', 'auth_check']},
            {'name': 'parse_request', 'callees': ['memcpy']},
        ]
        g = build_call_graph(snippets)
        self.assertIn('http_handler', g)
        self.assertIn('parse_request', g['http_handler'])
        self.assertIn('auth_check', g['http_handler'])
        self.assertIn('memcpy', g['parse_request'])

    def test_names_lowercased(self):
        snippets = [{'name': 'MyFunc', 'callees': ['HelperA']}]
        g = build_call_graph(snippets)
        self.assertIn('myfunc', g)
        self.assertIn('helpera', g['myfunc'])


class VerifyCallPathTests(unittest.TestCase):
    def setUp(self):
        self.graph = {
            'http_handler': {'parse_request', 'auth_check'},
            'parse_request': {'memcpy'},
            'auth_check': {'validate_token'},
        }

    def test_empty_graph_returns_true(self):
        ok, reason = verify_call_path({'call_path': ['a', 'b']}, {})
        self.assertTrue(ok)
        self.assertEqual(reason, 'no-graph-data')

    def test_empty_call_path_fails(self):
        ok, reason = verify_call_path({'call_path': []}, self.graph)
        self.assertFalse(ok)
        self.assertIn('empty', reason)

    def test_valid_path(self):
        ok, _ = verify_call_path(
            {'call_path': ['http_handler', 'parse_request', 'memcpy']},
            self.graph,
        )
        self.assertTrue(ok)

    def test_invalid_hop(self):
        ok, reason = verify_call_path(
            {'call_path': ['http_handler', 'memcpy']},  # not a direct edge
            self.graph,
        )
        self.assertFalse(ok)
        self.assertIn('http_handler→memcpy', reason)

    def test_single_node_present(self):
        ok, reason = verify_call_path({'call_path': ['http_handler']}, self.graph)
        self.assertTrue(ok)
        self.assertEqual(reason, 'single-node-present')

    def test_single_node_absent(self):
        ok, _ = verify_call_path({'call_path': ['unknown_func']}, self.graph)
        self.assertFalse(ok)


class AnnotateCallPathTests(unittest.TestCase):
    def test_annotation_added(self):
        graph = {'a': {'b'}, 'b': set()}
        findings = [{'call_path': ['a', 'b']}, {'call_path': []}]
        result = annotate_call_path_verification(findings, graph)
        self.assertTrue(result[0]['call_path_verified'])
        self.assertFalse(result[1]['call_path_verified'])


class FilterUnreachableTests(unittest.TestCase):
    def setUp(self):
        self.graph = {
            'main': {'handler'},
            'handler': {'process'},
            'process': {'sink_func'},
        }

    def test_no_graph_all_pass(self):
        findings = [{'snippet_id': 'x', 'call_path': ['sink_func']}]
        r, u = filter_unreachable(findings, {}, ['main'])
        self.assertEqual(r, findings)
        self.assertEqual(u, [])

    def test_no_entry_points_all_pass(self):
        findings = [{'snippet_id': 'x', 'call_path': ['sink_func']}]
        r, u = filter_unreachable(findings, self.graph, [])
        self.assertEqual(r, findings)
        self.assertEqual(u, [])

    def test_reachable_finding(self):
        findings = [{'snippet_id': 'sink_func', 'call_path': ['main', 'handler', 'sink_func']}]
        r, u = filter_unreachable(findings, self.graph, ['main'])
        self.assertEqual(len(r), 1)
        self.assertEqual(u, [])

    def test_unreachable_finding(self):
        findings = [{'snippet_id': 'orphan_func', 'call_path': ['orphan_func']}]
        r, u = filter_unreachable(findings, self.graph, ['main'])
        self.assertEqual(r, [])
        self.assertEqual(len(u), 1)
        self.assertEqual(u[0]['static_reachability'], 'unreachable')


class DetectHallucinationTests(unittest.TestCase):
    def test_ok_when_no_content(self):
        finding = {'desc': 'buffer overflow in foo_func', 'call_path': ['foo_func']}
        hallucinated, reason = detect_hallucination(finding, {})
        self.assertFalse(hallucinated)
        self.assertEqual(reason, 'no-snippet-content')

    def test_matching_desc(self):
        snippet = {'content': 'void foo_func() { char buffer[10]; overflow_here(); }'}
        finding = {'desc': 'buffer overflow in foo_func via overflow_here', 'call_path': ['foo_func']}
        hallucinated, _ = detect_hallucination(finding, snippet)
        self.assertFalse(hallucinated)

    def test_mostly_absent_desc_tokens_flagged(self):
        snippet = {'content': 'void foo() { int x = 1; }'}
        finding = {
            'desc': 'allocate_memory_buffer causes heap_overflow through pointer_arithmetic_underflow',
            'call_path': [],
        }
        hallucinated, reason = detect_hallucination(finding, snippet)
        self.assertTrue(hallucinated)
        self.assertIn('desc tokens', reason)

    def test_mostly_absent_call_path_flagged(self):
        snippet = {'content': 'void foo() { int x = 1; }'}
        finding = {
            'desc': 'a bug',
            'call_path': ['nonexistent_func_alpha', 'another_missing_func', 'third_absent_func'],
        }
        hallucinated, reason = detect_hallucination(finding, snippet)
        self.assertTrue(hallucinated)
        self.assertIn('call_path', reason)


class AnnotateHallucinationTests(unittest.TestCase):
    def test_annotations_added(self):
        snippet_db = {'sid1': {'content': 'void foo_func() { memcpy(dst, src, len); }'}}
        findings = [
            {'snippet_id': 'sid1', 'desc': 'foo_func memcpy overflow', 'call_path': ['foo_func']},
            {'snippet_id': 'sid_missing', 'desc': 'some desc', 'call_path': []},
        ]
        result = annotate_hallucination(findings, snippet_db)
        self.assertIn('hallucination_detected', result[0])
        self.assertIn('hallucination_detected', result[1])
        # Missing snippet → no-snippet-content → not hallucinated
        self.assertFalse(result[1]['hallucination_detected'])


if __name__ == '__main__':
    unittest.main()
