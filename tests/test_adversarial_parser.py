"""Adversarial tests for stages/parser.py — LLM output parsing edge cases.

Covers deep nesting, unicode, markdown code fences, repeated keys,
truncated boundaries, and mixed JSONL formats that real LLM outputs
produce and that standard tests do not cover.
"""

import unittest

from ai_vuln_harness.stages.parser import (
    _balanced_json_prefix,
    _extract_objects,
    parse_findings,
)


class ParserDeepNestingTests(unittest.TestCase):
    """Extremely deep or wide JSON structures."""

    def test_deeply_nested_json(self):
        inner = '{"a": ' * 500 + '"bottom"' + "}" * 500
        text = f"Some preamble {inner} trailing text"
        f, g = parse_findings(text, domain="mem-safety")
        self.assertIsInstance(f, list)
        self.assertIsInstance(g, list)

    def test_wide_object_with_many_keys(self):
        keys = ", ".join(f'"k{i}": "v{i}"' for i in range(5000))
        text = "{{ {} }}".format(keys)
        f, g = parse_findings(text, domain="all")
        self.assertEqual(len(g), 0)


class ParserMarkdownFenceTests(unittest.TestCase):
    """JSON inside markdown fenced code blocks — a common LLM output pattern."""

    def test_json_in_triple_backtick_block(self):
        text = """Here is the analysis:

```json
{"snippet_id": "s1", "class": "overflow", "severity": "HIGH"}
```"""
        f, g = parse_findings(text)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["snippet_id"], "s1")

    def test_json_in_triple_backtick_no_lang(self):
        text = """```
{"snippet_id": "s1", "desc": "test", "status": "raw", "poc_confirmed": false}
```"""
        f, g = parse_findings(text)
        self.assertEqual(len(f), 1)

    def test_multiple_json_blocks_in_markdown(self):
        text = """First finding:
```json
{"snippet_id": "a", "class": "overflow", "severity": "HIGH", "desc": "a", "status": "raw", "poc_confirmed": false}
```

Second finding:
```json
{"snippet_id": "b", "class": "uaf", "severity": "CRITICAL", "desc": "b", "status": "raw", "poc_confirmed": false}
```"""
        f, g = parse_findings(text)
        ids = {x["snippet_id"] for x in f if "snippet_id" in x}
        self.assertEqual(ids, {"a", "b"})


class ParserRepeatedKeyJsonTests(unittest.TestCase):
    """JSON with duplicate keys — LLMs sometimes repeat keys."""

    def test_duplicate_keys_last_wins(self):
        text = '{"snippet_id": "a", "snippet_id": "b", "class": "x", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false}'
        f, g = parse_findings(text)
        self.assertEqual(len(f), 1)

    def test_duplicate_keys_in_nested(self):
        text = '{"snippet_id": "a", "snippet_id": "b", "class": "x", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false}'
        f, g = parse_findings(text)
        self.assertGreaterEqual(len(f), 1)


class ParserUnicodeAndEncodingTests(unittest.TestCase):
    """Non-ASCII identifiers and encodings."""

    def test_unicode_identifiers(self):
        text = '{"snippet_id": "s1", "class": "café_overflow", "severity": "HIGH", "desc": "测试", "status": "raw", "poc_confirmed": false}'
        f, g = parse_findings(text)
        self.assertEqual(len(f), 1)

    def test_surrogate_pairs(self):
        text = '{"snippet_id": "s1", "class": "\\ud83d\\udca5", "severity": "HIGH", "desc": "boom", "status": "raw", "poc_confirmed": false}'
        f, g = parse_findings(text)
        self.assertEqual(len(g), 0)

    def test_bom_prefix(self):
        text = '\ufeff{"snippet_id": "s1", "class": "overflow", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false}'
        f, g = parse_findings(text)
        self.assertEqual(len(f), 1)


class ParserTruncationBoundaryTests(unittest.TestCase):
    """Output truncated at various positions in the JSON structure."""

    def test_truncated_after_open_brace(self):
        text = '{"snippet_id": "a", "severity": "HIGH"'
        f, g = parse_findings(text)
        self.assertEqual(len(f), 0)

    def test_truncated_array_with_one_complete(self):
        text = '[{"snippet_id": "a", "severity": "HIGH", "class": "x", "desc": "d", "status": "raw", "poc_confirmed": false}, '
        f, g = parse_findings(text)
        self.assertEqual(len(f), 1)

    def test_truncated_key_name(self):
        text = '{"snippet_'
        f, g = parse_findings(text)
        self.assertEqual(len(f), 0)
        self.assertEqual(len(g), 0)

    def test_truncated_during_string_escape(self):
        text = '{"snippet_id": "a\\'
        f, g = parse_findings(text)
        self.assertEqual(len(f), 0)

    def test_truncated_array_with_trailing_comma(self):
        text = '[{"snippet_id": "a", "class": "x", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false},]'
        f, g = parse_findings(text)
        self.assertIsInstance(f, list)
        self.assertIsInstance(g, list)


class ParserLineNoiseTests(unittest.TestCase):
    """Garbage text adjacent to valid JSON."""

    def test_garbage_before_and_after_json(self):
        text = """asdfghjkl;
{"snippet_id": "s1", "class": "overflow", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false}
zxcvbnm,./"""
        f, g = parse_findings(text)
        self.assertEqual(len(f), 1)

    def test_xml_tags_around_json(self):
        text = '<response>\n{"snippet_id": "s1", "class": "x", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false}\n</response>'
        f, g = parse_findings(text)
        self.assertEqual(len(f), 1)

    def test_prose_then_json_then_more_prose(self):
        text = 'We analyzed the code and found: {"snippet_id": "s1", "class": "overflow", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false}. This is critical.'
        f, g = parse_findings(text)
        self.assertEqual(len(f), 1)


class ParserExtractObjectsAdversarialTests(unittest.TestCase):
    """Direct tests on _extract_objects with adversarial inputs."""

    def test_list_of_empty_objects(self):
        text = "[{},{},{},{},{}]"
        objs = _extract_objects(text)
        self.assertEqual(len(objs), 5)

    def test_mixed_objects_and_non_dicts(self):
        text = '[{"a": 1}, null, "string", 42, {"b": 2}]'
        objs = _extract_objects(text)
        self.assertEqual(len(objs), 2)

    def test_balanced_prefix_deeply_nested(self):
        line = 'pre {"a": {"b": {"c": 1}}} post'
        result = _balanced_json_prefix(line)
        self.assertIsNotNone(result)
        self.assertEqual(result["a"]["b"]["c"], 1)

    def test_balanced_prefix_with_multiple_json_candidates(self):
        line = '{"a": 1} stuff {"b": 2}'
        result = _balanced_json_prefix(line)
        self.assertIsNotNone(result)

    def test_balanced_prefix_no_json(self):
        line = "just some regular text with {curly braces} but no json"
        result = _balanced_json_prefix(line)
        self.assertIsNone(result)

    def test_balanced_prefix_unmatched_braces(self):
        line = '{"a": 1} {{{'
        result = _balanced_json_prefix(line)
        self.assertEqual(result, {"a": 1})

    def test_balanced_prefix_empty_object(self):
        line = "text {} more text"
        result = _balanced_json_prefix(line)
        self.assertEqual(result, {})


class ParserSpamDetectionTests(unittest.TestCase):
    """Model outputs very many findings."""

    def test_thousand_identical_findings(self):
        items = [
            '{"snippet_id": "s1", "class": "overflow", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false}'
        ] * 1000
        text = "[" + ",".join(items) + "]"
        f, g = parse_findings(text)
        self.assertEqual(len(f), 1000)

    def test_sentinel_with_partial_findings_mixed(self):
        text = '{"done": true}\n{"snippet_id": "s1", "class": "x", "severity": "HIGH", "desc": "d", "status": "raw", "poc_confirmed": false}'
        f, g = parse_findings(text)
        self.assertGreaterEqual(len(f), 1)

    def test_only_coverage_gaps(self):
        import json as _json

        text = _json.dumps(
            [
                {"coverage_gap": "domain-a", "reason": "no files"},
                {"coverage_gap": "domain-b", "reason": "all excluded"},
            ]
        )
        f, g = parse_findings(text)
        self.assertEqual(len(f), 0)
        self.assertGreaterEqual(len(g), 2)


if __name__ == "__main__":
    unittest.main()
