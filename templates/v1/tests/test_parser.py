import unittest

from stages.parser import parse_findings


class ParseFindingsTests(unittest.TestCase):
    def test_empty_body(self):
        f, g = parse_findings('', domain='mem-safety')
        self.assertEqual(f, [])
        self.assertEqual(g, [])

    def test_sentinel_only(self):
        f, g = parse_findings('{"done": true}', domain='format-str')
        self.assertEqual(f, [])
        self.assertEqual(len(g), 1)
        self.assertEqual(g[0]['coverage_gap'], 'format-str')

    def test_mixed_json_and_prose_same_line(self):
        text = '{"done": true} We analyzed and found no issues.'
        f, g = parse_findings(text, domain='auth')
        self.assertEqual(f, [])
        self.assertEqual(len(g), 1)

    def test_malformed_json(self):
        text = '{"snippet_id": "x", "severity": "HIGH", }'
        f, g = parse_findings(text, domain='ipc')
        self.assertEqual(f, [])
        self.assertEqual(g, [])

    def test_truncated_output(self):
        text = '[{"snippet_id": "a", "severity": "HIGH"'
        f, g = parse_findings(text, domain='data-flow')
        self.assertEqual(f, [])
        self.assertEqual(g, [])


if __name__ == '__main__':
    unittest.main()
