"""Adversarial tests for stages/ingestor.py — snippet analysis edge cases.

Covers tag overload, binary content, path normalization tricks,
integer arithmetic with complex expressions, and boundary conditions
in external input detection.
"""

import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from stages.ingestor import (
    detect_external_input,
    detect_integer_arith_untrusted,
    filter_snippets,
    load_repo_snippets,
    should_exclude_path,
    tag_snippet,
)


class IngestorTagOverloadTests(unittest.TestCase):
    """Content matching every possible tag simultaneously."""

    def test_all_tags_triggered(self):
        content = (
            'malloc free memcpy memmove buffer pointer '
            'recv(fd, buf, len, 0) '
            'auth token session credential permission '
            'crypto cipher hash nonce iv tls '
            'socket pipe mmap shared_memory shm dbus '
            'unsafe reinterpret_cast raw_pointer '
            'printf("hello") '
            'size = len + 4; n = recv(fd, buf, len, 0)'
        )
        tags = tag_snippet({'content': content})
        expected = {'memory', 'external-input', 'auth', 'crypto', 'ipc', 'unsafe', 'format-string', 'integer-arith'}
        for tag in expected:
            self.assertIn(tag, tags, f'missing tag: {tag}')
        self.assertEqual(len(tags), len(expected))

    def test_no_tags_triggered(self):
        content = 'int a = 1; int b = 2; int c = a + b;'
        tags = tag_snippet({'content': content})
        self.assertEqual(tags, [])


class IngestorBinaryContentTests(unittest.TestCase):
    """Non-ASCII or binary content in tag analysis."""

    def test_null_bytes(self):
        content = 'void \x00pwn() { \x00\x00\x00 overflow(); }'
        tags = tag_snippet({'content': content})
        self.assertIsInstance(tags, list)

    def test_high_ascii_identifiers(self):
        content = 'void \xff\xfe\xfd() { int \x80\x81; }'
        tags = tag_snippet({'content': content})
        self.assertIsInstance(tags, list)


class IngestorPathExclusionTests(unittest.TestCase):
    """Edge cases in path exclusion logic."""

    def test_dotfile_path_excluded(self):
        self.assertTrue(should_exclude_path('.hidden/file.c'))

    def test_contrib_subdirectory_excluded(self):
        self.assertTrue(should_exclude_path('lib/contrib/foo.c'))

    def test_examples_excluded(self):
        self.assertTrue(should_exclude_path('docs/examples/demo.c'))

    def test_src_not_excluded(self):
        self.assertFalse(should_exclude_path('src/main/core.c'))

    def test_case_insensitive_exclusion(self):
        self.assertTrue(should_exclude_path('src/Tests/foo.c'))

    def test_very_long_path(self):
        long_path = '/'.join(['a' * 100] * 20) + '.c'
        result = should_exclude_path(long_path)
        self.assertIsInstance(result, bool)

    def test_non_library_returns_false(self):
        self.assertFalse(should_exclude_path('test/foo.c', is_library_target=False))


class IngestorExternalInputTests(unittest.TestCase):
    """Boundary conditions in external input detection."""

    def test_encoded_input_variants(self):
        self.assertTrue(detect_external_input('n = recvfrom(sock, buf, len, 0, NULL, NULL);'))
        self.assertTrue(detect_external_input('buf = request.body'))
        self.assertTrue(detect_external_input('arg = getenv("HOME")'))

    def test_non_library_target_broader(self):
        self.assertTrue(detect_external_input('var params = {}', is_library_target=False))
        self.assertFalse(detect_external_input('int x = 1;', is_library_target=False))

    def test_http_in_comment_not_confused(self):
        self.assertTrue(detect_external_input('// http request parser\nsize = len + offset;'))

    def test_socket_in_variable_name(self):
        self.assertTrue(detect_external_input('int my_socket_fd = 0;'))

    def test_external_input_empty_string(self):
        self.assertFalse(detect_external_input(''))


class IngestorIntegerArithTests(unittest.TestCase):
    """Complex integer arithmetic detection scenarios."""

    def test_len_math_with_untrusted(self):
        self.assertTrue(detect_integer_arith_untrusted('size = len + 4; n = recv(fd, buf, len, 0);'))

    def test_count_multiplication(self):
        self.assertTrue(detect_integer_arith_untrusted('alloc = count * sizeof(int); // tainted'))

    def test_index_arithmetic(self):
        self.assertTrue(detect_integer_arith_untrusted('pos = index - offset; n = recv(fd, buf, len, 0);'))

    def test_arith_without_untrusted(self):
        self.assertFalse(detect_integer_arith_untrusted('size = len + 4;'))

    def test_untrusted_without_arith(self):
        self.assertFalse(detect_integer_arith_untrusted('recv(fd, buf, len, 0);'))

    def test_division_expression(self):
        self.assertTrue(detect_integer_arith_untrusted('idx = count / 2; // tainted'))

    def test_modulo_expression(self):
        self.assertTrue(detect_integer_arith_untrusted('rem = len % 8; n = recv(fd, buf, len, 0);'))


class IngestorFilterSnippetsTests(unittest.TestCase):
    """Edge cases in snippet filtering."""

    def test_empty_snippets(self):
        self.assertEqual(filter_snippets([]), [])

    def test_all_excluded(self):
        snippets = [
            {'file': 'test/foo.c'},
            {'file': 'contrib/bar.c'},
            {'file': '.hidden/baz.c'},
        ]
        self.assertEqual(filter_snippets(snippets), [])

    def test_missing_file_key_not_excluded(self):
        snippets = [{'content': 'int x;'}, {'file': 'src/main.c', 'content': 'int y;'}]
        result = filter_snippets(snippets)
        self.assertEqual(len(result), 2)

    def test_none_file_key_raises(self):
        snippets = [{'file': None}, {'file': 'src/main.c'}]
        with self.assertRaises(TypeError):
            filter_snippets(snippets)


class IngestorCstIntegrationTests(unittest.TestCase):
    def test_load_repo_snippets_falls_back_to_file_snippet_without_cst(self):
        with TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / 'src').mkdir()
            path = repo / 'src' / 'main.c'
            path.write_text('#include <stdio.h>\nvoid main(void) { helper(); }\n')

            snippets = load_repo_snippets(repo)

            self.assertEqual(len(snippets), 1)
            self.assertEqual(snippets[0]['kind'], 'file')
            self.assertEqual(snippets[0]['imports'], ['stdio.h'])
            self.assertIn('helper', snippets[0]['callees'])

    def test_load_repo_snippets_uses_cst_output_when_available(self):
        with TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / 'src').mkdir()
            path = repo / 'src' / 'main.c'
            path.write_text('void ignored(void) {}\n')
            fake_snippets = [
                {
                    'id': 'sha256:aaaaaa:bbbbbb',
                    'file': 'src/main.c',
                    'language': 'c',
                    'kind': 'function',
                    'name': 'entry',
                    'lines': [1, 3],
                    'content': 'void entry(void) { helper(); }',
                    'imports': [],
                    'callees': ['helper'],
                    'callers': [],
                    'tags': ['external-input'],
                    'token_count': 12,
                    'continuation': False,
                },
                {
                    'id': 'sha256:cccccc:dddddd',
                    'file': 'src/main.c',
                    'language': 'c',
                    'kind': 'function',
                    'name': 'helper',
                    'lines': [5, 7],
                    'content': 'void helper(void) {}',
                    'imports': [],
                    'callees': [],
                    'callers': [],
                    'tags': [],
                    'token_count': 6,
                    'continuation': False,
                },
            ]
            with patch('stages.ingestor._extract_cst_snippets', return_value=fake_snippets):
                snippets = load_repo_snippets(repo)

            self.assertEqual([s['name'] for s in snippets], ['entry', 'helper'])
            helper = next(s for s in snippets if s['name'] == 'helper')
            self.assertEqual(helper['callers'], ['entry'])


if __name__ == '__main__':
    unittest.main()
