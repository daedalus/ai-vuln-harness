"""Tests for stages/diff.py — incremental / diff-driven scanning."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from stages.diff import (
    filter_snippets_by_diff,
    get_changed_line_ranges,
    get_changed_snippets,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _snippet(file: str, start: int, end: int, name: str = 'fn') -> dict:
    return {
        'id': f'sha256:aabbcc:ddeeff',
        'file': file,
        'name': name,
        'lines': [start, end],
        'content': '',
        'tags': [],
    }


# Minimal unified-diff output (only +++ and @@ lines matter for the parser)
_SAMPLE_DIFF = """\
diff --git a/src/foo.c b/src/foo.c
index abc1234..def5678 100644
--- a/src/foo.c
+++ b/src/foo.c
@@ -10,5 +10,7 @@ void old_func() {
+    new_line_a();
+    new_line_b();
diff --git a/src/bar.c b/src/bar.c
index 111..222 100644
--- a/src/bar.c
+++ b/src/bar.c
@@ -1,3 +1,0 @@ void bar() {
"""

# Diff with a pure deletion hunk (+N,0)
_DELETION_DIFF = """\
diff --git a/lib/baz.c b/lib/baz.c
--- a/lib/baz.c
+++ b/lib/baz.c
@@ -5,2 +5,0 @@ void baz() {
"""

# Diff for a deleted file (+++ /dev/null)
_DELETED_FILE_DIFF = """\
diff --git a/gone.c b/gone.c
--- a/gone.c
+++ /dev/null
@@ -1,4 +0,0 @@ void gone() {
"""


# ---------------------------------------------------------------------------
# get_changed_line_ranges — unit tests using subprocess mock
# ---------------------------------------------------------------------------

class GetChangedLineRangesTests(unittest.TestCase):
    def _run_with_diff(self, diff_output: str) -> dict:
        mock_result = MagicMock()
        mock_result.stdout = diff_output
        with patch('subprocess.run', return_value=mock_result) as mock_run:
            result = get_changed_line_ranges(Path('/repo'), 'main', 'HEAD')
            mock_run.assert_called_once()
        return result

    def test_basic_diff_parsed(self):
        ranges = self._run_with_diff(_SAMPLE_DIFF)
        self.assertIn('src/foo.c', ranges)
        self.assertIn('src/bar.c', ranges)

    def test_hunk_range_for_added_lines(self):
        ranges = self._run_with_diff(_SAMPLE_DIFF)
        # @@ -10,5 +10,7 @@ → start=10, count=7 → end=16
        self.assertEqual(ranges['src/foo.c'], [(10, 16)])

    def test_pure_deletion_hunk_recorded(self):
        ranges = self._run_with_diff(_DELETION_DIFF)
        self.assertIn('lib/baz.c', ranges)
        # +5,0 → pure deletion → recorded as (5, 5)
        self.assertEqual(ranges['lib/baz.c'], [(5, 5)])

    def test_deleted_file_not_included(self):
        ranges = self._run_with_diff(_DELETED_FILE_DIFF)
        self.assertNotIn('gone.c', ranges)

    def test_empty_diff_returns_empty_dict(self):
        ranges = self._run_with_diff('')
        self.assertEqual(ranges, {})

    def test_git_failure_returns_empty_dict(self):
        with patch('subprocess.run', side_effect=subprocess.CalledProcessError(1, 'git')):
            result = get_changed_line_ranges(Path('/repo'), 'abc', 'def')
        self.assertEqual(result, {})

    def test_git_not_found_returns_empty_dict(self):
        with patch('subprocess.run', side_effect=FileNotFoundError('git not found')):
            result = get_changed_line_ranges(Path('/repo'), 'abc', 'def')
        self.assertEqual(result, {})

    def test_single_line_hunk_no_count(self):
        """A hunk like ``@@ -5 +5 @@`` (no comma) means one line."""
        diff = '+++ b/single.c\n@@ -5 +5 @@ void fn() {\n'
        ranges = self._run_with_diff(diff)
        self.assertEqual(ranges['single.c'], [(5, 5)])

    def test_multiple_hunks_same_file(self):
        diff = (
            '+++ b/multi.c\n'
            '@@ -1,3 +1,3 @@ void a() {\n'
            '@@ -20,5 +20,2 @@ void b() {\n'
        )
        ranges = self._run_with_diff(diff)
        self.assertEqual(ranges['multi.c'], [(1, 3), (20, 21)])


# ---------------------------------------------------------------------------
# filter_snippets_by_diff
# ---------------------------------------------------------------------------

class FilterSnippetsByDiffTests(unittest.TestCase):
    def test_empty_snippets(self):
        ranges = {'src/foo.c': [(10, 20)]}
        self.assertEqual(filter_snippets_by_diff([], ranges), [])

    def test_empty_ranges(self):
        snippets = [_snippet('src/foo.c', 1, 50)]
        self.assertEqual(filter_snippets_by_diff(snippets, {}), [])

    def test_overlapping_snippet_included(self):
        snippets = [_snippet('src/foo.c', 8, 20)]
        ranges = {'src/foo.c': [(10, 16)]}
        result = filter_snippets_by_diff(snippets, ranges)
        self.assertEqual(len(result), 1)
        self.assertIs(result[0], snippets[0])

    def test_non_overlapping_snippet_excluded(self):
        snippets = [_snippet('src/foo.c', 25, 40)]
        ranges = {'src/foo.c': [(10, 16)]}
        result = filter_snippets_by_diff(snippets, ranges)
        self.assertEqual(result, [])

    def test_adjacent_but_not_overlapping_excluded(self):
        # snippet ends at 9, hunk starts at 10 — no overlap
        snippets = [_snippet('src/foo.c', 1, 9)]
        ranges = {'src/foo.c': [(10, 16)]}
        self.assertEqual(filter_snippets_by_diff(snippets, ranges), [])

    def test_snippet_in_unchanged_file_excluded(self):
        snippets = [_snippet('src/other.c', 1, 50)]
        ranges = {'src/foo.c': [(10, 16)]}
        self.assertEqual(filter_snippets_by_diff(snippets, ranges), [])

    def test_exact_boundary_overlap_included(self):
        # snippet is exactly one line that equals the hunk boundary
        snippets = [_snippet('src/foo.c', 10, 10)]
        ranges = {'src/foo.c': [(10, 10)]}
        self.assertEqual(len(filter_snippets_by_diff(snippets, ranges)), 1)

    def test_snippet_spans_entire_hunk(self):
        snippets = [_snippet('src/foo.c', 1, 100)]
        ranges = {'src/foo.c': [(10, 16)]}
        self.assertEqual(len(filter_snippets_by_diff(snippets, ranges)), 1)

    def test_multiple_snippets_mixed(self):
        snippets = [
            _snippet('src/foo.c', 1, 9, 'before'),
            _snippet('src/foo.c', 10, 20, 'inside'),
            _snippet('src/foo.c', 21, 40, 'after'),
        ]
        ranges = {'src/foo.c': [(10, 20)]}
        result = filter_snippets_by_diff(snippets, ranges)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['name'], 'inside')

    def test_missing_lines_field_treated_as_line_1(self):
        snippet = {'file': 'src/foo.c', 'name': 'fn'}
        ranges = {'src/foo.c': [(1, 5)]}
        result = filter_snippets_by_diff([snippet], ranges)
        self.assertEqual(len(result), 1)

    def test_order_preserved(self):
        snippets = [
            _snippet('a.c', 5, 10, 'fn_a'),
            _snippet('b.c', 1, 20, 'fn_b'),
            _snippet('a.c', 30, 40, 'fn_c'),
        ]
        ranges = {'a.c': [(5, 10), (30, 40)], 'b.c': [(1, 20)]}
        result = filter_snippets_by_diff(snippets, ranges)
        self.assertEqual([s['name'] for s in result], ['fn_a', 'fn_b', 'fn_c'])


# ---------------------------------------------------------------------------
# get_changed_snippets (integration of the two helpers)
# ---------------------------------------------------------------------------

class GetChangedSnippetsTests(unittest.TestCase):
    def _mock_ranges(self, ranges: dict):
        return patch('stages.diff.get_changed_line_ranges', return_value=ranges)

    def test_delegates_to_filter(self):
        snippets = [_snippet('src/foo.c', 10, 20)]
        ranges = {'src/foo.c': [(10, 20)]}
        with self._mock_ranges(ranges):
            result = get_changed_snippets(Path('/repo'), snippets, 'main')
        self.assertEqual(len(result), 1)

    def test_no_diff_returns_empty(self):
        snippets = [_snippet('src/foo.c', 1, 50)]
        with self._mock_ranges({}):
            result = get_changed_snippets(Path('/repo'), snippets, 'main')
        self.assertEqual(result, [])

    def test_head_commit_defaults_to_HEAD(self):
        """get_changed_line_ranges should be called with head_commit='HEAD'."""
        captured = {}

        def mock_ranges(repo, base, head):
            captured['head'] = head
            return {}

        with patch('stages.diff.get_changed_line_ranges', side_effect=mock_ranges):
            get_changed_snippets(Path('/repo'), [], 'main')

        self.assertEqual(captured['head'], 'HEAD')

    def test_custom_head_commit_forwarded(self):
        captured = {}

        def mock_ranges(repo, base, head):
            captured['head'] = head
            return {}

        with patch('stages.diff.get_changed_line_ranges', side_effect=mock_ranges):
            get_changed_snippets(Path('/repo'), [], 'v1.0', 'v2.0')

        self.assertEqual(captured['head'], 'v2.0')


if __name__ == '__main__':
    unittest.main()
