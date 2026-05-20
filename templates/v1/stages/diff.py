"""Incremental / diff-driven scanning support.

Parses ``git diff --unified=0 BASE HEAD`` output to determine which
source-code line ranges changed between two commits, then filters an
already-extracted snippet list down to only the snippets whose line
ranges overlap with a changed hunk.

Usage example::

    from stages.diff import get_changed_snippets

    changed = get_changed_snippets(
        repo=Path('/path/to/repo'),
        snippets=all_snippets,
        base_commit='main',
        head_commit='HEAD',
    )
    # ``changed`` is a (possibly empty) subset of ``all_snippets`` — feed
    # it into the rest of the pipeline in place of the full snippet list.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

# Matches the ``+<start>[,<count>]`` part of a unified-diff hunk header.
# Example lines: ``@@ -3,7 +3,6 @@ ...``  → group(1)="3", group(2)="6"
_HUNK_RE = re.compile(r'^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@')


def get_changed_line_ranges(
    repo: Path,
    base_commit: str,
    head_commit: str = 'HEAD',
) -> dict[str, list[tuple[int, int]]]:
    """Return changed line ranges per file by diffing two commits.

    Runs ``git diff --unified=0 <base> <head>`` inside *repo* and parses
    the unified-diff output.

    Returns a dict mapping each changed file path (relative to the repo
    root, using forward slashes) to a list of ``(start_line, end_line)``
    tuples covering every added/modified hunk in the *head* tree.

    Pure-deletion hunks (``+N,0``) are recorded as the single-line range
    ``(N, N)`` so that functions containing the deletion site are still
    included in the scan.

    Returns an empty dict if *git* is not available or the diff fails.
    """
    try:
        result = subprocess.run(
            ['git', 'diff', '--unified=0', base_commit, head_commit],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=True,
        )
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return {}

    changed: dict[str, list[tuple[int, int]]] = {}
    current_file: str | None = None

    for line in result.stdout.splitlines():
        if line.startswith('+++ '):
            # ``+++ b/relative/path`` for changed files; ``+++ /dev/null`` for deletions.
            rest = line[4:]
            if rest.startswith('b/'):
                current_file = rest[2:]
                changed.setdefault(current_file, [])
            else:
                current_file = None  # deleted file — no new lines to scan
        elif line.startswith('@@ ') and current_file is not None:
            m = _HUNK_RE.match(line)
            if not m:
                continue
            start = int(m.group(1))
            count_str = m.group(2)
            if count_str is None:
                count = 1
            else:
                count = int(count_str)

            if count == 0:
                # Pure deletion: no new lines, but record position for context.
                end = max(start, 1)
            else:
                end = start + count - 1

            changed[current_file].append((start, end))

    return changed


def _ranges_overlap(
    snippet_start: int,
    snippet_end: int,
    ranges: list[tuple[int, int]],
) -> bool:
    """Return True if [snippet_start, snippet_end] overlaps any range in *ranges*."""
    for r_start, r_end in ranges:
        if snippet_start <= r_end and r_start <= snippet_end:
            return True
    return False


def filter_snippets_by_diff(
    snippets: list[dict],
    changed_ranges: dict[str, list[tuple[int, int]]],
) -> list[dict]:
    """Return the subset of *snippets* that overlap with *changed_ranges*.

    A snippet matches when its ``file`` key appears in *changed_ranges*
    **and** its ``lines`` range overlaps at least one changed hunk.

    Snippets from files not present in *changed_ranges* are dropped
    (no changes detected in those files).  Snippets whose ``lines``
    field is missing or malformed are treated as covering line 1 only.
    """
    if not changed_ranges:
        return []

    result: list[dict] = []
    for snippet in snippets:
        file_key = snippet.get('file', '')
        ranges = changed_ranges.get(file_key)
        if not ranges:
            continue

        lines = snippet.get('lines')
        if isinstance(lines, (list, tuple)) and len(lines) >= 2:
            s_start, s_end = int(lines[0]), int(lines[1])
        else:
            s_start = s_end = 1

        if _ranges_overlap(s_start, s_end, ranges):
            result.append(snippet)

    return result


def get_changed_snippets(
    repo: Path,
    snippets: list[dict],
    base_commit: str,
    head_commit: str = 'HEAD',
) -> list[dict]:
    """Filter *snippets* to only those changed between *base_commit* and *head_commit*.

    This is the primary entry point for diff-driven scanning::

        changed = get_changed_snippets(repo, all_snippets, 'main', 'HEAD')

    Returns a subset of *snippets* (preserving order).  Returns an empty
    list when git is unavailable or no snippets overlap with the diff.
    """
    changed_ranges = get_changed_line_ranges(repo, base_commit, head_commit)
    return filter_snippets_by_diff(snippets, changed_ranges)
