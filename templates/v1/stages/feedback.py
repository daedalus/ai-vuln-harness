"""Feedback stage — seed new Hunt tasks from confirmed, traced findings.

After Trace confirms that an attacker-controlled path reaches a sink, the
Feedback stage looks for the same attack class in sibling files (same
directory) that have not yet been covered.  This replicates the Glasswing /
Cloudflare Stage 7 feedback loop, where one real finding multiplies the
search surface before a final Report pass.

The key insight: if ``src/parser/lexer.c`` has a confirmed buffer-overflow,
the other files in ``src/parser/`` share the same coding idioms and should be
hunted for the same class before the pipeline closes.
"""

from __future__ import annotations

from pathlib import Path


def _sibling_files(
    source_file: str,
    all_files: set[str],
    *,
    exclude: set[str] | None = None,
) -> list[str]:
    """Return files in the same directory as *source_file* (excluding itself)."""
    parent = str(Path(source_file).parent)
    excluded = exclude or set()
    return sorted(
        f for f in all_files
        if str(Path(f).parent) == parent
        and f != source_file
        and f not in excluded
    )


def build_feedback_tasks(
    traced_findings: list[dict],
    all_snippets: list[dict],
    *,
    already_covered: set[str] | None = None,
    max_tasks: int = 10,
    scope_notes: str | None = None,
) -> list[dict]:
    """Generate new Hunt tasks from confirmed, traced findings.

    For each finding that has been trace-confirmed, emit a Hunt task targeting
    sibling files (same directory) that share the same attack class but have
    not been hunted yet.

    Parameters
    ----------
    traced_findings:
        Findings that reached ``trace_status = 'confirmed'`` or whose
        ``status`` is ``'confirmed'``.
    all_snippets:
        Full snippet list for the repo (used to discover sibling files).
    already_covered:
        File paths already targeted by existing Hunt tasks; siblings in this
        set are excluded so we never re-hunt what was already covered.
    max_tasks:
        Cap on the number of new tasks emitted (default 10).
    scope_notes:
        Optional operator scope notes forwarded verbatim into each task's
        ``scope_notes`` field.

    Returns
    -------
    list of new task dicts.
    """
    covered = already_covered or set()
    all_files = {str(s.get('file') or '') for s in all_snippets if s.get('file')}

    # Deduplicate on (parent_dir, attack_class) so we emit one task per
    # directory/class combo even when multiple findings point at the same area.
    seen_keys: set[tuple[str, str]] = set()
    tasks: list[dict] = []

    for finding in traced_findings:
        if len(tasks) >= max_tasks:
            break

        source_file = str(finding.get('file') or finding.get('snippet_id') or '')
        attack_class = str(
            finding.get('class')
            or finding.get('attack_class')
            or finding.get('domain')
            or ''
        )
        if not source_file or not attack_class:
            continue

        siblings = _sibling_files(source_file, all_files, exclude=covered)
        if not siblings:
            continue

        key = (str(Path(source_file).parent), attack_class)
        if key in seen_keys:
            continue
        seen_keys.add(key)

        task: dict = {
            'task_id': f'feedback_{attack_class}_{len(tasks) + 1}',
            'domain': attack_class,
            'attack_class': attack_class,
            'target_files': siblings,
            'rationale': (
                f'Feedback: confirmed {attack_class!r} in {source_file} — '
                f'scanning {len(siblings)} sibling file(s) for the same pattern.'
            ),
            'priority': 'high',
            'source': 'feedback',
            'seeded_by': source_file,
        }
        if scope_notes:
            task['scope_notes'] = scope_notes
        tasks.append(task)

    return tasks
