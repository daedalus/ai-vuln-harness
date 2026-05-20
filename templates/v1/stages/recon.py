from __future__ import annotations

import re
import subprocess
from pathlib import Path

_SECURITY_PATTERNS: list[re.Pattern] = [
    re.compile(r'CVE-\d{4}-\d{4,}', re.I),
    re.compile(r'\bsec(?:urity)?[:\s]', re.I),
    re.compile(r'\bfix(?:es)?[.\s]*auth', re.I),
    re.compile(r'\bsanitize', re.I),
    re.compile(r'\boverflow\b', re.I),
    re.compile(r'\buaf\b', re.I),
    re.compile(r'\buse.after.free\b', re.I),
    re.compile(r'\bformat.string\b', re.I),
    re.compile(r'\binteger.overflow\b', re.I),
    re.compile(r'\bmemory.corruption\b', re.I),
    re.compile(r'\bprivilege.escalation\b', re.I),
    re.compile(r'\barbitrary.code\b', re.I),
    re.compile(r'\bremote.code\b', re.I),
    re.compile(r'\boob\b', re.I),
    re.compile(r'\bout.of.bounds\b', re.I),
    re.compile(r'\bspoof\b', re.I),
    re.compile(r'\bxss\b', re.I),
    re.compile(r'\bsql.injection\b', re.I),
    re.compile(r'\bpatch.*vuln', re.I),
    re.compile(r'\bvuln.*patch', re.I),
    re.compile(r'\bsecurity.fix\b', re.I),
    re.compile(r'\bhotfix\b', re.I),
]

_COMMIT_LINE_PREFIX = '---COMMIT---'


def _scan_git_security_patches(repo_path: str | Path) -> set[str]:
    try:
        check = subprocess.run(
            ['git', '-C', str(repo_path), 'log', '--all', '--oneline', '--max-count=500'],
            capture_output=True, text=True, timeout=15,
        )
    except (subprocess.SubprocessError, OSError):
        return set()
    if check.returncode != 0 or not check.stdout.strip():
        return set()

    has_hit = any(
        any(p.search(line.split(' ', 1)[-1] if ' ' in line else line)
            for p in _SECURITY_PATTERNS)
        for line in check.stdout.splitlines()
    )
    if not has_hit:
        return set()

    try:
        result = subprocess.run(
            ['git', '-C', str(repo_path), 'log', '--all', '--diff-filter=M',
             '--name-only', f'--pretty=format:{_COMMIT_LINE_PREFIX}%s'],
            capture_output=True, text=True, timeout=30,
        )
    except (subprocess.SubprocessError, OSError):
        return set()
    if result.returncode != 0:
        return set()

    patched: set[str] = set()
    in_interesting_commit = False

    for line in result.stdout.splitlines():
        if line.startswith(_COMMIT_LINE_PREFIX):
            subject = line[len(_COMMIT_LINE_PREFIX):]
            in_interesting_commit = any(p.search(subject) for p in _SECURITY_PATTERNS)
        elif in_interesting_commit and line.strip():
            patched.add(line.strip())

    return patched


def _find_sibling_files(
    patched_files: set[str],
    all_files: set[str],
) -> set[str]:
    patched_dirs: dict[str, set[str]] = {}
    for f in patched_files:
        d = str(Path(f).parent)
        patched_dirs.setdefault(d, set()).add(Path(f).name)

    siblings: set[str] = set()
    for f in all_files:
        p = Path(f)
        d = str(p.parent)
        if d in patched_dirs and p.name not in patched_dirs[d]:
            siblings.add(f)
    return siblings


def build_recon_tasks(
    snippets: list[dict],
    repo_path: str | Path | None = None,
) -> list[dict]:
    domain_to_files: dict[str, set[str]] = {}

    for s in snippets:
        file = s.get('file', '')
        tags = s.get('tags', [])
        if any(t in tags for t in ('memory', 'unsafe', 'integer-arith')):
            domain_to_files.setdefault('mem-safety', set()).add(file)
        if 'auth' in tags:
            domain_to_files.setdefault('auth', set()).add(file)
        if 'crypto' in tags:
            domain_to_files.setdefault('crypto', set()).add(file)
        if 'ipc' in tags:
            domain_to_files.setdefault('ipc', set()).add(file)
        if 'external-input' in tags:
            domain_to_files.setdefault('data-flow', set()).add(file)
        if 'format-string' in tags:
            domain_to_files.setdefault('format-str', set()).add(file)

    if repo_path is not None:
        all_files = {s['file'] for s in snippets if 'file' in s}
        patched = _scan_git_security_patches(repo_path)
        if patched:
            siblings = _find_sibling_files(patched, all_files)
            if siblings:
                domain_to_files.setdefault('patch-gap', set()).update(siblings)

    tasks = []
    for idx, (domain, files) in enumerate(sorted(domain_to_files.items()), start=1):
        priority = (
            'high' if domain in {'mem-safety', 'data-flow', 'crypto', 'patch-gap'} else 'medium'
        )
        tasks.append({
            'task_id': f't_{domain}_{idx}',
            'domain': domain,
            'attack_class': domain,
            'target_files': sorted(files),
            'rationale': (
                f'sibling files of security-patched files (git history grep)'
                if domain == 'patch-gap' else
                f'{domain} targets derived from tags'
            ),
            'priority': priority,
        })
    return tasks
