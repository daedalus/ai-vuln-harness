from __future__ import annotations

import re
import subprocess
from pathlib import Path
from collections import defaultdict

_LOGIC_CHAIN_TAG_PAIRS: list[frozenset[str]] = [
    frozenset({'auth', 'external-input'}),
    frozenset({'auth', 'ipc'}),
    frozenset({'memory', 'ipc'}),
    frozenset({'memory', 'external-input'}),
    frozenset({'crypto', 'external-input'}),
    frozenset({'auth', 'memory'}),
]

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

_DOMAIN_TAGS: dict[str, set[str]] = {
    'mem-safety': {'memory', 'unsafe', 'integer-arith'},
    'auth': {'auth'},
    'crypto': {'crypto'},
    'ipc': {'ipc'},
    'data-flow': {'external-input'},
    'format-str': {'format-string'},
}


def _map_snippet_to_domains(
    snippet: dict,
    domain_to_files: dict[str, set[str]],
) -> None:
    file = snippet.get('file', '')
    if not file:
        return
    tags = set(snippet.get('tags', []))
    for domain, trigger_tags in _DOMAIN_TAGS.items():
        if trigger_tags & tags:
            domain_to_files.setdefault(domain, set()).add(file)


def _build_task(
    domain: str,
    files: set[str],
    idx: int,
    dependency_graph: dict | None = None,
    scope_notes: str | None = None,
) -> dict:
    _HIGH_PRIORITY = {'mem-safety', 'data-flow', 'crypto', 'patch-gap', 'logic-chain', 'supply-chain'}
    priority = 'high' if domain in _HIGH_PRIORITY else 'medium'
    rationale_map = {
        'patch-gap': 'sibling files of security-patched files (git history grep)',
        'logic-chain': (
            'multi-component attack chain: file contains tag combinations '
            'that can compose into complex exploit paths'
        ),
        'supply-chain': (
            'files with external dependency edges; prioritize cross-repo '
            'supply-chain discovery paths'
        ),
    }
    rationale = rationale_map.get(domain, f'{domain} targets derived from tags')
    task: dict = {
        'task_id': f't_{domain}_{idx}',
        'domain': domain,
        'attack_class': domain,
        'target_files': sorted(files),
        'rationale': rationale,
        'priority': priority,
    }
    if domain == 'logic-chain':
        task['task_type'] = 'logic_chain'
    if domain == 'supply-chain':
        task['task_type'] = 'supply_chain'
        task['dependency_graph'] = dependency_graph
        task['cross_repo_targets'] = dependency_graph['external_dependencies']
    if scope_notes:
        task['scope_notes'] = scope_notes
    return task


def _scan_git_security_patches(repo_path: str | Path) -> set[str]:
    try:
        check = subprocess.run(
            ['git', '-C', str(repo_path), 'log', '--all', '--oneline', '--max-count=2000'],
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


def _detect_logic_chains(snippets: list[dict]) -> dict[str, set[str]]:
    """Find files containing tag combinations that suggest multi-component attack chains.

    A logic-chain file has two or more high-value tags that can compose into a
    complex attack path (e.g., ``auth`` + ``external-input`` can compose into
    an authentication-bypass triggered by attacker-controlled data).  These
    files merit a single Hunt task scoped to the full chain rather than
    individual attack classes.
    """
    chain_files: set[str] = set()
    for s in snippets:
        tags = set(s.get('tags') or [])
        file = s.get('file', '')
        if not file:
            continue
        for pair in _LOGIC_CHAIN_TAG_PAIRS:
            if pair.issubset(tags):
                chain_files.add(file)
                break
    if chain_files:
        return {'logic-chain': chain_files}
    return {}


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


def _normalise_dependency_name(raw: str) -> str:
    dep = raw.strip().strip('"').strip("'")
    if dep.startswith('@'):
        parts = dep.split('/')
        return '/'.join(parts[:2]) if len(parts) >= 2 else dep
    separators = ['/', '.', '::']
    for sep in separators:
        if sep in dep:
            dep = dep.split(sep, 1)[0]
            break
    return dep


def _is_external_dependency(dep: str) -> bool:
    dep = dep.strip()
    if not dep:
        return False
    if dep.startswith(('.', '/')):
        return False
    if dep.endswith(('.c', '.cc', '.cpp', '.h', '.py', '.go', '.rs', '.ts', '.js')):
        return False
    return True


def build_dependency_graph(snippets: list[dict]) -> dict:
    dep_to_files: dict[str, set[str]] = defaultdict(set)
    file_to_deps: dict[str, set[str]] = defaultdict(set)
    for snippet in snippets:
        file = str(snippet.get('file') or '')
        if not file:
            continue
        for imp in snippet.get('imports') or []:
            dep = _normalise_dependency_name(str(imp))
            if not _is_external_dependency(dep):
                continue
            dep_to_files[dep].add(file)
            file_to_deps[file].add(dep)
    return {
        'external_dependencies': sorted(dep_to_files.keys()),
        'dependency_to_files': {k: sorted(v) for k, v in sorted(dep_to_files.items())},
        'file_to_dependencies': {k: sorted(v) for k, v in sorted(file_to_deps.items())},
        'files_with_external_deps': sorted(file_to_deps.keys()),
    }


def build_recon_tasks(
    snippets: list[dict],
    repo_path: str | Path | None = None,
    scope_notes: str | None = None,
) -> list[dict]:
    domain_to_files: dict[str, set[str]] = {}

    for s in snippets:
        _map_snippet_to_domains(s, domain_to_files)

    if repo_path is not None:
        all_files = {s['file'] for s in snippets if 'file' in s}
        patched = _scan_git_security_patches(repo_path)
        if patched:
            siblings = _find_sibling_files(patched, all_files)
            if siblings:
                domain_to_files.setdefault('patch-gap', set()).update(siblings)

    for domain, files in _detect_logic_chains(snippets).items():
        domain_to_files.setdefault(domain, set()).update(files)

    dependency_graph = build_dependency_graph(snippets)
    if dependency_graph['files_with_external_deps']:
        domain_to_files.setdefault('supply-chain', set()).update(dependency_graph['files_with_external_deps'])

    tasks = []
    for idx, (domain, files) in enumerate(sorted(domain_to_files.items()), start=1):
        tasks.append(_build_task(domain, files, idx, dependency_graph, scope_notes))
    return tasks
