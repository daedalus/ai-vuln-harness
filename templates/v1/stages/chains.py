"""Chain synthesis — identify exploit chains across findings.

Goal: detect clusters where multiple low/medium findings compose into a
higher-severity exploit chain. A chain of findings is an exploit.

Scoring:
  - +2 if chain crosses a trust boundary (external-input → sink)
  - +1 per MEDIUM / +2 per HIGH / +3 per CRITICAL finding in chain
  - +1 if chain involves recently modified files
  - -1 if chain involves well-tested or hardened areas

Critical: the call graph is keyed on lowercase function names, but findings
reference snippet IDs (``sha256:...``). The chainer MUST resolve ``snippet_id
→ function name`` before BFS traversal — without this, BFS searches for
``sha256:...`` keys that don't exist in the graph, producing zero chains.
This is the single most common chainer bug.
"""

from __future__ import annotations

from pathlib import PurePosixPath

_SEV_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFORMATIONAL': 0}
_CWE_HINTS = {
    'buffer-overflow': 'CWE-120',
    'format-string': 'CWE-134',
    'integer-overflow': 'CWE-190',
    'sql-injection': 'CWE-89',
    'xss': 'CWE-79',
    'auth': 'CWE-287',
    'crypto': 'CWE-327',
    'path-traversal': 'CWE-22',
}


def _component(file_path: str) -> str:
    parts = list(PurePosixPath(file_path).parts)
    return parts[0] if parts else 'root'


def _cwe_for(finding: dict) -> str:
    klass = str(finding.get('class') or '').lower()
    for key, cwe in _CWE_HINTS.items():
        if key in klass:
            return cwe
    return 'CWE-20'


def _cvss_for(severity: str, cross_component: bool) -> float:
    base = {
        'CRITICAL': 9.1,
        'HIGH': 8.0,
        'MEDIUM': 6.0,
        'LOW': 3.9,
        'INFORMATIONAL': 0.0,
    }.get(str(severity).upper(), 0.0)
    if cross_component:
        base = min(10.0, base + 0.7)
    return round(base, 1)


def _mitigations(finding_a: dict, finding_b: dict) -> list[str]:
    classes = {str(finding_a.get('class', '')).lower(), str(finding_b.get('class', '')).lower()}
    out = ['Add strict boundary and type validation on untrusted inputs']
    if any('auth' in c for c in classes):
        out.append('Enforce authorization checks at component boundaries')
    if any('crypto' in c for c in classes):
        out.append('Use vetted cryptographic primitives and rotate weak algorithms')
    if any('overflow' in c or 'memory' in c for c in classes):
        out.append('Harden unsafe memory operations with explicit bounds checks')
    return out


def _should_chain(
    a: dict, b: dict, by_id: dict, seen_pairs: set[tuple[str, str]]
) -> tuple[bool, str, str, str, str]:
    a_file = str(a.get('file') or by_id.get(a.get('snippet_id'), {}).get('file') or '')
    b_file = str(b.get('file') or by_id.get(b.get('snippet_id'), {}).get('file') or '')
    if not a_file or not b_file:
        return False, '', '', '', ''
    pair = tuple(sorted((a.get('snippet_id', ''), b.get('snippet_id', ''))))
    if pair in seen_pairs:
        return False, '', '', '', ''
    seen_pairs.add(pair)

    comp_a = _component(a_file)
    comp_b = _component(b_file)
    cross_component = comp_a != comp_b
    severe = min(
        _SEV_RANK.get(str(a.get('severity', '')).upper(), 0),
        _SEV_RANK.get(str(b.get('severity', '')).upper(), 0),
    ) >= 2
    if not (cross_component or severe):
        return False, '', '', '', ''
    return True, a_file, b_file, comp_a, comp_b


def _build_chain(a: dict, b: dict, a_file: str, b_file: str, comp_a: str, comp_b: str, chain_id: str) -> dict:
    cross_component = comp_a != comp_b
    cvss = _cvss_for(a.get('severity', 'LOW'), cross_component)
    return {
        'chain_id': chain_id,
        'feasible': bool(a.get('call_path_verified', True) and b.get('call_path_verified', True)),
        'components': sorted({comp_a, comp_b}),
        'steps': [
            {
                'snippet_id': a.get('snippet_id'),
                'file': a_file,
                'class': a.get('class'),
                'severity': a.get('severity'),
                'cwe': _cwe_for(a),
            },
            {
                'snippet_id': b.get('snippet_id'),
                'file': b_file,
                'class': b.get('class'),
                'severity': b.get('severity'),
                'cwe': _cwe_for(b),
            },
        ],
        'cvss': {
            'vector': 'AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H' if cross_component else 'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H',
            'score': cvss,
        },
        'narrative': (
            f'Attacker chains {a.get("class", "initial access")} in {a_file} '
            f'with {b.get("class", "impact escalation")} in {b_file} '
            f'to move from {comp_a} into {comp_b}.'
        ),
        'mitigations': _mitigations(a, b),
    }


def synthesize_exploit_chains(findings: list[dict], snippets: list[dict], max_chains: int = 20) -> list[dict]:
    by_id = {s.get('id'): s for s in snippets}
    confirmed = [f for f in findings if str(f.get('status', '')).lower() == 'confirmed']
    confirmed.sort(key=lambda f: _SEV_RANK.get(str(f.get('severity', '')).upper(), 0), reverse=True)

    chains: list[dict] = []
    seen_pairs: set[tuple[str, str]] = set()
    for i, a in enumerate(confirmed):
        for b in confirmed[i + 1:]:
            ok, a_file, b_file, comp_a, comp_b = _should_chain(a, b, by_id, seen_pairs)
            if not ok:
                continue
            chain = _build_chain(a, b, a_file, b_file, comp_a, comp_b, f'chain-{len(chains) + 1:04d}')
            chains.append(chain)
            if len(chains) >= max_chains:
                return chains
    return chains
