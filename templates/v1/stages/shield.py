"""Shielding utilities: call-path graph verification, static reachability,
hallucination detection (token-overlap + KL-divergence), and semantic
deduplication (cosine similarity).

These run as post-hunt, pre-Validate filters to catch the most common sources
of false positives before spending Validate API calls on them.
"""

from __future__ import annotations

import math
import re
from collections import Counter, deque


# ---------------------------------------------------------------------------
# Call-path graph verification (improvement ①)
# ---------------------------------------------------------------------------

def build_call_graph(snippets: list[dict]) -> dict[str, set[str]]:
    """Build a caller→callees adjacency map from the snippet DB.

    Each snippet may declare ``callers`` and ``callees`` lists.  We index by
    snippet name (lower-cased) so we can match call_path entries regardless of
    capitalisation variance introduced by LLMs.
    """
    graph: dict[str, set[str]] = {}
    for s in snippets:
        name = str(s.get('name') or s.get('id') or '').lower()
        callees = [c.lower() for c in (s.get('callees') or [])]
        if name:
            graph.setdefault(name, set()).update(callees)
    return graph


def _call_path_names(finding: dict) -> list[str]:
    return [str(n).lower() for n in (finding.get('call_path') or [])]


def verify_call_path(finding: dict, graph: dict[str, set[str]]) -> tuple[bool, str]:
    """Return ``(ok, reason)``.

    A call path is considered *verified* when every consecutive hop (A→B) in
    the path exists as an edge in the call graph.  An empty path is *not*
    verified — see the ``fix_now`` gate in ``report.py``.

    If the graph is empty (no callers/callees data in the snippet DB), we
    return ``(True, 'no-graph-data')`` rather than penalising all findings.
    """
    if not graph:
        return True, 'no-graph-data'

    path = _call_path_names(finding)
    if not path:
        return False, 'empty-call-path'
    if len(path) == 1:
        # Single-hop: check the function exists in the graph at all
        if path[0] in graph:
            return True, 'single-node-present'
        return False, f'function {path[0]!r} not found in call graph'

    missing = []
    for i in range(len(path) - 1):
        caller, callee = path[i], path[i + 1]
        if caller not in graph or callee not in graph.get(caller, set()):
            missing.append(f'{path[i]}→{path[i+1]}')

    if missing:
        return False, f'unverified hops: {", ".join(missing)}'
    return True, 'verified'


def annotate_call_path_verification(
    findings: list[dict],
    graph: dict[str, set[str]],
) -> list[dict]:
    """Return findings with ``call_path_verified`` and ``call_path_reason``
    fields added.  Does not drop findings — callers decide what to do."""
    out = []
    for f in findings:
        ok, reason = verify_call_path(f, graph)
        out.append({**f, 'call_path_verified': ok, 'call_path_reason': reason})
    return out


# ---------------------------------------------------------------------------
# Static reachability pre-filter (improvement ⑦)
# ---------------------------------------------------------------------------

def _reachable_from(start: str, targets: set[str], graph: dict[str, set[str]], max_hops: int = 6) -> bool:
    """BFS: is any name in *targets* reachable from *start* within *max_hops*?"""
    visited: set[str] = set()
    queue: deque[tuple[str, int]] = deque([(start, 0)])
    while queue:
        node, depth = queue.popleft()
        if node in visited:
            continue
        visited.add(node)
        if node in targets:
            return True
        if depth >= max_hops:
            continue
        for neighbour in graph.get(node, set()):
            if neighbour not in visited:
                queue.append((neighbour, depth + 1))
    return False


def filter_unreachable(
    findings: list[dict],
    graph: dict[str, set[str]],
    entry_points: list[str],
    max_hops: int = 6,
) -> tuple[list[dict], list[dict]]:
    """Split findings into (reachable, unreachable).

    A finding is *reachable* when at least one entry point can reach the
    snippet's function name (or any name in its call_path) within *max_hops*
    in the call graph.

    If there are no entry points or no graph data, all findings are returned
    as reachable (fail-open to avoid silently discarding real bugs).
    """
    if not graph or not entry_points:
        return findings, []

    entry_set = {e.lower() for e in entry_points}
    reachable: list[dict] = []
    unreachable: list[dict] = []

    for f in findings:
        # Collect candidate target names from snippet + call_path
        targets: set[str] = set()
        sid = str(f.get('snippet_id') or '')
        if sid:
            targets.add(sid.lower())
        for name in _call_path_names(f):
            targets.add(name)

        found = False
        for ep in entry_set:
            if _reachable_from(ep, targets, graph, max_hops):
                found = True
                break

        if found:
            reachable.append(f)
        else:
            unreachable.append({**f, 'static_reachability': 'unreachable'})

    return reachable, unreachable


# ---------------------------------------------------------------------------
# Hallucination detector (improvement ⑧)
# ---------------------------------------------------------------------------

def _tokenise(text: str) -> set[str]:
    """Extract identifier-like tokens (≥4 chars) from a string."""
    return {t.lower() for t in re.findall(r'[A-Za-z_][A-Za-z0-9_]{3,}', text)}


def detect_hallucination(finding: dict, snippet: dict) -> tuple[bool, str]:
    """Return ``(hallucinated, reason)``.

    Checks that:
    1. Identifier tokens cited in ``desc`` (>5 chars) appear in the snippet content.
    2. Each function name in ``call_path`` appears somewhere in the snippet content
       or its callers/callees lists.

    Strings shorter than 4 characters are skipped (too generic).
    If the snippet has no content, the check is skipped (fail-open).
    """
    content = str(snippet.get('content') or '').lower()
    if not content:
        return False, 'no-snippet-content'

    content_tokens = _tokenise(content)
    # Also include explicit callers/callees names
    for name in list(snippet.get('callers') or []) + list(snippet.get('callees') or []):
        content_tokens.add(name.lower())

    # --- desc token check ---
    desc = str(finding.get('desc') or '')
    desc_tokens = {t for t in _tokenise(desc) if len(t) > 5}
    missing_desc = desc_tokens - content_tokens
    # Allow up to 30% of desc tokens to be absent (LLMs paraphrase)
    if desc_tokens and len(missing_desc) / len(desc_tokens) > 0.60:
        return True, f'desc tokens not in snippet: {sorted(missing_desc)[:5]}'

    # --- call_path check ---
    missing_path = []
    for name in _call_path_names(finding):
        if len(name) > 3 and name not in content_tokens:
            missing_path.append(name)
    # Flag only if *most* call path names are absent
    path_names = [n for n in _call_path_names(finding) if len(n) > 3]
    if path_names and len(missing_path) / len(path_names) > 0.70:
        return True, f'call_path names not in snippet: {missing_path[:5]}'

    return False, 'ok'


def annotate_hallucination(
    findings: list[dict],
    snippet_db: dict[str, dict],
) -> list[dict]:
    """Add ``hallucination_detected`` and ``hallucination_reason`` to each finding."""
    out = []
    for f in findings:
        snippet = snippet_db.get(f.get('snippet_id', ''), {})
        hallucinated, reason = detect_hallucination(f, snippet)
        out.append({**f, 'hallucination_detected': hallucinated, 'hallucination_reason': reason})
    return out


# ---------------------------------------------------------------------------
# KL-divergence hallucination detection
# ---------------------------------------------------------------------------

def _token_freqs(text: str) -> Counter:
    """Tokenise and return a frequency counter over identifier-like tokens (>=4 chars)."""
    return Counter(t.lower() for t in re.findall(r'[A-Za-z_][A-Za-z0-9_]{3,}', text))


def _normalise(counter: Counter) -> dict[str, float]:
    """Return a probability dict from a counter (no smoothing)."""
    total = sum(counter.values())
    if total == 0:
        return {}
    return {t: c / total for t, c in counter.items()}


def kl_divergence(p: dict[str, float], q: dict[str, float]) -> float:
    """KL(P ‖ Q) over the support of P only.

    Tokens present in P but absent from Q contribute
    ``P(t) * log(P(t) / epsilon)`` where epsilon = 1e-8, so
    fully absent vocabulary pushes KL toward infinity.
    """
    eps = 1e-8
    d = 0.0
    for t, p_t in p.items():
        q_t = q.get(t, eps)
        d += p_t * math.log(p_t / q_t)
    return d


def detect_hallucination_kl(
    finding: dict,
    snippet: dict,
    threshold: float = 5.0,
) -> tuple[bool, str]:
    """Return ``(hallucinated, reason)`` using KL-divergence.

    Computes KL(desc_distribution ‖ code_distribution) over the desc
    vocabulary only.  Desc tokens absent from the code get a very small
    epsilon probability, making their contribution
    ``P(t) * log(P(t) / 1e-8)`` ≈ P(t) * 18.4 — which dominates when
    the model is using vocabulary unrelated to the source code.

    Fail-open when snippet content or desc is empty.
    """
    content = str(snippet.get('content') or '')
    if not content:
        return False, 'no-snippet-content'

    desc = str(finding.get('desc') or '')
    if not desc.strip():
        return False, 'no-desc'

    p_counts = _token_freqs(desc)
    q_counts = _token_freqs(content)

    if not p_counts:
        return False, 'no-desc-tokens'

    if not q_counts:
        return True, 'desc-tokens-absent-from-empty-code'

    p_probs = _normalise(p_counts)
    q_probs = _normalise(q_counts)

    kl = kl_divergence(p_probs, q_probs)

    missing = sorted(p_counts.keys() - q_counts.keys())[:5]

    if kl >= threshold:
        return True, f'KL={kl:.2f} (threshold={threshold}); desc tokens missing from code: {missing}'

    return False, f'KL={kl:.2f} (ok)'


def annotate_hallucination_kl(
    findings: list[dict],
    snippet_db: dict[str, dict],
    threshold: float = 2.0,
) -> list[dict]:
    """Add ``hallucination_kl`` (float), ``hallucination_kl_detected`` (bool),
    and ``hallucination_kl_reason`` (str) to each finding."""
    out = []
    for f in findings:
        snippet = snippet_db.get(f.get('snippet_id', ''), {})
        detected, reason = detect_hallucination_kl(f, snippet, threshold)
        out.append({
            **f,
            'hallucination_kl': float('nan') if reason.startswith('no-') else None,
            'hallucination_kl_detected': detected,
            'hallucination_kl_reason': reason,
        })
    return out


# ---------------------------------------------------------------------------
# Cosine-similarity semantic deduplication
# ---------------------------------------------------------------------------

def _tf_vector(tokens: list[str], vocab: dict[str, int]) -> list[float]:
    """Build a unit-normalised TF vector for *tokens* against *vocab*."""
    n = len(vocab)
    vec = [0.0] * n
    for t in tokens:
        idx = vocab.get(t)
        if idx is not None:
            vec[idx] += 1.0
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        vec = [v / norm for v in vec]
    return vec


def _desc_tokens(finding: dict) -> list[str]:
    return re.findall(r'[A-Za-z_][A-Za-z0-9_]{3,}', (finding.get('desc') or '').lower())


def cosine_similarity(a: list[float], b: list[float]) -> float:
    """Cosine similarity between two vectors of equal length."""
    if len(a) != len(b):
        raise ValueError(f'vector length mismatch: {len(a)} vs {len(b)}')
    dot = sum(ai * bi for ai, bi in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def deduplicate_semantic(
    findings: list[dict],
    threshold: float = 0.85,
) -> list[dict]:
    """Deduplicate findings by cosine similarity of their descriptions.

    Builds a TF vector for each finding's ``desc`` field and groups findings
    whose pairwise cosine similarity exceeds *threshold*.  Within each group
    the highest-severity finding is kept.

    Use this *alongside* the composite-key dedup in ``report.deduplicate()``:
    that catches same-function-same-class duplicates, while this catches
    semantically identical bugs reported across different functions by
    different hunter agents.
    """
    if not findings:
        return []

    _SEV_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFORMATIONAL': 0}

    token_lists = [_desc_tokens(f) for f in findings]
    all_tokens = sorted({t for tl in token_lists for t in tl})
    vocab = {t: i for i, t in enumerate(all_tokens)}

    vectors = [_tf_vector(tl, vocab) for tl in token_lists]

    # Build adjacency via union-find
    parent = list(range(len(findings)))
    rank = [0] * len(findings)

    def _find(x: int) -> int:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def _union(a: int, b: int) -> None:
        ra, rb = _find(a), _find(b)
        if ra == rb:
            return
        if rank[ra] < rank[rb]:
            parent[ra] = rb
        elif rank[ra] > rank[rb]:
            parent[rb] = ra
        else:
            parent[rb] = ra
            rank[ra] += 1

    for i in range(len(findings)):
        for j in range(i + 1, len(findings)):
            sim = cosine_similarity(vectors[i], vectors[j])
            if sim >= threshold:
                _union(i, j)

    # Collapse: keep highest-severity per group
    groups: dict[int, list[int]] = {}
    for i in range(len(findings)):
        root = _find(i)
        groups.setdefault(root, []).append(i)

    kept: list[dict] = []
    for indices in groups.values():
        best = max(indices, key=lambda idx: _SEV_RANK.get(str(findings[idx].get('severity', '')).upper(), 0))
        kept.append(findings[best])

    return kept
