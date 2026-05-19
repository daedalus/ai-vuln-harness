from __future__ import annotations

from collections import defaultdict


def build_context_packs(
    snippets: list[dict],
    recon_tasks: list[dict] | None,
    allow_full_db_fallback: bool = False,
    budget_tokens: int = 180_000,
) -> list[dict]:
    if (not recon_tasks) and (not allow_full_db_fallback):
        raise ValueError('Recon output is required. Set allow_full_db_fallback=True to bypass explicitly.')

    by_file = {s.get('file'): s for s in snippets}

    if not recon_tasks and allow_full_db_fallback:
        recon_tasks = [
            {
                'task_id': 'fallback-all',
                'domain': 'all',
                'attack_class': 'all',
                'target_files': list(by_file.keys()),
                'rationale': 'explicit full-db fallback',
                'priority': 'low',
            }
        ]

    domain_snippets: dict[str, list[dict]] = defaultdict(list)
    for task in recon_tasks or []:
        for f in task.get('target_files', []):
            if f in by_file:
                domain_snippets[task['domain']].append(by_file[f])

    packs = []
    for domain, items in domain_snippets.items():
        token_sum = 0
        pack_snips = []
        for s in items:
            tc = int(s.get('token_count') or 0)
            if token_sum + tc > budget_tokens and pack_snips:
                packs.append(_make_pack(domain, pack_snips))
                token_sum = 0
                pack_snips = []
            pack_snips.append(s)
            token_sum += tc
        if pack_snips:
            packs.append(_make_pack(domain, pack_snips))

    return packs


def _make_pack(domain: str, snippets: list[dict]) -> dict:
    return {
        'agent': domain,
        'guidance': f'Focus only on {domain}.',
        'snippets': snippets,
        'cross_refs': {},
        'security_context': {},
        'known_entries': [],
    }
