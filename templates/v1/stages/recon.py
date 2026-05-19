from __future__ import annotations


def build_recon_tasks(snippets: list[dict]) -> list[dict]:
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

    tasks = []
    for idx, (domain, files) in enumerate(sorted(domain_to_files.items()), start=1):
        tasks.append(
            {
                'task_id': f't_{domain}_{idx}',
                'domain': domain,
                'attack_class': domain,
                'target_files': sorted(files),
                'rationale': f'{domain} targets derived from tags',
                'priority': 'high' if domain in {'mem-safety', 'data-flow', 'crypto'} else 'medium',
            }
        )
    return tasks
