from __future__ import annotations

import argparse
import json
from pathlib import Path

from stages.ingestor import filter_snippets, tag_snippet
from stages.recon import build_recon_tasks
from stages.coordinator import build_context_packs
from stages.parser import parse_findings
from stages.report import build_report
from stages.runtime import JsonCache, StateDB, split_model_pools


def _load_repo_files(repo: Path) -> list[dict]:
    snippets = []
    for path in repo.rglob('*'):
        if path.suffix.lower() not in {'.c', '.cc', '.cpp', '.h', '.go', '.rs', '.py', '.js', '.ts'}:
            continue
        try:
            text = path.read_text(encoding='utf-8', errors='ignore')
        except OSError:
            continue
        snippets.append(
            {
                'id': f'{path}:1',
                'file': str(path.relative_to(repo)),
                'name': path.stem,
                'content': text[:6000],
                'token_count': max(1, len(text) // 4),
            }
        )
    return snippets


def run(mode: str, repo: Path, allow_full_db_fallback: bool = False) -> dict:
    cfg = json.loads((Path(__file__).parent / 'config/defaults.json').read_text())
    state = StateDB(Path(__file__).parent / cfg['state_db'])
    cache = JsonCache(Path(__file__).parent / cfg['cache_file'])

    raw_snippets = _load_repo_files(repo)
    snippets = filter_snippets(raw_snippets, is_library_target=cfg['is_library_target'])
    for s in snippets:
        s['tags'] = tag_snippet(s, is_library_target=cfg['is_library_target'])

    recon_tasks = build_recon_tasks(snippets)
    _ = build_context_packs(
        snippets,
        recon_tasks=recon_tasks,
        allow_full_db_fallback=allow_full_db_fallback,
    )

    model_chain = [
        'deepseek/deepseek-v4-flash:free',
        'qwen/qwen-2.5-coder-32b-instruct:free',
        'nvidia/nemotron-3-super-120b-a12b:free',
        'arcee-ai/trinity-large-thinking:free',
    ]
    hunt_models, validate_models = split_model_pools(model_chain)

    findings, gaps = parse_findings('{"done": true}', domain='mem-safety')

    report = build_report(
        repo=str(repo),
        findings=findings,
        chains=[],
        gaps=gaps,
        trace_required=cfg['is_library_target'],
    )

    state.put_meta('last_mode', mode)
    state.put_meta('hunt_models', json.dumps(hunt_models))
    state.put_meta('validate_models', json.dumps(validate_models))
    cache.put('last_report', report)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description='AI vuln harness v1 scaffold')
    parser.add_argument('--mode', choices=['full', 'max-run', 'validate-only', 'resume'], default='full')
    parser.add_argument('--repo', required=True)
    parser.add_argument('--allow-full-db-fallback', action='store_true')
    args = parser.parse_args()

    report = run(args.mode, Path(args.repo), allow_full_db_fallback=args.allow_full_db_fallback)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
