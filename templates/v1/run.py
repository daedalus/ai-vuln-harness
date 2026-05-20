from __future__ import annotations

import argparse
import json
from pathlib import Path

from stages.diff import get_changed_snippets
from stages.ingestor import filter_snippets, load_repo_snippets, tag_snippet
from stages.recon import build_recon_tasks
from stages.coordinator import build_context_packs
from stages.parser import parse_findings
from stages.report import build_report
from stages.runtime import JsonCache, StateDB, fetch_model_limits, load_auth_config, split_model_pools
from stages.shield import (
    annotate_call_path_verification,
    annotate_hallucination,
    annotate_hallucination_kl,
    build_call_graph,
    deduplicate_semantic,
    filter_unreachable,
)
from stages.voting import merge_hunter_outputs
from stages.suppressions import SuppressionRegistry


def run(mode: str, repo: Path, *,
        auth_path: Path | None = None,
        kl_threshold: float = 5.0,
        cosine_threshold: float = 0.85,
        allow_full_db_fallback: bool = False,
        base_commit: str | None = None,
        head_commit: str = 'HEAD') -> dict:
    cfg = json.loads((Path(__file__).parent / 'config/defaults.json').read_text())
    state = StateDB(Path(__file__).parent / cfg['state_db'])
    cache = JsonCache(Path(__file__).parent / cfg['cache_file'])

    auth = load_auth_config(explicit_path=auth_path, script_dir=Path(__file__).parent)
    state.put_meta('auth_providers', json.dumps(sorted(auth.keys())))

    raw_snippets = load_repo_snippets(repo, is_library_target=cfg['is_library_target'])
    snippets = filter_snippets(raw_snippets, is_library_target=cfg['is_library_target'])
    for s in snippets:
        s['tags'] = sorted(set(s.get('tags') or []) | set(tag_snippet(s, is_library_target=cfg['is_library_target'])))

    # --- Diff-driven incremental scan (mode='diff' or explicit commits) ---
    if mode == 'diff' or base_commit is not None:
        if base_commit is None:
            raise ValueError("--base-commit is required when mode is 'diff'")
        snippets = get_changed_snippets(repo, snippets, base_commit, head_commit)
        state.put_meta('diff_base_commit', base_commit)
        state.put_meta('diff_head_commit', head_commit)
        state.put_meta('diff_snippet_count', str(len(snippets)))

    model_chain = [
        'deepseek/deepseek-v4-flash:free',
        'qwen/qwen-2.5-coder-32b-instruct:free',
        'nvidia/nemotron-3-super-120b-a12b:free',
        'arcee-ai/trinity-large-thinking:free',
    ]

    model_limits = fetch_model_limits(model_chain, Path(__file__).parent)
    min_context = min(model_limits.values())
    budget_tokens = int(min_context * 0.85)

    recon_tasks = build_recon_tasks(snippets, repo_path=str(repo))
    _ = build_context_packs(
        snippets,
        recon_tasks=recon_tasks,
        allow_full_db_fallback=allow_full_db_fallback,
        budget_tokens=budget_tokens,
    )
    hunt_models, validate_models = split_model_pools(model_chain)

    # --- Simulated multi-hunter output (two runs) for voting demonstration ---
    raw_run1, _ = parse_findings('{"done": true}', domain='mem-safety')
    raw_run2: list[dict] = []
    promoted, _suppressed_by_vote = merge_hunter_outputs([raw_run1, raw_run2], min_votes=2)

    # --- Build snippet DB for shield lookups ---
    snippet_db = {s['id']: s for s in snippets}

    # --- Call-graph annotation (improvement ①) ---
    call_graph = build_call_graph(snippets)
    promoted = annotate_call_path_verification(promoted, call_graph)

    # --- Hallucination annotation (improvement ⑧) ---
    promoted = annotate_hallucination(promoted, snippet_db)

    # --- KL-divergence hallucination detection ---
    promoted = annotate_hallucination_kl(promoted, snippet_db, threshold=kl_threshold)

    # --- Cosine-similarity semantic deduplication ---
    promoted = deduplicate_semantic(promoted, threshold=cosine_threshold)

    # --- Static reachability pre-filter (improvement ⑦) ---
    entry_points = cfg.get('entry_points', [])
    promoted, _unreachable = filter_unreachable(promoted, call_graph, entry_points)

    # --- False-positive suppression registry (improvement ④) ---
    registry = SuppressionRegistry(Path(__file__).parent / cfg.get('suppressions_file', 'output/suppressions.json'))
    findings, _registry_suppressed = registry.filter(promoted)

    report = build_report(
        repo=str(repo),
        findings=findings,
        chains=[],
        gaps=[],
        trace_required=cfg['is_library_target'],
    )

    state.put_meta('last_mode', mode)
    state.put_meta('hunt_models', json.dumps(hunt_models))
    state.put_meta('validate_models', json.dumps(validate_models))
    cache.put('last_report', report)

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description='AI vuln harness v1 scaffold')
    parser.add_argument('--mode', choices=['full', 'max-run', 'validate-only', 'resume', 'diff'], default='full')
    parser.add_argument('--repo', required=True)
    parser.add_argument('--allow-full-db-fallback', action='store_true')
    parser.add_argument('--auth-json', type=Path, default=None,
                        help='Path to auth.json. Overrides script-relative and global fallback paths.')
    parser.add_argument('--kl-threshold', type=float, default=5.0,
                        help='KL-divergence threshold for hallucination detection (default: 5.0)')
    parser.add_argument('--cosine-threshold', type=float, default=0.85,
                        help='Cosine similarity threshold for semantic dedup (default: 0.85)')
    parser.add_argument('--base-commit', type=str, default=None,
                        help='Base commit/ref for diff-driven scanning (required with --mode diff)')
    parser.add_argument('--head-commit', type=str, default='HEAD',
                        help='Head commit/ref for diff-driven scanning (default: HEAD)')
    args = parser.parse_args()

    report = run(args.mode, Path(args.repo),
                 auth_path=args.auth_json,
                 kl_threshold=args.kl_threshold,
                 cosine_threshold=args.cosine_threshold,
                 allow_full_db_fallback=args.allow_full_db_fallback,
                 base_commit=args.base_commit,
                 head_commit=args.head_commit)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
