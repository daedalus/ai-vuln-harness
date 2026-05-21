from __future__ import annotations

import argparse
import json
from pathlib import Path

from stages.diff import get_changed_snippets
from stages.feedback import build_feedback_tasks
from stages.gapfill import build_gapfill_tasks
from stages.ingestor import filter_snippets, load_repo_snippets, tag_snippet
from stages.recon import build_recon_tasks
from stages.coordinator import build_context_packs
from stages.parser import parse_findings
from stages.report import build_report, deduplicate
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


def _load_stages_config(script_dir: Path) -> dict:
    """Load per-stage model-pool and concurrency config from config/stages.json.

    Returns an empty dict if the file is absent or malformed so callers can
    safely fall back to defaults.
    """
    path = script_dir / 'config' / 'stages.json'
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _stage_workers(stages_cfg: dict, stage: str, global_max: int) -> int:
    """Resolve the effective max_workers for *stage* honouring global cap."""
    stage_cfg = stages_cfg.get('stages', {}).get(stage, {})
    per_stage = stage_cfg.get('max_workers', global_max)
    return min(per_stage, global_max)


def run(mode: str, repo: Path, *,
        auth_path: Path | None = None,
        kl_threshold: float = 5.0,
        cosine_threshold: float = 0.85,
        allow_full_db_fallback: bool = False,
        base_commit: str | None = None,
        head_commit: str = 'HEAD',
        max_cost_usd: float | None = None,
        max_concurrency: int | None = None,
        scope_notes: str | None = None) -> dict:
    cfg = json.loads((Path(__file__).parent / 'config/defaults.json').read_text())
    stages_cfg = _load_stages_config(Path(__file__).parent)
    state = StateDB(Path(__file__).parent / cfg['state_db'])
    cache = JsonCache(Path(__file__).parent / cfg['cache_file'])

    # --- Cost guardrail: abort early if budget already exceeded ---
    run_id = f'{mode}:{str(repo)}'
    if max_cost_usd is not None:
        spent = state.total_cost(run_id)
        if spent >= max_cost_usd:
            raise RuntimeError(
                f'Cost limit ${max_cost_usd:.2f} reached '
                f'(${spent:.2f} already spent on run {run_id!r})'
            )

    auth = load_auth_config(explicit_path=auth_path, script_dir=Path(__file__).parent)
    state.put_meta('auth_providers', json.dumps(sorted(auth.keys())))

    # --- Effective concurrency cap ---
    global_max = max_concurrency or cfg.get('max_workers', 3)
    hunt_workers = _stage_workers(stages_cfg, 'hunt', global_max)
    validate_workers = _stage_workers(stages_cfg, 'validate', global_max)
    state.put_meta('hunt_workers', str(hunt_workers))
    state.put_meta('validate_workers', str(validate_workers))

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

    recon_tasks = build_recon_tasks(snippets, repo_path=str(repo), scope_notes=scope_notes)
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

    # --- Gapfill: identify domains with zero confirmed findings and re-queue ---
    gapfill_tasks = build_gapfill_tasks(
        recon_tasks, promoted, max_tasks=5, scope_notes=scope_notes,
    )
    state.put_meta('gapfill_task_count', str(len(gapfill_tasks)))
    all_tasks = recon_tasks + gapfill_tasks

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

    # --- Feedback: seed new Hunt tasks from confirmed/traced findings ---
    traced = [f for f in findings if f.get('trace_status') == 'confirmed']
    already_covered = {f for t in all_tasks for f in t.get('target_files', [])}
    feedback_tasks = build_feedback_tasks(
        traced, snippets,
        already_covered=already_covered,
        max_tasks=10,
        scope_notes=scope_notes,
    )
    state.put_meta('feedback_task_count', str(len(feedback_tasks)))

    report = build_report(
        repo=str(repo),
        findings=findings,
        chains=[],
        gaps=[{'domain': t['domain'], 'files': t['target_files']} for t in gapfill_tasks],
        trace_required=cfg['is_library_target'],
    )

    state.put_meta('last_mode', mode)
    state.put_meta('hunt_models', json.dumps(hunt_models))
    state.put_meta('validate_models', json.dumps(validate_models))
    if scope_notes:
        state.put_meta('scope_notes_hash', str(hash(scope_notes)))
    cache.put('last_report', report)

    return report


# Ordered list of every mode that performs an actual scan (excludes 'all').
_SINGLE_MODES: list[str] = ['full', 'max-run', 'validate-only', 'resume', 'diff']


def _merge_reports(reports: list[dict]) -> dict:
    """Merge multiple per-mode reports into a single combined report.

    Findings are deduplicated across reports using the same composite key
    used inside ``build_report`` (file × class × start-line).  The
    highest-severity variant is kept.  Summary counters, chains, and gaps
    are aggregated across all reports.
    """
    if not reports:
        return build_report(repo='', findings=[], chains=[], gaps=[])

    repo = reports[0].get('repo', '')
    all_findings: list[dict] = []
    all_chains: list[dict] = []
    all_gaps: list[dict] = []
    combined_summary: dict[str, int] = {}

    for report in reports:
        all_findings.extend(report.get('findings') or [])
        all_chains.extend(report.get('chains') or [])
        all_gaps.extend(report.get('gaps') or [])
        for key, val in (report.get('summary') or {}).items():
            if isinstance(val, int):
                combined_summary[key] = combined_summary.get(key, 0) + val

    deduped = deduplicate(all_findings)

    merged = build_report(
        repo=repo,
        findings=deduped,
        chains=all_chains,
        gaps=all_gaps,
        trace_required=True,
    )
    # Replace the freshly-computed summary with the aggregated one so per-mode
    # counts are preserved and not recomputed from the merged finding set alone.
    merged['summary'] = combined_summary
    merged['modes_run'] = [r.get('mode_run', 'unknown') for r in reports]
    return merged


def run_all(repo: Path, *,
            auth_path: Path | None = None,
            kl_threshold: float = 5.0,
            cosine_threshold: float = 0.85,
            allow_full_db_fallback: bool = False,
            base_commit: str | None = None,
            head_commit: str = 'HEAD',
            max_cost_usd: float | None = None,
            max_concurrency: int | None = None,
            scope_notes: str | None = None) -> dict:
    """Run every single scanning mode in sequence and return a merged report.

    The ``diff`` mode is included only when *base_commit* is provided; it is
    silently skipped otherwise so that ``--mode all`` never fails due to a
    missing ``--base-commit``.
    """
    reports: list[dict] = []
    for mode in _SINGLE_MODES:
        if mode == 'diff' and base_commit is None:
            continue
        report = run(
            mode, repo,
            auth_path=auth_path,
            kl_threshold=kl_threshold,
            cosine_threshold=cosine_threshold,
            allow_full_db_fallback=allow_full_db_fallback,
            base_commit=base_commit,
            head_commit=head_commit,
            max_cost_usd=max_cost_usd,
            max_concurrency=max_concurrency,
            scope_notes=scope_notes,
        )
        report['mode_run'] = mode
        reports.append(report)

    merged = _merge_reports(reports)
    merged['mode_run'] = 'all'
    return merged


def main() -> None:
    parser = argparse.ArgumentParser(description='AI vuln harness v1 scaffold')
    parser.add_argument('--mode', choices=['full', 'max-run', 'validate-only', 'resume', 'diff', 'all'], default='full')
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
    parser.add_argument('--max-cost-usd', type=float, default=None,
                        help='Abort the run if cumulative cost exceeds this amount in USD')
    parser.add_argument('--max-concurrency', type=int, default=None,
                        help='Global cap on concurrent model workers across all stages')
    parser.add_argument('--scope-notes', type=Path, default=None,
                        help='Path to a text file whose contents are appended to every '
                             "stage's user_input to scope or exclude surfaces")
    args = parser.parse_args()

    scope_notes_text: str | None = None
    if args.scope_notes is not None:
        scope_notes_text = Path(args.scope_notes).read_text()

    kwargs = dict(
        auth_path=args.auth_json,
        kl_threshold=args.kl_threshold,
        cosine_threshold=args.cosine_threshold,
        allow_full_db_fallback=args.allow_full_db_fallback,
        base_commit=args.base_commit,
        head_commit=args.head_commit,
        max_cost_usd=args.max_cost_usd,
        max_concurrency=args.max_concurrency,
        scope_notes=scope_notes_text,
    )
    if args.mode == 'all':
        report = run_all(Path(args.repo), **kwargs)
    else:
        report = run(args.mode, Path(args.repo), **kwargs)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
