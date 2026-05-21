"""AI Vulnerability Research Harness — multi-agent pipeline runner.

Canonical pipeline (15 stages):
  INGESTOR → RECON → COORDINATOR → HUNT → VALIDATE → GAPFILL → VOTING →
  SHIELD → SUPPRESSIONS → CHAINS → POC → TRACE → EXPOSURE → FEEDBACK → REPORT

Never edit the template in place. Copy it first:
  cp -a /home/dclavijo/.opencode/skills/ai-vuln-harness/templates/v1/ ./my-harness/

Never survey the target yourself. The harness pipeline's INGESTOR and RECON
stages are the ONLY authorized surveyors — they parse the repo through
tree-sitter, build snippet databases, and construct context packs. Do not
read, explore, grep, or analyze the target repository directly. Pre-reading
the target contaminates the eval by leaking context that should only flow
through the pipeline.

Run modes: full | max-run | validate-only | resume | diff | all | poc-only

Track KPIs: precision@top-N, reject rate, duplicate rate, gap-closure rate,
time/cost per stage. Maintain a benchmark corpus + regression gate for
prompt/model updates.
"""

from __future__ import annotations

import argparse
import json
import os
import logging
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from pathlib import Path

from stages.diff import get_changed_snippets
from stages.chains import synthesize_exploit_chains
from stages.contracts import PIPELINE_STAGES, standardize_finding
from stages.coordinator import build_context_packs
from stages.exposure import annotate_exposure_windows
from stages.feedback import build_feedback_tasks
from stages.gapfill import build_gapfill_tasks
from stages.ingestor import filter_snippets, load_repo_snippets, tag_snippet
from stages.parser import parse_findings
from stages.poc import process_findings as run_poc
from stages.recon import build_recon_tasks
from stages.report import build_report, deduplicate
from stages.validate import build_validate_prompt, is_api_by_design
from stages.runtime import (
    HUNT_SYSTEM_PROMPT,
    TRACE_SYSTEM_PROMPT,
    VALIDATE_SYSTEM_PROMPT,
    ModelPool,
    _rephrase_gap_prompt,
    call_llm,
    call_llm_from_pool,
    health_check_models,
    JsonCache,
    StateDB,
    fetch_model_limits,
    load_auth_config,
    repair_json_output,
    split_model_pools,
)
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

logger = logging.getLogger('vuln-harness')


def _setup_logging(log_dir: Path | None = None, log_file: Path | None = None) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')

    stderr = logging.StreamHandler(sys.stderr)
    stderr.setLevel(logging.INFO)
    stderr.setFormatter(fmt)
    root.addHandler(stderr)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    elif log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_dir / 'run.log', encoding='utf-8')
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        root.addHandler(fh)


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


def _run_one_hunt_pack(
    pack: dict,
    model: str,
    *,
    auth: dict[str, str],
    cache: JsonCache,
) -> tuple[list[dict], list[dict]]:
    prompt = pack.get('prompt') or json.dumps(pack, indent=2)
    tc_sum = sum(s.get('token_count', 0) for s in pack.get('snippets', []))
    logger.info('hunt pack %s model=%s token_count_sum=%d prompt_chars=%d', pack.get('agent', '?'), model, tc_sum, len(prompt))
    try:
        raw = call_llm(
            model, prompt,
            system=HUNT_SYSTEM_PROMPT,
            auth=auth,
            cache=cache,
        )
        logger.debug('hunt pack %s raw=%d chars', pack.get('agent', '?'), len(raw))
        domain = pack.get('agent', 'unknown')
        findings, gaps = parse_findings(raw, domain=domain)
        logger.debug('hunt pack %s parsed: %d findings, %d gaps', pack.get('agent', '?'), len(findings), len(gaps))
        for f in findings:
            f.setdefault('hunt_model', model)
        return findings, gaps
    except Exception as e:
        logger.warning('hunt model %s pack %s failed: %s', model, pack.get('agent', '?'), e)
        gap_domain = pack.get('agent', 'unknown')
        return [], [{'coverage_gap': gap_domain, 'reason': f'hunt exception: {e}', 'domain': gap_domain}]


def _run_one_hunt_pack_from_pool(
    pack: dict,
    pool: ModelPool,
    *,
    auth: dict[str, str],
    cache: JsonCache,
) -> tuple[list[dict], list[dict]]:
    prompt = pack.get('prompt') or json.dumps(pack, indent=2)
    tc_sum = sum(s.get('token_count', 0) for s in pack.get('snippets', []))
    logger.info('hunt pack %s pooled prompt_chars=%d', pack.get('agent', '?'), len(prompt))
    try:
        raw = call_llm_from_pool(
            pool, prompt,
            system=HUNT_SYSTEM_PROMPT,
            auth=auth,
            cache=cache,
        )
        logger.debug('hunt pack %s pooled raw=%d chars', pack.get('agent', '?'), len(raw))
        domain = pack.get('agent', 'unknown')
        findings, gaps = parse_findings(raw, domain=domain)
        logger.debug('hunt pack %s pooled parsed: %d findings, %d gaps', pack.get('agent', '?'), len(findings), len(gaps))
        return findings, gaps
    except Exception as e:
        logger.warning('hunt pack %s pooled failed: %s', pack.get('agent', '?'), e)
        gap_domain = pack.get('agent', 'unknown')
        return [], [{'coverage_gap': gap_domain, 'reason': f'hunt exception: {e}', 'domain': gap_domain}]


def _run_hunt_packs(
    packs: list[dict],
    models: list[str],
    *,
    auth: dict[str, str],
    cache: JsonCache,
    parallel: int = 3,
    max_run: int | None = None,
    domain_map: dict[str, list[dict]] | None = None,
    model_pool: ModelPool | None = None,
) -> tuple[list[dict], list[dict]]:
    from stages.runtime import _MODEL_BY_DOMAIN

    if max_run is not None:
        packs = packs[:max_run]

    all_findings: list[dict] = []
    all_gaps: list[dict] = []

    if model_pool is not None:
        tasks = [{'pack': p} for p in packs]
    else:
        tasks: list[dict] = []
        for pack in packs:
            domain = pack.get('agent', 'mem-safety')
            preferred = _MODEL_BY_DOMAIN.get(domain)
            ordered = []
            if preferred and preferred in models:
                ordered.append(preferred)
            ordered.extend(m for m in models if m not in ordered)
            tasks.append({'pack': pack, 'models': ordered})

    completed = 0
    total = len(tasks)
    logger.info('hunt starting %d pack(s) with %d worker(s)%s',
                total, parallel,
                ' (pooled)' if model_pool else '')

    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = {}
        for t in tasks:
            if model_pool is not None:
                futures[pool.submit(_run_one_hunt_pack_from_pool, t['pack'], model_pool, auth=auth, cache=cache)] = t
            else:
                model = t['models'][0] if t['models'] else ''
                futures[pool.submit(_run_one_hunt_pack, t['pack'], model, auth=auth, cache=cache)] = t

        for f in as_completed(futures):
            t = futures[f]
            domain = t['pack'].get('agent', '?')
            try:
                findings, gaps = f.result()
                all_findings.extend(findings)
                all_gaps.extend(gaps)
            except Exception as e:
                all_gaps.append({'coverage_gap': domain, 'reason': f'hunt worker exception: {e}'})
            completed += 1
            logger.info('hunt %d/%d packs done', completed, total)

    return all_findings, all_gaps


def _run_validate_finding(
    finding: dict,
    snippet: dict,
    model: str,
    *,
    auth: dict[str, str],
    cache: JsonCache,
) -> dict:
    if is_api_by_design(finding, snippet):
        logger.debug('validate skip %s: api_by_design', finding.get('title', finding.get('name', '?')))
        return {**finding, 'validate_status': 'rejected', 'validate_reason': 'api_by_design'}
    finding = standardize_finding(finding)
    snippet_code = snippet.get('content', '')
    prompt = build_validate_prompt(finding, snippet)
    logger.debug('validate finding=%s model=%s prompt_chars=%d', finding.get('title', '?'), model, len(prompt))
    try:
        raw = call_llm(
            model, prompt,
            system=VALIDATE_SYSTEM_PROMPT,
            auth=auth,
            cache=cache,
        )
        parsed, _repaired = repair_json_output(raw)
        if not parsed:
            parsed = {}
        status = parsed.get('status', 'needs-more-info')
        reason = parsed.get('reason', '') or ''
        if not parsed:
            reason = f'unparseable LLM response: {raw[:200]}'
        logger.debug('validate result: status=%s reason=%s', status, reason[:80])
        return {**finding, 'validate_status': status, 'validate_reason': reason}
    except Exception as e:
        logger.warning('validate exception for %s: %s', finding.get('title', '?'), e)
        return {**finding, 'validate_status': 'needs-more-info', 'validate_reason': f'validate exception: {e}'}


def _run_validate_finding_from_pool(
    finding: dict,
    snippet: dict,
    pool: ModelPool,
    *,
    auth: dict[str, str],
    cache: JsonCache,
) -> dict:
    if is_api_by_design(finding, snippet):
        return {**finding, 'validate_status': 'rejected', 'validate_reason': 'api_by_design'}
    finding = standardize_finding(finding)
    snippet_code = snippet.get('content', '')
    prompt = build_validate_prompt(finding, snippet)
    try:
        raw = call_llm_from_pool(
            pool, prompt,
            system=VALIDATE_SYSTEM_PROMPT,
            auth=auth,
            cache=cache,
        )
        parsed, _repaired = repair_json_output(raw)
        if not parsed:
            parsed = {}
        status = parsed.get('status', 'needs-more-info')
        reason = parsed.get('reason', '') or ''
        if not parsed:
            reason = f'unparseable LLM response: {raw[:200]}'
        return {**finding, 'validate_status': status, 'validate_reason': reason}
    except Exception as e:
        return {**finding, 'validate_status': 'needs-more-info', 'validate_reason': f'validate exception: {e}'}


def _run_validate_findings(
    findings: list[dict],
    snippet_db: dict[str, dict],
    models: list[str],
    *,
    auth: dict[str, str],
    cache: JsonCache,
    parallel: int = 3,
    model_pool: ModelPool | None = None,
) -> list[dict]:
    if not findings:
        return []

    validated: list[dict] = []
    total = len(findings)
    logger.info('validate validating %d finding(s) with %d worker(s)%s',
                total, parallel,
                ' (pooled)' if model_pool else '')

    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = {}
        for finding in findings:
            sid = finding.get('snippet_id', '')
            snippet = snippet_db.get(sid, {})
            if model_pool is not None:
                futures[pool.submit(
                    _run_validate_finding_from_pool, finding, snippet, model_pool,
                    auth=auth, cache=cache,
                )] = finding
            else:
                model = models[0] if models else 'deepseek/deepseek-v4-flash:free'
                futures[pool.submit(
                    _run_validate_finding, finding, snippet, model,
                    auth=auth, cache=cache,
                )] = finding

        completed = 0
        for f in as_completed(futures):
            try:
                validated.append(f.result())
            except Exception as e:
                orig = futures[f]
                validated.append({**orig, 'validate_status': 'needs-more-info', 'validate_reason': str(e)})
            completed += 1
            logger.info('validate %d/%d findings done', completed, total)

    return validated


def _gapfill_rerun(
    gaps: list[dict],
    original_packs: list[dict],
    hunt_models: list[str],
    domain_map: dict[str, list[dict]],
    *,
    auth: dict[str, str],
    cache: JsonCache,
    parallel: int = 3,
    gapfill_iter: int = 0,
    model_pool: ModelPool | None = None,
) -> tuple[list[dict], list[dict]]:
    if not hunt_models:
        return [], []

    model_idx = gapfill_iter % len(hunt_models)
    fallback_model = hunt_models[model_idx]

    rerun_packs: list[dict] = []
    for g in gaps:
        domain = g.get('coverage_gap', g.get('domain', 'mem-safety'))
        candidates = domain_map.get(domain, original_packs[:1])
        if not candidates:
            continue
        pack = deepcopy(candidates[0])
        prompt_text = json.dumps(pack, indent=2)
        pack['prompt'] = _rephrase_gap_prompt(prompt_text, fallback_model)
        pack['gapfill_model'] = fallback_model
        pack['agent'] = domain
        rerun_packs.append(pack)

    logger.info('gapfill iteration %d/2: retrying %d gap(s) with model %s%s',
                gapfill_iter + 1, len(rerun_packs), fallback_model,
                ' (pooled)' if model_pool else '')
    for g in rerun_packs:
        logger.debug('gapfill pack domain=%s prompt_chars=%d', g.get('agent', '?'), len(g.get('prompt', '')))

    fresh_findings, fresh_gaps = _run_hunt_packs(
        rerun_packs, [fallback_model],
        auth=auth, cache=cache, parallel=parallel,
        model_pool=model_pool,
    )

    logger.debug('gapfill iteration %d: %d fresh findings, %d remaining gaps',
                 gapfill_iter + 1, len(fresh_findings), len(fresh_gaps))

    for g in gaps:
        g['gapfill_retried'] = True

    return fresh_findings, fresh_gaps


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    items: list[dict] = []
    for line in path.read_text().strip().splitlines():
        line = line.strip()
        if line:
            try:
                items.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return items


def _persist_jsonl(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w') as f:
        for item in items:
            f.write(json.dumps(item) + '\n')


def run(mode: str, repo: Path, *,
        auth_path: Path | None = None,
        kl_threshold: float = 5.0,
        cosine_threshold: float = 0.85,
        allow_full_db_fallback: bool = False,
        base_commit: str | None = None,
        head_commit: str = 'HEAD',
        max_cost_usd: float | None = None,
        max_concurrency: int | None = None,
        skip_health: bool = False,
        max_run: int | None = None,
        scope_notes: str | None = None,
        reingest: bool = False,
        model_chain_override: list[str] | None = None,
        validate_model_chain_override: list[str] | None = None,
        run_poc_enabled: bool = False,
        poc_finding_id: str | None = None,
        refresh_models: bool = False,
        budget_ratio: float = 0.85,
        pooled: bool = False) -> dict:
    script_dir = Path(__file__).parent
    cfg = json.loads((script_dir / 'config/defaults.json').read_text())
    stages_cfg = _load_stages_config(script_dir)
    state = StateDB(script_dir / cfg['state_db'])
    cache = JsonCache(script_dir / cfg['cache_file'])

    run_id = f'{mode}:{str(repo)}'
    state.create_run(repo_path=str(repo), run_id=run_id)
    if max_cost_usd is not None:
        spent = state.total_cost(run_id)
        if spent >= max_cost_usd:
            state.finish_run(run_id, 'cost_limit')
            raise RuntimeError(
                f'Cost limit ${max_cost_usd:.2f} reached '
                f'(${spent:.2f} already spent on run {run_id!r})'
            )

    auth = load_auth_config(explicit_path=auth_path, script_dir=script_dir)
    state.put_meta('auth_providers', json.dumps(sorted(auth.keys())))

    global_max = max_concurrency or cfg.get('max_workers', 3)
    hunt_workers = _stage_workers(stages_cfg, 'hunt', global_max)
    validate_workers = _stage_workers(stages_cfg, 'validate', global_max)
    state.put_meta('hunt_workers', str(hunt_workers))
    state.put_meta('validate_workers', str(validate_workers))

    output_dir = script_dir / 'output'
    output_dir.mkdir(parents=True, exist_ok=True)

    # --- INGESTOR ---
    snippet_db_path = output_dir / 'snippet_db.json'
    if reingest and snippet_db_path.exists():
        logger.info('reingest enabled: loading snippet_db from %s', snippet_db_path)
        snippet_db = json.loads(snippet_db_path.read_text())
        if isinstance(snippet_db, list):
            snippet_db = {s['id']: s for s in snippet_db}
        snippets = list(snippet_db.values())
    else:
        raw_snippets = load_repo_snippets(repo, is_library_target=cfg['is_library_target'])
        snippets = filter_snippets(raw_snippets, is_library_target=cfg['is_library_target'])
        for s in snippets:
            s['tags'] = sorted(set(s.get('tags') or []) | set(tag_snippet(s, is_library_target=cfg['is_library_target'])))
        snippet_db = {s['id']: s for s in snippets}
        snippet_db_path.write_text(json.dumps(snippet_db, indent=2))

    if mode == 'diff' or base_commit is not None:
        if base_commit is None:
            raise ValueError("--base-commit is required when mode is 'diff'")
        snippets = get_changed_snippets(repo, snippets, base_commit, head_commit)
        state.put_meta('diff_base_commit', base_commit)
        state.put_meta('diff_head_commit', head_commit)
        state.put_meta('diff_snippet_count', str(len(snippets)))

    model_chain = model_chain_override or [
        'deepseek/deepseek-v4-flash:free',
        'qwen/qwen-2.5-coder-32b-instruct:free',
        'nvidia/nemotron-3-super-120b-a12b:free',
        'arcee-ai/trinity-large-thinking:free',
    ]

    if not skip_health and auth and mode not in ('validate-only', 'resume', 'poc-only'):
        logger.info('probing model chain (%d models)...', len(model_chain))
        logger.debug('health check models: %s', model_chain)
        alive, dead = health_check_models(model_chain, auth=auth, cache=cache)
        cache.put('model_health_alive', alive)
        cache.put('model_health_dead', dead)
        cache.put('model_health_timestamp', time.time())
        if dead:
            logger.warning('dead models: %s', dead)
        if alive:
            model_chain = alive
        else:
            logger.warning('all models dead; continuing with original chain')
    elif skip_health:
        cached_alive = cache.get('model_health_alive')
        if cached_alive:
            logger.info('using cached health results: %d alive model(s)', len(cached_alive))
            model_chain = cached_alive

    if refresh_models:
        limits_path = script_dir / 'config' / 'model_limits.json'
        if limits_path.exists():
            limits_path.unlink()
            logger.info('refreshed model limits cache')

    model_limits = fetch_model_limits(model_chain, script_dir)
    min_context = min(model_limits.values())
    budget_tokens = int(min_context * budget_ratio)
    logger.info('budget model_limits=%s min_context=%d budget_ratio=%.2f budget_tokens=%d', model_limits, min_context, budget_ratio, budget_tokens)

    # --- RECON ---
    recon_tasks = build_recon_tasks(snippets, repo_path=str(repo), scope_notes=scope_notes)
    state.put_meta('recon_task_count', str(len(recon_tasks)))
    _persist_jsonl(output_dir / 'recon_tasks.json', recon_tasks)

    # --- COORDINATOR ---
    packs = build_context_packs(
        snippets,
        recon_tasks=recon_tasks,
        allow_full_db_fallback=allow_full_db_fallback,
        budget_tokens=budget_tokens,
    )
    state.put_meta('pack_count', str(len(packs)))
    domain_map: dict[str, list[dict]] = {}
    for p in packs:
        domain_map.setdefault(p.get('agent', ''), []).append(p)
    from collections import Counter
    pack_domain_counts: Counter = Counter()
    for p in packs:
        pack_domain_counts[p.get('agent', '?')] += 1
    logger.info('pack total=%d per_domain=%s', len(packs), dict(pack_domain_counts))
    for i, p in enumerate(packs):
        prompt = json.dumps(p, indent=2)
        tc_sum = sum(s.get('token_count', 0) for s in p.get('snippets', []))
        logger.info('pack #%d agent=%s snippets=%d token_count_sum=%d budget=%d prompt_chars=%d',
                    i + 1, p.get('agent', '?'), len(p.get('snippets', [])), tc_sum, budget_tokens, len(prompt))
    _persist_jsonl(output_dir / 'context_packs.json', packs)

    if pooled:
        from stages.runtime import _resolve_provider, _strip_provider
        logger.debug('building ModelPool from %d models: %s', len(model_chain), model_chain)
        model_pool = ModelPool(model_chain, model_limits)
        for m in model_chain:
            logger.info('[health] %s %s alive', _resolve_provider(m), _strip_provider(m))
        hunt_models = model_pool.alive
        validate_models = model_pool.alive
        logger.debug('pooled mode: %d alive models (hunt=%d, validate=%d)',
                     len(model_chain), len(hunt_models), len(validate_models))
        state.put_meta('pooled', 'true')
    else:
        model_pool = None
        hunt_models, validate_models = split_model_pools(model_chain)
    if validate_model_chain_override and not pooled:
        validate_models = validate_model_chain_override
    state.put_meta('hunt_models', json.dumps(hunt_models))
    state.put_meta('validate_models', json.dumps(validate_models))

    # --- HUNT ---
    all_findings: list[dict] = []
    all_gaps: list[dict] = []

    if mode in ('validate-only', 'resume', 'poc-only'):
        all_findings = _load_jsonl(output_dir / 'findings.jsonl')
        all_gaps = _load_jsonl(output_dir / 'gaps.jsonl')
        logger.info('loaded %d finding(s) and %d gap(s) from cache', len(all_findings), len(all_gaps))
    else:
        if auth:
            all_findings, all_gaps = _run_hunt_packs(
                packs, hunt_models,
                auth=auth, cache=cache,
                parallel=hunt_workers,
                max_run=max_run,
                domain_map=domain_map,
                model_pool=model_pool if pooled else None,
            )
        else:
            logger.warning('no auth configured; using empty findings')

        _persist_jsonl(output_dir / 'findings.jsonl', all_findings)
        _persist_jsonl(output_dir / 'gaps.jsonl', all_gaps)

    # --- VALIDATE (on raw findings, before dedup) ---
    if mode not in ('validate-only', 'poc-only') and all_findings and auth:
        validated = _run_validate_findings(
            all_findings, snippet_db, validate_models,
            auth=auth, cache=cache, parallel=validate_workers,
            model_pool=model_pool if pooled else None,
        )
        _persist_jsonl(output_dir / 'validated.jsonl', validated)
    else:
        validated = all_findings[:]
        for f in validated:
            f.setdefault('validate_status', 'needs-more-info')
            f.setdefault('validate_reason', 'skipped')

    # --- GAPFILL (2 iterations, model rotation + prompt rephrase) ---
    gapfill_tasks = build_gapfill_tasks(
        recon_tasks, validated, max_tasks=5, scope_notes=scope_notes,
    )
    for gapfill_iter in range(2):
        current = [g for g in all_gaps if not g.get('gapfill_retried')]
        if not current:
            break
        fresh_f, fresh_g = _gapfill_rerun(
            current, packs, hunt_models, domain_map,
            auth=auth, cache=cache, parallel=hunt_workers,
            gapfill_iter=gapfill_iter,
            model_pool=model_pool if pooled else None,
        )
        validated.extend(fresh_f)
        all_gaps = [g for g in all_gaps if g.get('gapfill_retried')] + fresh_g

    state.put_meta('gapfill_task_count', str(len(gapfill_tasks)))
    all_tasks = recon_tasks + gapfill_tasks

    # --- VOTING ---
    promoted, suppressed_by_vote = merge_hunter_outputs(
        [validated], min_votes=cfg.get('shield', {}).get('min_votes', 2),
    )
    state.put_meta('suppressed_by_vote', str(len(suppressed_by_vote)))

    # --- SHIELD ---
    call_graph = build_call_graph(snippets)
    promoted = annotate_call_path_verification(promoted, call_graph)
    promoted = annotate_hallucination(promoted, snippet_db)
    promoted = annotate_hallucination_kl(promoted, snippet_db, threshold=kl_threshold)
    promoted = deduplicate_semantic(promoted, threshold=cosine_threshold)

    entry_points = cfg.get('entry_points', [])
    promoted, unreachable = filter_unreachable(promoted, call_graph, entry_points)
    state.put_meta('unreachable_count', str(len(unreachable)))

    # --- SUPPRESSIONS ---
    registry = SuppressionRegistry(script_dir / cfg.get('suppressions_file', 'output/suppressions.json'))
    findings, registry_suppressed = registry.filter(promoted)
    state.put_meta('registry_suppressed', str(len(registry_suppressed)))

    # --- CHAINS ---
    chains = synthesize_exploit_chains(findings, snippets)

    # --- POC (auto-generate & optionally compile/run) ---
    pocs: list[dict] = []
    if run_poc_enabled:
        target_findings = findings
        if poc_finding_id and poc_finding_id != 'all':
            target_findings = [f for f in findings if f.get('id') == poc_finding_id or f.get('finding_id') == poc_finding_id]
        if target_findings:
            logger.info('running PoC on %d finding(s)', len(target_findings))
            pocs = run_poc(target_findings, snippet_db)
            logger.info('poc completed: %d result(s)', len(pocs))
        _persist_jsonl(output_dir / 'pocs.jsonl', pocs)

    # --- TRACE (determine input reachability from consumer entry points) ---
    for f in findings:
        f.setdefault('trace_status', 'not_required')
    state.put_meta('trace_results', json.dumps(
        {'not_required': len([f for f in findings if f.get('trace_status') == 'not_required'])}
    ))

    # --- EXPOSURE ---
    findings, exposure_metrics = annotate_exposure_windows(findings, repo)

    # --- FEEDBACK ---
    traced = [f for f in findings if f.get('trace_status') == 'confirmed']
    already_covered = {f for t in all_tasks for f in t.get('target_files', [])}
    feedback_tasks = build_feedback_tasks(
        traced, snippets,
        already_covered=already_covered,
        max_tasks=10,
        scope_notes=scope_notes,
    )
    state.put_meta('feedback_task_count', str(len(feedback_tasks)))

    # --- REPORT ---
    report = build_report(
        repo=str(repo),
        findings=findings,
        chains=chains,
        gaps=[{'domain': t['domain'], 'files': t['target_files']} for t in gapfill_tasks],
        trace_required=cfg['is_library_target'],
        exposure_metrics=exposure_metrics,
    )
    if pocs:
        report['pocs'] = pocs

    state.put_meta('last_mode', mode)
    state.finish_run(run_id)
    cache.put('last_report', report)

    return report


_SINGLE_MODES: list[str] = ['full', 'max-run', 'validate-only', 'resume', 'diff', 'poc-only']


def _merge_reports(reports: list[dict]) -> dict:
    """Merge multiple per-mode reports into a single combined report.

    Findings are deduplicated across reports using the same composite key
    used inside ``build_report`` (file x class x start-line).  The
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
            skip_health: bool = False,
            max_run: int | None = None,
            scope_notes: str | None = None,
            reingest: bool = False,
            model_chain_override: list[str] | None = None,
            validate_model_chain_override: list[str] | None = None,
            run_poc_enabled: bool = False,
            poc_finding_id: str | None = None,
        refresh_models: bool = False,
        budget_ratio: float = 0.85,
        pooled: bool = False) -> dict:
    reports: list[dict] = []
    for mode in _SINGLE_MODES:
        if mode == 'diff' and base_commit is None:
            continue
        if mode == 'poc-only' and not run_poc_enabled:
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
            skip_health=skip_health,
            max_run=max_run,
            scope_notes=scope_notes,
            reingest=reingest,
            model_chain_override=model_chain_override,
            validate_model_chain_override=validate_model_chain_override,
            run_poc_enabled=run_poc_enabled,
            poc_finding_id=poc_finding_id,
            refresh_models=refresh_models,
            budget_ratio=budget_ratio,
            pooled=pooled,
        )
        report['mode_run'] = mode
        reports.append(report)

    merged = _merge_reports(reports)
    merged['mode_run'] = 'all'
    return merged


def _check_deps():
    import importlib
    import shutil
    import sys

    if sys.version_info < (3, 9):
        sys.exit('fatal: Python >= 3.9 required')

    missing = []
    for pkg in ('tree_sitter', 'tiktoken'):
        if importlib.util.find_spec(pkg) is None:
            missing.append(pkg)

    try:
        from tree_sitter_c import language as c_lang
        c_lang()
    except Exception:
        missing.append('tree-sitter-c')

    if missing:
        sys.exit(f'fatal: missing packages: {", ".join(missing)}. '
                 f'Run: pip install tree-sitter tree-sitter-c tiktoken')

    import tree_sitter
    ts_ver = getattr(tree_sitter, '__version__', None)
    if ts_ver is None:
        ts_ver = getattr(tree_sitter, 'version', None) or '0.25+'
    if isinstance(ts_ver, str):
        try:
            parts = tuple(int(x) for x in ts_ver.split('.')[:2])
            if parts < (0, 25):
                sys.exit(f'fatal: tree-sitter {ts_ver} detected, '
                         f'>= 0.25 required (0.22 API is incompatible)')
        except (ValueError, TypeError):
            pass

    poc_stage_exists = (Path(__file__).parent / 'stages/shield.py').exists()
    if poc_stage_exists and not shutil.which('gcc'):
        pass


def main() -> None:
    _check_deps()

    parser = argparse.ArgumentParser(description='AI vuln harness v1 scaffold')
    parser.add_argument('--mode', choices=['full', 'max-run', 'validate-only', 'resume', 'diff', 'all', 'poc-only'], default='full')
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
    parser.add_argument('--max-run', type=int, default=None,
                        help='Process only the first N packs (invaluable for debugging a single domain)')
    parser.add_argument('--skip-health', action='store_true',
                        help='Skip model health checks for cached re-runs')
    parser.add_argument('--scope-notes', type=Path, default=None,
                        help='Path to a text file whose contents are appended to every '
                             "stage's user_input to scope or exclude surfaces")
    parser.add_argument('--reingest', action='store_true',
                        help='Skip re-extraction if cached outputs exist (load from output/snippet_db.json)')
    parser.add_argument('--proxy', type=str, default=None,
                        help='Set HTTP_PROXY/HTTPS_PROXY env vars for all outbound requests')
    parser.add_argument('--model-health-check', action='store_true',
                        help='Run model health check only (no pipeline). Probes all models and reports alive/dead.')
    parser.add_argument('--model', type=str, action='append', dest='model_override',
                        help='Override the hunt model chain (may be specified multiple times). '
                             'Overrides the default model chain entirely.')
    parser.add_argument('--validate-model', type=str, action='append', dest='validate_model_override',
                        help='Override the validate model chain (may be specified multiple times). '
                             'Overrides the validate model pool entirely.')
    parser.add_argument('--budget-ratio', type=float, default=0.85,
                        help='Fraction of min_context to use as token budget (default: 0.85)')
    parser.add_argument('--refresh-models', action='store_true',
                        help='Invalidate model limits cache before this run')
    parser.add_argument('--pooled', action='store_true',
                        help='Use pooled model mode: all alive models go into a shared pool ranked by '
                             'capability. call_llm picks the best model; on failure marks it dead and '
                             'retries with the next best. Applies to both Hunt and Validate stages.')
    parser.add_argument('--poc', type=str, nargs='?', const='all', default=None, dest='poc_finding',
                        help='Run PoC confirmation on findings. Without argument: all findings. '
                             'With ID: that specific finding. Combine with --poc-only to skip API stages.')
    parser.add_argument('--poc-only', action='store_true', dest='poc_only',
                         help='Skip API stages; load cached findings and gaps, run PoC only.')
    parser.add_argument('--log-file', type=Path, default=None,
                         help='Write detailed debug logs to this file instead of <repo>/../run.log')
    args = parser.parse_args()

    if args.proxy:
        os.environ.setdefault('http_proxy', args.proxy)
        os.environ.setdefault('https_proxy', args.proxy)
        os.environ.setdefault('HTTP_PROXY', args.proxy)
        os.environ.setdefault('HTTPS_PROXY', args.proxy)

    scope_notes_text: str | None = None
    if args.scope_notes is not None:
        scope_notes_text = Path(args.scope_notes).read_text()

    mode = args.mode
    if args.poc_only:
        mode = 'poc-only'

    kwargs = dict(
        auth_path=args.auth_json,
        kl_threshold=args.kl_threshold,
        cosine_threshold=args.cosine_threshold,
        allow_full_db_fallback=args.allow_full_db_fallback,
        base_commit=args.base_commit,
        head_commit=args.head_commit,
        max_cost_usd=args.max_cost_usd,
        max_concurrency=args.max_concurrency,
        skip_health=args.skip_health,
        max_run=args.max_run,
        scope_notes=scope_notes_text,
        reingest=args.reingest,
        model_chain_override=args.model_override,
        validate_model_chain_override=args.validate_model_override,
        run_poc_enabled=args.poc_finding is not None or args.poc_only,
        poc_finding_id=args.poc_finding if args.poc_finding != 'all' else None,
        refresh_models=args.refresh_models,
        budget_ratio=args.budget_ratio,
        pooled=args.pooled,
    )

    # Validate that auth exists for non-cached modes
    if mode in ('full', 'max-run', 'all') and not args.auth_json and not Path(Path(__file__).parent / 'auth.json').exists() and not Path(Path.home() / '.local/share/opencode/auth.json').exists():
        logger.warning('No auth.json found; running with empty model pools (will produce 0 findings)')

    _setup_logging(
        log_file=args.log_file,
        log_dir=None if args.log_file else (Path(args.repo).parent if Path(args.repo).is_absolute() else None),
    )

    if args.model_health_check:
        from stages.runtime import fetch_model_limits, health_check_models
        sd = Path(__file__).parent
        auth = load_auth_config(explicit_path=args.auth_json, script_dir=sd)
        cache = JsonCache(sd / 'output/cache.json')
        model_chain = args.model_override or []
        model_limits = fetch_model_limits(model_chain, sd)
        all_models = list(model_limits.keys()) if model_limits else model_chain
        if not all_models:
            print(json.dumps({'error': 'no models to check'}, indent=2))
            return
        alive, dead = health_check_models(all_models, auth=auth, cache=cache, max_workers=8)
        cache.put('model_health_alive', alive)
        cache.put('model_health_dead', dead)
        cache.put('model_health_timestamp', time.time())
        result = {
            'alive': {m: model_limits.get(m, '?') for m in sorted(alive, key=lambda x: -(model_limits.get(x, 0) if isinstance(model_limits.get(x), int) else 0))},
            'dead': {m: str(e[:100]) for m, e in sorted(dead, key=lambda x: -(model_limits.get(x[0], 0) if isinstance(model_limits.get(x[0]), int) else 0))},
        }
        print(json.dumps(result, indent=2))
        return

    if mode == 'all':
        report = run_all(Path(args.repo), **kwargs)
    else:
        report = run(mode, Path(args.repo), **kwargs)
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
