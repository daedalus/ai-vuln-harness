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
import contextlib
import json
import logging
import os
import sys
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from pathlib import Path

from stages.chains import synthesize_exploit_chains
from stages.contracts import standardize_finding
from stages.coordinator import build_context_packs
from stages.diff import get_changed_snippets
from stages.exposure import annotate_exposure_windows
from stages.feedback import build_feedback_tasks
from stages.gapfill import build_gapfill_tasks
from stages.ingestor import filter_snippets, load_repo_snippets, tag_snippet
from stages.parser import parse_findings
from stages.poc import process_findings as run_poc
from stages.recon import build_recon_tasks
from stages.report import build_report, deduplicate
from stages.runtime import (
    HUNT_SYSTEM_PROMPT,
    VALIDATE_SYSTEM_PROMPT,
    JsonCache,
    ModelPool,
    StateDB,
    _rephrase_gap_prompt,
    call_llm,
    call_llm_from_pool,
    fetch_model_limits,
    health_check_models,
    load_auth_config,
    load_packs_pickle,
    repair_json_output,
    save_packs_pickle,
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
from stages.suppressions import SuppressionRegistry
from stages.validate import build_validate_prompt, is_api_by_design
from stages.voting import merge_hunter_outputs

logger = logging.getLogger("vuln-harness")


def _ingest_snippets(
    repo: Path,
    output_dir: Path,
    reingest: bool,
    cfg: dict,
) -> tuple[list[dict], dict]:
    snippet_db_path = output_dir / "snippet_db.json"
    if reingest and snippet_db_path.exists():
        snippet_db = json.loads(snippet_db_path.read_text())
        if isinstance(snippet_db, list):
            snippet_db = {s["id"]: s for s in snippet_db}
        snippets = list(snippet_db.values())
    else:
        raw_snippets = load_repo_snippets(
            repo,
            is_library_target=cfg["is_library_target"],
        )
        snippets = filter_snippets(
            raw_snippets,
            is_library_target=cfg["is_library_target"],
        )
        for s in snippets:
            s["tags"] = sorted(
                set(s.get("tags") or [])
                | set(tag_snippet(s, is_library_target=cfg["is_library_target"])),
            )
        snippet_db = {s["id"]: s for s in snippets}
        snippet_db_path.write_text(json.dumps(snippet_db, indent=2))
    return snippets, snippet_db


def _apply_diff_filter(
    mode: str,
    base_commit: str | None,
    repo: Path,
    snippets: list[dict],
    head_commit: str,
    state: StateDB,
) -> list[dict]:
    if mode != "diff" and base_commit is None:
        return snippets
    if base_commit is None:
        msg = "--base-commit is required when mode is 'diff'"
        raise ValueError(msg)
    snippets = get_changed_snippets(repo, snippets, base_commit, head_commit)
    state.put_meta("diff_base_commit", base_commit)
    state.put_meta("diff_head_commit", head_commit)
    state.put_meta("diff_snippet_count", str(len(snippets)))
    return snippets


def _resolve_model_chain(
    model_chain_override: list[str] | None,
    skip_health: bool,
    auth: dict,
    mode: str,
    cache: JsonCache,
) -> list[str]:
    model_chain = model_chain_override or [
        "deepseek/deepseek-v4-flash:free",
        "qwen/qwen-2.5-coder-32b-instruct:free",
        "nvidia/nemotron-3-super-120b-a12b:free",
        "arcee-ai/trinity-large-thinking:free",
    ]
    if not skip_health and auth and mode not in ("validate-only", "resume", "poc-only"):
        alive, dead = health_check_models(model_chain, auth=auth, cache=cache)
        cache.put("model_health_alive", alive)
        cache.put("model_health_dead", dead)
        cache.put("model_health_timestamp", time.time())
        if dead:
            logger.warning("dead models: %s", dead)
        if alive:
            model_chain = alive
        else:
            logger.warning("all models dead; continuing with original chain")
    elif skip_health:
        cached_alive = cache.get("model_health_alive")
        if cached_alive:
            model_chain = cached_alive
    return model_chain


def _resolve_pools(
    model_chain: list[str],
    model_limits: dict,
    pooled: bool,
    validate_model_chain_override: list[str] | None,
    state: StateDB,
) -> tuple[list[str], list[str], ModelPool | None]:
    if pooled:
        model_pool = ModelPool(model_chain, model_limits)
        hunt_models = model_pool.alive
        validate_models = model_pool.alive
        state.put_meta("pooled", "true")
    else:
        model_pool = None
        hunt_models, validate_models = split_model_pools(model_chain)
    if validate_model_chain_override and not pooled:
        validate_models = validate_model_chain_override
    return hunt_models, validate_models, model_pool


def _run_hunt_stage(
    mode: str,
    auth: dict,
    packs: list[dict],
    hunt_models: list[str],
    cache: JsonCache,
    hunt_workers: int,
    max_run: int | None,
    domain_map: dict,
    model_pool: ModelPool | None,
    output_dir: Path,
) -> tuple[list[dict], list[dict]]:
    if mode in ("validate-only", "resume", "poc-only"):
        all_findings = _load_jsonl(output_dir / "findings.jsonl")
        all_gaps = _load_jsonl(output_dir / "gaps.jsonl")
        return all_findings, all_gaps
    if not auth:
        logger.warning("no auth configured; using empty findings")
        return [], []
    all_findings, all_gaps = _run_hunt_packs(
        packs,
        hunt_models,
        auth=auth,
        cache=cache,
        parallel=hunt_workers,
        max_run=max_run,
        domain_map=domain_map,
        model_pool=model_pool,
    )
    _persist_jsonl(output_dir / "findings.jsonl", all_findings)
    _persist_jsonl(output_dir / "gaps.jsonl", all_gaps)
    return all_findings, all_gaps


def _run_validate_stage(
    mode: str,
    all_findings: list[dict],
    snippet_db: dict,
    validate_models: list[str],
    pooled: bool,
    auth: dict,
    cache: JsonCache,
    validate_workers: int,
    model_pool: ModelPool | None,
    output_dir: Path,
) -> list[dict]:
    if mode in ("validate-only", "poc-only") or not all_findings or not auth:
        validated = all_findings[:]
        for f in validated:
            f.setdefault("validate_status", "needs-more-info")
            f.setdefault("validate_reason", "skipped")
        return validated
    validated = _run_validate_findings(
        all_findings,
        snippet_db,
        validate_models,
        auth=auth,
        cache=cache,
        parallel=validate_workers,
        model_pool=model_pool if pooled else None,
    )
    _persist_jsonl(output_dir / "validated.jsonl", validated)
    return validated


def _run_gapfill_loop(
    recon_tasks: list[dict],
    validated: list[dict],
    all_gaps: list[dict],
    packs: list[dict],
    hunt_models: list[str],
    domain_map: dict,
    auth: dict,
    cache: JsonCache,
    hunt_workers: int,
    model_pool: ModelPool | None,
    scope_notes: str | None,
) -> tuple[list[dict], list[dict], list[dict]]:
    gapfill_tasks = build_gapfill_tasks(
        recon_tasks,
        validated,
        max_tasks=5,
        scope_notes=scope_notes,
    )
    for gapfill_iter in range(2):
        current = [g for g in all_gaps if not g.get("gapfill_retried")]
        if not current:
            break
        fresh_f, fresh_g = _gapfill_rerun(
            current,
            packs,
            hunt_models,
            domain_map,
            auth=auth,
            cache=cache,
            parallel=hunt_workers,
            gapfill_iter=gapfill_iter,
            model_pool=model_pool,
        )
        validated.extend(fresh_f)
        all_gaps = [g for g in all_gaps if g.get("gapfill_retried")] + fresh_g
    return validated, all_gaps, gapfill_tasks


def _build_coordinator_packs(
    snippets: list[dict],
    recon_tasks: list[dict] | None,
    output_dir: Path,
    budget_tokens: int,
    allow_full_db_fallback: bool,
    load_packs_cache: bool,
) -> list[dict]:
    packs_pkl = output_dir / "context_packs.pkl"
    if load_packs_cache and packs_pkl.exists():
        return load_packs_pickle(packs_pkl)
    packs = build_context_packs(
        snippets,
        recon_tasks=recon_tasks,
        allow_full_db_fallback=allow_full_db_fallback,
        budget_tokens=budget_tokens,
    )
    save_packs_pickle(packs, packs_pkl)
    return packs


def _build_domain_map(packs: list[dict]) -> dict[str, list[dict]]:
    dm: dict[str, list[dict]] = {}
    for p in packs:
        dm.setdefault(p.get("agent", ""), []).append(p)
    counts: Counter = Counter()
    for p in packs:
        counts[p.get("agent", "?")] += 1
    logger.info("pack total=%d per_domain=%s", len(packs), dict(counts))
    for i, p in enumerate(packs):
        tc_sum = sum(s.get("token_count", 0) for s in p.get("snippets", []))
        logger.info(
            "pack #%d agent=%s snippets=%d token_count_sum=%d prompt_chars=%d",
            i + 1,
            p.get("agent", "?"),
            len(p.get("snippets", [])),
            tc_sum,
            len(json.dumps(p, indent=2)),
        )
    return dm


def _run_poc_stage(
    findings: list[dict],
    snippet_db: dict,
    output_dir: Path,
    run_poc_enabled: bool,
    poc_finding_id: str | None,
) -> list[dict]:
    if not run_poc_enabled:
        return []
    target = findings
    if poc_finding_id and poc_finding_id != "all":
        target = [
            f
            for f in findings
            if f.get("id") == poc_finding_id or f.get("finding_id") == poc_finding_id
        ]
    if not target:
        _persist_jsonl(output_dir / "pocs.jsonl", [])
        return []
    pocs = run_poc(target, snippet_db)
    _persist_jsonl(output_dir / "pocs.jsonl", pocs)
    return pocs


def _run_trace_stage(findings: list[dict], state: StateDB) -> None:
    for f in findings:
        f.setdefault("trace_status", "not_required")
    state.put_meta(
        "trace_results",
        json.dumps(
            {
                "not_required": len(
                    [f for f in findings if f.get("trace_status") == "not_required"],
                ),
            },
        ),
    )


def _run_shield_stage(
    promoted: list[dict],
    snippet_db: dict,
    cfg: dict,
    kl_threshold: float,
    cosine_threshold: float,
) -> tuple[list[dict], list[dict]]:
    call_graph = build_call_graph(list(snippet_db.values()))
    promoted = annotate_call_path_verification(promoted, call_graph)
    promoted = annotate_hallucination(promoted, snippet_db)
    promoted = annotate_hallucination_kl(promoted, snippet_db, threshold=kl_threshold)
    promoted = deduplicate_semantic(promoted, threshold=cosine_threshold)
    entry_points = cfg.get("entry_points", [])
    return filter_unreachable(promoted, call_graph, entry_points)


def _setup_logging(log_dir: Path | None = None, log_file: Path | None = None) -> None:
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)
    fmt = logging.Formatter(
        "%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%H:%M:%S",
    )

    stderr = logging.StreamHandler(sys.stderr)
    stderr.setLevel(logging.INFO)
    stderr.setFormatter(fmt)
    root.addHandler(stderr)

    if log_file:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        root.addHandler(fh)
    elif log_dir:
        log_dir.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(log_dir / "run.log", encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(fmt)
        root.addHandler(fh)


def _load_stages_config(script_dir: Path) -> dict:
    """Load per-stage model-pool and concurrency config from config/stages.json.

    Returns an empty dict if the file is absent or malformed so callers can
    safely fall back to defaults.
    """
    path = script_dir / "config" / "stages.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except (json.JSONDecodeError, OSError):
        return {}


def _stage_workers(stages_cfg: dict, stage: str, global_max: int) -> int:
    """Resolve the effective max_workers for *stage* honouring global cap."""
    stage_cfg = stages_cfg.get("stages", {}).get(stage, {})
    per_stage = stage_cfg.get("max_workers", global_max)
    return min(per_stage, global_max)


def _run_one_hunt_pack(
    pack: dict,
    model: str,
    *,
    auth: dict[str, str],
    cache: JsonCache,
) -> tuple[list[dict], list[dict]]:
    prompt = pack.get("prompt") or json.dumps(pack, indent=2)
    tc_sum = sum(s.get("token_count", 0) for s in pack.get("snippets", []))
    logger.info(
        "hunt pack %s model=%s token_count_sum=%d prompt_chars=%d",
        pack.get("agent", "?"),
        model,
        tc_sum,
        len(prompt),
    )
    try:
        raw = call_llm(
            model,
            prompt,
            system=HUNT_SYSTEM_PROMPT,
            auth=auth,
            cache=cache,
        )
        logger.debug("hunt pack %s raw=%d chars", pack.get("agent", "?"), len(raw))
        domain = pack.get("agent", "unknown")
        findings, gaps = parse_findings(raw, domain=domain)
        logger.debug(
            "hunt pack %s parsed: %d findings, %d gaps",
            pack.get("agent", "?"),
            len(findings),
            len(gaps),
        )
        for f in findings:
            f.setdefault("hunt_model", model)
        return findings, gaps
    except Exception as e:
        logger.warning(
            "hunt model %s pack %s failed: %s",
            model,
            pack.get("agent", "?"),
            e,
        )
        gap_domain = pack.get("agent", "unknown")
        return [], [
            {
                "coverage_gap": gap_domain,
                "reason": f"hunt exception: {e}",
                "domain": gap_domain,
            },
        ]


def _run_one_hunt_pack_from_pool(
    pack: dict,
    pool: ModelPool,
    *,
    auth: dict[str, str],
    cache: JsonCache,
) -> tuple[list[dict], list[dict]]:
    prompt = pack.get("prompt") or json.dumps(pack, indent=2)
    logger.info(
        "hunt pack %s pooled prompt_chars=%d",
        pack.get("agent", "?"),
        len(prompt),
    )
    try:
        raw = call_llm_from_pool(
            pool,
            prompt,
            system=HUNT_SYSTEM_PROMPT,
            auth=auth,
            cache=cache,
        )
        logger.debug(
            "hunt pack %s pooled raw=%d chars",
            pack.get("agent", "?"),
            len(raw),
        )
        domain = pack.get("agent", "unknown")
        findings, gaps = parse_findings(raw, domain=domain)
        logger.debug(
            "hunt pack %s pooled parsed: %d findings, %d gaps",
            pack.get("agent", "?"),
            len(findings),
            len(gaps),
        )
        return findings, gaps
    except Exception as e:
        logger.warning("hunt pack %s pooled failed: %s", pack.get("agent", "?"), e)
        gap_domain = pack.get("agent", "unknown")
        return [], [
            {
                "coverage_gap": gap_domain,
                "reason": f"hunt exception: {e}",
                "domain": gap_domain,
            },
        ]


def _run_hunt_packs(
    packs: list[dict],
    models: list[str],
    *,
    auth: dict[str, str],
    cache: JsonCache,
    parallel: int = 3,
    max_run: int | None = None,
    domain_map: dict[str, list[dict]] | None = None,  # noqa: ARG001
    model_pool: ModelPool | None = None,
) -> tuple[list[dict], list[dict]]:
    from stages.runtime import _MODEL_BY_DOMAIN

    if max_run is not None:
        packs = packs[:max_run]

    all_findings: list[dict] = []
    all_gaps: list[dict] = []

    if model_pool is not None:
        tasks = [{"pack": p} for p in packs]
    else:
        tasks: list[dict] = []
        for pack in packs:
            domain = pack.get("agent", "mem-safety")
            preferred = _MODEL_BY_DOMAIN.get(domain)
            ordered = []
            if preferred and preferred in models:
                ordered.append(preferred)
            ordered.extend(m for m in models if m not in ordered)
            tasks.append({"pack": pack, "models": ordered})

    completed = 0
    total = len(tasks)
    logger.info(
        "hunt starting %d pack(s) with %d worker(s)%s",
        total,
        parallel,
        " (pooled)" if model_pool else "",
    )

    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = {}
        for t in tasks:
            if model_pool is not None:
                futures[
                    pool.submit(
                        _run_one_hunt_pack_from_pool,
                        t["pack"],
                        model_pool,
                        auth=auth,
                        cache=cache,
                    )
                ] = t
            else:
                model = t["models"][0] if t["models"] else ""
                futures[
                    pool.submit(
                        _run_one_hunt_pack,
                        t["pack"],
                        model,
                        auth=auth,
                        cache=cache,
                    )
                ] = t

        for f in as_completed(futures):
            t = futures[f]
            domain = t["pack"].get("agent", "?")
            try:
                findings, gaps = f.result()
                all_findings.extend(findings)
                all_gaps.extend(gaps)
            except Exception as e:
                all_gaps.append(
                    {"coverage_gap": domain, "reason": f"hunt worker exception: {e}"},
                )
            completed += 1
            logger.info("hunt %d/%d packs done", completed, total)

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
        logger.debug(
            "validate skip %s: api_by_design",
            finding.get("title", finding.get("name", "?")),
        )
        return {
            **finding,
            "validate_status": "rejected",
            "validate_reason": "api_by_design",
        }
    finding = standardize_finding(finding)
    prompt = build_validate_prompt(finding, snippet)
    logger.debug(
        "validate finding=%s model=%s prompt_chars=%d",
        finding.get("title", "?"),
        model,
        len(prompt),
    )
    try:
        raw = call_llm(
            model,
            prompt,
            system=VALIDATE_SYSTEM_PROMPT,
            auth=auth,
            cache=cache,
        )
        parsed, _repaired = repair_json_output(raw)
        if not parsed:
            parsed = {}
        status = parsed.get("status", "needs-more-info")
        reason = parsed.get("reason", "") or ""
        if not parsed:
            reason = f"unparseable LLM response: {raw[:200]}"
        logger.debug("validate result: status=%s reason=%s", status, reason[:80])
        return {**finding, "validate_status": status, "validate_reason": reason}
    except Exception as e:
        logger.warning("validate exception for %s: %s", finding.get("title", "?"), e)
        return {
            **finding,
            "validate_status": "needs-more-info",
            "validate_reason": f"validate exception: {e}",
        }


def _run_validate_finding_from_pool(
    finding: dict,
    snippet: dict,
    pool: ModelPool,
    *,
    auth: dict[str, str],
    cache: JsonCache,
) -> dict:
    if is_api_by_design(finding, snippet):
        return {
            **finding,
            "validate_status": "rejected",
            "validate_reason": "api_by_design",
        }
    finding = standardize_finding(finding)
    prompt = build_validate_prompt(finding, snippet)
    try:
        raw = call_llm_from_pool(
            pool,
            prompt,
            system=VALIDATE_SYSTEM_PROMPT,
            auth=auth,
            cache=cache,
        )
        parsed, _repaired = repair_json_output(raw)
        if not parsed:
            parsed = {}
        status = parsed.get("status", "needs-more-info")
        reason = parsed.get("reason", "") or ""
        if not parsed:
            reason = f"unparseable LLM response: {raw[:200]}"
        return {**finding, "validate_status": status, "validate_reason": reason}
    except Exception as e:
        return {
            **finding,
            "validate_status": "needs-more-info",
            "validate_reason": f"validate exception: {e}",
        }


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
    logger.info(
        "validate validating %d finding(s) with %d worker(s)%s",
        total,
        parallel,
        " (pooled)" if model_pool else "",
    )

    with ThreadPoolExecutor(max_workers=parallel) as pool:
        futures = {}
        for finding in findings:
            sid = finding.get("snippet_id", "")
            snippet = snippet_db.get(sid, {})
            if model_pool is not None:
                futures[
                    pool.submit(
                        _run_validate_finding_from_pool,
                        finding,
                        snippet,
                        model_pool,
                        auth=auth,
                        cache=cache,
                    )
                ] = finding
            else:
                model = models[0] if models else "deepseek/deepseek-v4-flash:free"
                futures[
                    pool.submit(
                        _run_validate_finding,
                        finding,
                        snippet,
                        model,
                        auth=auth,
                        cache=cache,
                    )
                ] = finding

        completed = 0
        for f in as_completed(futures):
            try:
                validated.append(f.result())
            except Exception as e:
                orig = futures[f]
                validated.append(
                    {
                        **orig,
                        "validate_status": "needs-more-info",
                        "validate_reason": str(e),
                    },
                )
            completed += 1
            logger.info("validate %d/%d findings done", completed, total)

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
        domain = g.get("coverage_gap", g.get("domain", "mem-safety"))
        candidates = domain_map.get(domain, original_packs[:1])
        if not candidates:
            continue
        pack = deepcopy(candidates[0])
        prompt_text = json.dumps(pack, indent=2)
        pack["prompt"] = _rephrase_gap_prompt(prompt_text, fallback_model)
        pack["gapfill_model"] = fallback_model
        pack["agent"] = domain
        rerun_packs.append(pack)

    logger.info(
        "gapfill iteration %d/2: retrying %d gap(s) with model %s%s",
        gapfill_iter + 1,
        len(rerun_packs),
        fallback_model,
        " (pooled)" if model_pool else "",
    )
    for g in rerun_packs:
        logger.debug(
            "gapfill pack domain=%s prompt_chars=%d",
            g.get("agent", "?"),
            len(g.get("prompt", "")),
        )

    fresh_findings, fresh_gaps = _run_hunt_packs(
        rerun_packs,
        [fallback_model],
        auth=auth,
        cache=cache,
        parallel=parallel,
        model_pool=model_pool,
    )

    logger.debug(
        "gapfill iteration %d: %d fresh findings, %d remaining gaps",
        gapfill_iter + 1,
        len(fresh_findings),
        len(fresh_gaps),
    )

    for g in gaps:
        g["gapfill_retried"] = True

    return fresh_findings, fresh_gaps


def _load_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    items: list[dict] = []
    for line in path.read_text().strip().splitlines():
        line = line.strip()
        if line:
            with contextlib.suppress(json.JSONDecodeError):
                items.append(json.loads(line))
    return items


def _persist_jsonl(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        f.writelines(json.dumps(item) + "\n" for item in items)


def run(
    mode: str,
    repo: Path,
    *,
    auth_path: Path | None = None,
    kl_threshold: float = 5.0,
    cosine_threshold: float = 0.85,
    allow_full_db_fallback: bool = False,
    base_commit: str | None = None,
    head_commit: str = "HEAD",
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
    pooled: bool = False,
    load_packs_cache: bool = False,
) -> dict:
    script_dir = Path(__file__).parent
    cfg = json.loads((script_dir / "config/defaults.json").read_text())
    stages_cfg = _load_stages_config(script_dir)
    state = StateDB(script_dir / cfg["state_db"])
    cache = JsonCache(script_dir / cfg["cache_file"])

    run_id = f"{mode}:{repo!s}"
    state.create_run(repo_path=str(repo), run_id=run_id)
    if max_cost_usd is not None:
        spent = state.total_cost(run_id)
        if spent >= max_cost_usd:
            state.finish_run(run_id, "cost_limit")
            msg = f"Cost limit ${max_cost_usd:.2f} reached (${spent:.2f} already spent)"
            raise RuntimeError(
                msg,
            )

    auth = load_auth_config(explicit_path=auth_path, script_dir=script_dir)
    state.put_meta("auth_providers", json.dumps(sorted(auth.keys())))

    global_max = max_concurrency or cfg.get("max_workers", 3)
    hunt_workers = _stage_workers(stages_cfg, "hunt", global_max)
    validate_workers = _stage_workers(stages_cfg, "validate", global_max)
    output_dir = script_dir / "output"
    output_dir.mkdir(parents=True, exist_ok=True)
    state.put_meta("hunt_workers", str(hunt_workers))
    state.put_meta("validate_workers", str(validate_workers))

    snippets, snippet_db = _ingest_snippets(repo, output_dir, reingest, cfg)
    snippets = _apply_diff_filter(mode, base_commit, repo, snippets, head_commit, state)

    model_chain = _resolve_model_chain(
        model_chain_override,
        skip_health,
        auth,
        mode,
        cache,
    )
    if refresh_models:
        p = script_dir / "config/model_limits.json"
        if p.exists():
            p.unlink()
    model_limits = fetch_model_limits(model_chain, script_dir)
    budget_tokens = int(min(model_limits.values()) * budget_ratio)

    recon_tasks = build_recon_tasks(
        snippets,
        repo_path=str(repo),
        scope_notes=scope_notes,
    )
    state.put_meta("recon_task_count", str(len(recon_tasks)))
    _persist_jsonl(output_dir / "recon_tasks.json", recon_tasks)

    packs = _build_coordinator_packs(
        snippets,
        recon_tasks,
        output_dir,
        budget_tokens,
        allow_full_db_fallback,
        load_packs_cache,
    )
    state.put_meta("pack_count", str(len(packs)))
    domain_map = _build_domain_map(packs)
    _persist_jsonl(output_dir / "context_packs.json", packs)

    hunt_models, validate_models, model_pool = _resolve_pools(
        model_chain,
        model_limits,
        pooled,
        validate_model_chain_override,
        state,
    )

    all_findings, all_gaps = _run_hunt_stage(
        mode,
        auth,
        packs,
        hunt_models,
        cache,
        hunt_workers,
        max_run,
        domain_map,
        model_pool,
        output_dir,
    )

    validated = _run_validate_stage(
        mode,
        all_findings,
        snippet_db,
        validate_models,
        pooled,
        auth,
        cache,
        validate_workers,
        model_pool,
        output_dir,
    )

    validated, all_gaps, gapfill_tasks = _run_gapfill_loop(
        recon_tasks,
        validated,
        all_gaps,
        packs,
        hunt_models,
        domain_map,
        auth,
        cache,
        hunt_workers,
        model_pool,
        scope_notes,
    )
    state.put_meta("gapfill_task_count", str(len(gapfill_tasks)))
    all_tasks = recon_tasks + gapfill_tasks

    promoted, suppressed_by_vote = merge_hunter_outputs(
        [validated],
        min_votes=cfg.get("shield", {}).get("min_votes", 2),
    )
    state.put_meta("suppressed_by_vote", str(len(suppressed_by_vote)))

    promoted, unreachable = _run_shield_stage(
        promoted,
        snippet_db,
        cfg,
        kl_threshold,
        cosine_threshold,
    )
    state.put_meta("unreachable_count", str(len(unreachable)))

    registry = SuppressionRegistry(
        script_dir / cfg.get("suppressions_file", "output/suppressions.json"),
    )
    findings, registry_suppressed = registry.filter(promoted)
    state.put_meta("registry_suppressed", str(len(registry_suppressed)))

    chains = synthesize_exploit_chains(findings, snippets)
    pocs = _run_poc_stage(
        findings,
        snippet_db,
        output_dir,
        run_poc_enabled,
        poc_finding_id,
    )
    _run_trace_stage(findings, state)

    findings, exposure_metrics = annotate_exposure_windows(findings, repo)

    traced = [f for f in findings if f.get("trace_status") == "confirmed"]
    covered = {f for t in all_tasks for f in t.get("target_files", [])}
    feedback_tasks = build_feedback_tasks(
        traced,
        snippets,
        already_covered=covered,
        max_tasks=10,
        scope_notes=scope_notes,
    )
    state.put_meta("feedback_task_count", str(len(feedback_tasks)))

    report = build_report(
        repo=str(repo),
        findings=findings,
        chains=chains,
        gaps=[
            {"domain": t["domain"], "files": t["target_files"]} for t in gapfill_tasks
        ],
        trace_required=cfg["is_library_target"],
        exposure_metrics=exposure_metrics,
    )
    if pocs:
        report["pocs"] = pocs

    state.put_meta("last_mode", mode)
    state.finish_run(run_id)
    cache.put("last_report", report)
    return report


_SINGLE_MODES: list[str] = [
    "full",
    "max-run",
    "validate-only",
    "resume",
    "diff",
    "poc-only",
]


def _merge_reports(reports: list[dict]) -> dict:
    """Merge multiple per-mode reports into a single combined report.

    Findings are deduplicated across reports using the same composite key
    used inside ``build_report`` (file x class x start-line).  The
    highest-severity variant is kept.  Summary counters, chains, and gaps
    are aggregated across all reports.
    """
    if not reports:
        return build_report(repo="", findings=[], chains=[], gaps=[])

    repo = reports[0].get("repo", "")
    all_findings: list[dict] = []
    all_chains: list[dict] = []
    all_gaps: list[dict] = []
    combined_summary: dict[str, int] = {}

    for report in reports:
        all_findings.extend(report.get("findings") or [])
        all_chains.extend(report.get("chains") or [])
        all_gaps.extend(report.get("gaps") or [])
        for key, val in (report.get("summary") or {}).items():
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
    merged["summary"] = combined_summary
    merged["modes_run"] = [r.get("mode_run", "unknown") for r in reports]
    return merged


def run_all(
    repo: Path,
    *,
    auth_path: Path | None = None,
    kl_threshold: float = 5.0,
    cosine_threshold: float = 0.85,
    allow_full_db_fallback: bool = False,
    base_commit: str | None = None,
    head_commit: str = "HEAD",
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
    pooled: bool = False,
    load_packs_cache: bool = False,
) -> dict:
    reports: list[dict] = []
    for mode in _SINGLE_MODES:
        if mode == "diff" and base_commit is None:
            continue
        if mode == "poc-only" and not run_poc_enabled:
            continue
        report = run(
            mode,
            repo,
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
            load_packs_cache=load_packs_cache,
        )
        report["mode_run"] = mode
        reports.append(report)

    merged = _merge_reports(reports)
    merged["mode_run"] = "all"
    return merged


def _check_deps() -> None:
    import importlib
    import shutil
    import sys

    missing = []
    for pkg in ("tree_sitter", "tiktoken"):
        if importlib.util.find_spec(pkg) is None:
            missing.append(pkg)

    try:
        from tree_sitter_c import language as c_lang

        c_lang()
    except Exception:
        missing.append("tree-sitter-c")

    if missing:
        sys.exit(
            f"fatal: missing packages: {', '.join(missing)}. "
            f"Run: pip install tree-sitter tree-sitter-c tiktoken",
        )

    import tree_sitter

    ts_ver = getattr(tree_sitter, "__version__", None)
    if ts_ver is None:
        ts_ver = getattr(tree_sitter, "version", None) or "0.25+"
    if isinstance(ts_ver, str):
        try:
            parts = tuple(int(x) for x in ts_ver.split(".")[:2])
            if parts < (0, 25):
                sys.exit(
                    f"fatal: tree-sitter {ts_ver} detected, "
                    f">= 0.25 required (0.22 API is incompatible)",
                )
        except (ValueError, TypeError):
            pass

    poc_stage_exists = (Path(__file__).parent / "stages/shield.py").exists()
    if poc_stage_exists and not shutil.which("gcc"):
        pass


def _setup_proxy(proxy: str | None) -> None:
    if not proxy:
        return
    for var in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY"):
        os.environ.setdefault(var, proxy)


def _warn_if_no_auth(mode: str, auth_json: Path | None) -> None:
    if mode not in ("full", "max-run", "all"):
        return
    if auth_json:
        return
    sd = Path(__file__).parent
    if (sd / "auth.json").exists():
        return
    if (Path.home() / ".local/share/opencode/auth.json").exists():
        return
    logger.warning(
        "No auth.json found; running with empty model pools (will produce 0 findings)",
    )


def _run_health_check(model_override: list[str] | None, auth_json: Path | None) -> None:
    from stages.runtime import (
        JsonCache,
        fetch_model_limits,
        health_check_models,
        load_auth_config,
    )

    sd = Path(__file__).parent
    auth = load_auth_config(explicit_path=auth_json, script_dir=sd)
    cache = JsonCache(sd / "output/cache.json")
    model_chain = model_override or []
    model_limits = fetch_model_limits(model_chain, sd)
    all_models = list(model_limits.keys()) if model_limits else model_chain
    if not all_models:
        return
    alive, dead = health_check_models(all_models, auth=auth, cache=cache, max_workers=8)
    cache.put("model_health_alive", alive)
    cache.put("model_health_dead", dead)
    cache.put("model_health_timestamp", time.time())

    def _sort_key(m: str | tuple) -> int:
        v = model_limits.get(m[0] if isinstance(m, tuple) else m, 0)
        return -(v if isinstance(v, int) else 0)

    {
        "alive": {m: model_limits.get(m, "?") for m in sorted(alive, key=_sort_key)},
        "dead": {m: str(e[:100]) for m, e in sorted(dead, key=_sort_key)},
    }


def _build_run_kwargs(args: argparse.Namespace) -> dict:
    return {
        "auth_path": args.auth_json,
        "kl_threshold": args.kl_threshold,
        "cosine_threshold": args.cosine_threshold,
        "allow_full_db_fallback": args.allow_full_db_fallback,
        "base_commit": args.base_commit,
        "head_commit": args.head_commit,
        "max_cost_usd": args.max_cost_usd,
        "max_concurrency": args.max_concurrency,
        "skip_health": args.skip_health,
        "max_run": args.max_run,
        "scope_notes": Path(args.scope_notes).read_text() if args.scope_notes else None,
        "reingest": args.reingest,
        "model_chain_override": args.model_override,
        "validate_model_chain_override": args.validate_model_override,
        "run_poc_enabled": args.poc_finding is not None or args.poc_only,
        "poc_finding_id": args.poc_finding if args.poc_finding != "all" else None,
        "refresh_models": args.refresh_models,
        "budget_ratio": args.budget_ratio,
        "pooled": args.pooled,
        "load_packs_cache": args.load_packs_cache,
    }


def main() -> None:
    _check_deps()

    parser = argparse.ArgumentParser(description="AI vuln harness v1 scaffold")
    parser.add_argument(
        "--mode",
        choices=[
            "full",
            "max-run",
            "validate-only",
            "resume",
            "diff",
            "all",
            "poc-only",
        ],
        default="full",
    )
    parser.add_argument("--repo", required=True)
    parser.add_argument("--allow-full-db-fallback", action="store_true")
    parser.add_argument("--auth-json", type=Path, default=None)
    parser.add_argument("--kl-threshold", type=float, default=5.0)
    parser.add_argument("--cosine-threshold", type=float, default=0.85)
    parser.add_argument("--base-commit", type=str, default=None)
    parser.add_argument("--head-commit", type=str, default="HEAD")
    parser.add_argument("--max-cost-usd", type=float, default=None)
    parser.add_argument("--max-concurrency", type=int, default=None)
    parser.add_argument("--max-run", type=int, default=None)
    parser.add_argument("--skip-health", action="store_true")
    parser.add_argument("--scope-notes", type=Path, default=None)
    parser.add_argument("--reingest", action="store_true")
    parser.add_argument("--proxy", type=str, default=None)
    parser.add_argument("--model-health-check", action="store_true")
    parser.add_argument("--model", type=str, action="append", dest="model_override")
    parser.add_argument(
        "--validate-model",
        type=str,
        action="append",
        dest="validate_model_override",
    )
    parser.add_argument("--budget-ratio", type=float, default=0.85)
    parser.add_argument("--refresh-models", action="store_true")
    parser.add_argument("--load-packs-cache", action="store_true")
    parser.add_argument("--pooled", action="store_true")
    parser.add_argument(
        "--poc",
        type=str,
        nargs="?",
        const="all",
        default=None,
        dest="poc_finding",
    )
    parser.add_argument("--poc-only", action="store_true", dest="poc_only")
    parser.add_argument("--log-file", type=Path, default=None)
    args = parser.parse_args()

    _setup_proxy(args.proxy)

    mode = "poc-only" if args.poc_only else args.mode

    _warn_if_no_auth(mode, args.auth_json)

    _setup_logging(
        log_file=args.log_file,
        log_dir=None
        if args.log_file
        else (Path(args.repo).parent if Path(args.repo).is_absolute() else None),
    )

    if args.model_health_check:
        _run_health_check(args.model_override, args.auth_json)
        return

    kwargs = _build_run_kwargs(args)
    if mode == "all":
        run_all(Path(args.repo), **kwargs)
    else:
        run(mode, Path(args.repo), **kwargs)


if __name__ == "__main__":
    main()
