"""AI Vulnerability Research Harness — multi-agent pipeline runner.

Canonical pipeline (17 stages):
  INGESTOR → RECON → COORDINATOR → HUNT → LOCALIZATION → VALIDATE →
  FUZZ_ORCHESTRATOR → GAPFILL → VOTING → SHIELD → SUPPRESSIONS → CHAINS →
  POC → TRACE → EXPOSURE → FEEDBACK → REPORT

Never edit the template in place. Copy it first:
  cp -a /home/dclavijo/.opencode/skills/ai-vuln-harness/templates/v1/ ./my-harness/

Never survey the target yourself. The harness pipeline's INGESTOR and RECON
stages are the ONLY authorized surveyors — they parse the repo through
tree-sitter, build snippet databases, and construct context packs. Do not
read, explore, grep, or analyze the target repository directly. Pre-reading
the target contaminates the eval by leaking context that should only flow
through the pipeline.

Run modes: full | max-run | validate-only | resume | diff | all | poc-only | benchmark

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
from datetime import UTC, datetime
from pathlib import Path

from .stages.chains import synthesize_exploit_chains
from .stages.contracts import has_valid_suspicious_points, standardize_finding
from .stages.coordinator import build_context_packs
from .stages.diff import get_changed_snippets
from .stages.exploit_synthesis import (
    check_poc_synthesis_readiness,
    run_exploit_synthesis,
)
from .stages.exposure import annotate_exposure_windows
from .stages.feedback import build_feedback_tasks
from .stages.fuzz_orchestrator import orchestrate_fuzz_targets
from .stages.gapfill import build_gapfill_tasks
from .stages.ingestor import filter_snippets, load_repo_snippets, tag_snippet
from .stages.localization import localize_findings
from .stages.parser import parse_findings
from .stages.patch import build_patch_candidates
from .stages.pbt import run_pbt_on_findings
from .stages.poc import process_findings as run_poc
from .stages.recon import build_recon_tasks
from .stages.report import build_report, deduplicate
from .stages.runtime import (
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
    load_packs_json,
    repair_json_output,
    save_packs_json,
    split_model_pools,
)
from .stages.shield import (
    annotate_call_path_verification,
    annotate_hallucination,
    annotate_hallucination_kl,
    build_call_graph,
    deduplicate_semantic,
    filter_unreachable,
)
from .stages.suppressions import SuppressionRegistry
from .stages.validate import build_validate_prompt, is_api_by_design
from .stages.voting import merge_hunter_outputs
from .stages.z3_verifier import verify_validate_feasibility

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


def _run_localization_stage(
    all_findings: list[dict],
    snippet_db: dict[str, dict],
    cfg: dict,
    output_dir: Path,
) -> tuple[list[dict], list[dict]]:
    if not all_findings:
        return [], []
    localization_cfg = cfg.get("localization", {})
    if not cfg.get("enable_localization_stage", False):
        passthrough = []
        for finding in all_findings:
            standardized = standardize_finding(finding)
            standardized["has_valid_localization"] = has_valid_suspicious_points(
                standardized,
            )
            standardized["localization_enforced"] = False
            passthrough.append(standardized)
        _persist_jsonl(output_dir / "localized_findings.jsonl", passthrough)
        return passthrough, []
    localized, unreachable = localize_findings(
        all_findings,
        snippet_db,
        entry_points=cfg.get("entry_points", []),
        max_hops=int(localization_cfg.get("max_reachability_hops", 6)),
    )
    _persist_jsonl(output_dir / "localized_findings.jsonl", localized)
    _persist_jsonl(output_dir / "localized_unreachable.jsonl", unreachable)
    return localized, unreachable


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
    cfg: dict,
) -> list[dict]:
    prioritized = all_findings
    if cfg.get("enable_localization_stage", False):
        prioritized = _sort_for_validation(prioritized)
    if mode in ("validate-only", "poc-only") or not prioritized or not auth:
        validated = all_findings[:]
        for f in validated:
            f.setdefault("validate_status", "needs-more-info")
            f.setdefault("validate_reason", "skipped")
        return validated
    validate_cfg = cfg.get("validate", {})
    enable_z3_verifier = bool(
        isinstance(validate_cfg, dict) and validate_cfg.get("enable_z3_verifier", False)
    )
    z3_timeout_ms = (
        max(1, int(validate_cfg.get("z3_timeout_ms", 50)))
        if isinstance(validate_cfg, dict)
        else 50
    )
    validated = _run_validate_findings(
        prioritized,
        snippet_db,
        validate_models,
        auth=auth,
        cache=cache,
        parallel=validate_workers,
        model_pool=model_pool if pooled else None,
        enable_z3_verifier=enable_z3_verifier,
        z3_timeout_ms=z3_timeout_ms,
    )
    _persist_jsonl(output_dir / "validated.jsonl", validated)
    return validated


def _run_pbt_stage(
    findings: list[dict],
    snippet_db: dict[str, dict],
    cfg: dict,
    *,
    auth: dict[str, str] | None = None,
    cache: JsonCache | None = None,
) -> list[dict]:
    pbt_cfg = cfg.get("pbt", {})
    enabled = bool(cfg.get("enable_pbt", False))
    if not enabled:
        return findings
    model = str(pbt_cfg.get("model", ""))
    pbt_iterations = int(pbt_cfg.get("iterations", 500))
    compile_timeout = int(pbt_cfg.get("compile_timeout", 30))
    run_timeout = int(pbt_cfg.get("run_timeout", 15))
    max_findings = int(pbt_cfg.get("max_findings", 50))
    enable_llm = bool(pbt_cfg.get("enable_llm", False))
    call_llm_func = call_llm if enable_llm else None
    logger.info(
        "[PBT] stage: iterations=%d compile_timeout=%d run_timeout=%d max=%d llm=%s",
        pbt_iterations,
        compile_timeout,
        run_timeout,
        max_findings,
        enable_llm,
    )
    annotated = run_pbt_on_findings(
        findings,
        snippet_db,
        pbt_iterations=pbt_iterations,
        compile_timeout=compile_timeout,
        run_timeout=run_timeout,
        model=model,
        auth=auth,
        cache=cache,
        call_llm_func=call_llm_func,
        enable_llm=enable_llm,
        max_findings=max_findings,
    )
    logger.info("[PBT] annotated %d finding(s)", len(annotated))
    return annotated


def _run_fuzz_orchestrator_stage(
    findings: list[dict],
    snippet_db: dict[str, dict],
    cfg: dict,
    output_dir: Path,
    *,
    chains: list[dict],
    mode: str,
) -> list[dict]:
    fuzz_cfg = cfg.get("fuzz_orchestrator", {})
    enabled = bool(cfg.get("enable_fuzz_orchestrator", False))
    benchmark_only = bool(fuzz_cfg.get("benchmark_only", True))
    if not enabled:
        return []
    if benchmark_only and mode != "benchmark":
        return []
    artifacts = orchestrate_fuzz_targets(
        findings,
        snippet_db,
        chains=chains,
        execute=bool(fuzz_cfg.get("execute", False)),
        use_valgrind=bool(fuzz_cfg.get("use_valgrind", False)),
        timeout_seconds=int(fuzz_cfg.get("timeout_seconds", 10)),
        max_targets=int(fuzz_cfg.get("max_targets", 25)),
        high_confidence_threshold=float(
            fuzz_cfg.get("high_confidence_threshold", 0.75)
        ),
        max_chain_targets=int(fuzz_cfg.get("max_chain_targets", 10)),
    )
    _persist_jsonl(output_dir / "fuzz_artifacts.jsonl", artifacts)
    return artifacts


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
        return load_packs_json(packs_pkl)
    packs = build_context_packs(
        snippets,
        recon_tasks=recon_tasks,
        allow_full_db_fallback=allow_full_db_fallback,
        budget_tokens=budget_tokens,
    )
    save_packs_json(packs, packs_pkl)
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


def _run_patch_stage(
    findings: list[dict],
    snippet_db: dict,
    output_dir: Path,
    run_patch_enabled: bool,
) -> list[dict]:
    """Generate patch candidates for confirmed findings (PATCH stage).

    Skipped when *run_patch_enabled* is False (default).  When enabled,
    delegates to :func:`build_patch_candidates` and persists the results
    to ``output/patch_candidates.jsonl``.

    Returns the list of patch candidate dicts (empty when disabled).
    """
    if not run_patch_enabled:
        return []
    candidates = build_patch_candidates(findings, snippet_db)
    _persist_jsonl(output_dir / "patch_candidates.jsonl", candidates)
    logger.info("[PATCH] generated %d patch candidate(s)", len(candidates))
    return candidates


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


def _apply_runtime_flags(
    cfg: dict,
    *,
    enable_fuzz_orchestrator: bool | None,
    enable_pbt: bool | None,
    pbt_enable_llm: bool | None = None,
    enable_exploit_synthesis: bool | None = None,
    enable_z3_validate: bool | None = None,
    z3_timeout_ms: int | None = None,
) -> dict:
    if enable_fuzz_orchestrator is not None:
        cfg["enable_fuzz_orchestrator"] = bool(enable_fuzz_orchestrator)
        if enable_fuzz_orchestrator:
            cfg["enable_localization_stage"] = True
        if enable_fuzz_orchestrator and isinstance(cfg.get("fuzz_orchestrator"), dict):
            cfg["fuzz_orchestrator"]["benchmark_only"] = False
    if enable_pbt is not None:
        cfg["enable_pbt"] = bool(enable_pbt)
        if enable_pbt:
            cfg["enable_localization_stage"] = True
    if pbt_enable_llm is not None:
        pbt_cfg = cfg.setdefault("pbt", {})
        if isinstance(pbt_cfg, dict):
            pbt_cfg["enable_llm"] = bool(pbt_enable_llm)
    if enable_exploit_synthesis is not None:
        cfg["enable_exploit_synthesis"] = bool(enable_exploit_synthesis)
    if enable_z3_validate is not None:
        validate_cfg = cfg.setdefault("validate", {})
        if isinstance(validate_cfg, dict):
            validate_cfg["enable_z3_verifier"] = bool(enable_z3_validate)
    if z3_timeout_ms is not None:
        validate_cfg = cfg.setdefault("validate", {})
        if isinstance(validate_cfg, dict):
            validate_cfg["z3_timeout_ms"] = max(1, int(z3_timeout_ms))
    return cfg


def _build_stage_poc_index(pocs: list[dict]) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for poc in pocs or []:
        if not isinstance(poc, dict):
            continue
        fid = str(
            poc.get("finding_id") or (poc.get("finding") or {}).get("snippet_id") or ""
        )
        sid = str(
            poc.get("snippet_id") or (poc.get("finding") or {}).get("snippet_id") or ""
        )
        if fid:
            index[fid] = poc
        if sid and sid not in index:
            index[sid] = poc
    return index


def _log_readiness_issues(findings: list[dict], pocs: list[dict]) -> None:
    poc_index = _build_stage_poc_index(pocs)
    not_ready = 0
    for finding in findings:
        fid = str(finding.get("id") or finding.get("finding_id") or "")
        sid = str(finding.get("snippet_id") or "")
        poc = poc_index.get(fid) or poc_index.get(sid)
        readiness = check_poc_synthesis_readiness(finding, poc)
        if not readiness["ready"]:
            not_ready += 1
        if readiness["issues"]:
            logger.debug(
                "[exploit-synthesis] readiness issues for finding %s: %s",
                fid or sid,
                "; ".join(readiness["issues"]),
            )
    if not_ready:
        logger.info(
            "[exploit-synthesis] %d/%d finding(s) have limited synthesis readiness "
            "(check debug logs for details)",
            not_ready,
            len(findings),
        )


def _run_exploit_synthesis_stage(
    findings: list[dict],
    snippet_db: dict,
    pocs: list[dict],
    output_dir: Path,
    cfg: dict,
    *,
    auth: dict | None = None,
    cache: JsonCache | None = None,
) -> list[dict]:
    """Run the exploit synthesis stage (T4→T1 tier assessment).

    Disabled by default; enabled via ``--enable-exploit-synthesis`` or
    ``cfg["enable_exploit_synthesis"] = True``.  When enabled, processes
    PoC-confirmed findings and annotates them with tier-graded exploitability
    depth records.

    Parameters
    ----------
    findings:
        Findings list (SHIELD / SUPPRESSIONS output).
    snippet_db:
        Snippet lookup dict.
    pocs:
        PoC result list from the POC stage.
    output_dir:
        Directory for writing ``exploit_synthesis.jsonl``.
    cfg:
        Pipeline configuration dict.
    auth:
        Auth dict for optional LLM enrichment.
    cache:
        JsonCache for LLM response caching.

    Returns
    -------
    list[dict]
        Exploit synthesis records (empty when stage is disabled).

    """
    if not bool(cfg.get("enable_exploit_synthesis", False)):
        return []

    synth_cfg = cfg.get("exploit_synthesis", {})
    enable_llm = bool(synth_cfg.get("enable_llm", False))
    model = str(synth_cfg.get("model", ""))
    max_findings = int(synth_cfg.get("max_findings", 50))

    call_llm_func = call_llm if enable_llm else None

    logger.info(
        "[exploit-synthesis] stage: max_findings=%d llm=%s",
        max_findings,
        enable_llm,
    )

    _log_readiness_issues(findings, pocs)

    records = run_exploit_synthesis(
        findings,
        snippet_db=snippet_db,
        pocs=pocs,
        enable_llm=enable_llm,
        call_llm_func=call_llm_func,
        model=model,
        auth=auth,
        cache=cache,
        max_findings=max_findings,
    )

    _persist_jsonl(output_dir / "exploit_synthesis.jsonl", records)
    logger.info("[exploit-synthesis] generated %d record(s)", len(records))
    return records


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
    from .stages.runtime import _MODEL_BY_DOMAIN

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
    enable_z3_verifier: bool = False,
    z3_timeout_ms: int = 50,
) -> dict:
    finding = standardize_finding(finding)
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
        result = {**finding, "validate_status": status, "validate_reason": reason}
        result = _apply_validate_z3_verdict(
            result,
            snippet,
            enable_z3_verifier=enable_z3_verifier,
            z3_timeout_ms=z3_timeout_ms,
        )
        return _enforce_localization_evidence(result)
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
    enable_z3_verifier: bool = False,
    z3_timeout_ms: int = 50,
) -> dict:
    finding = standardize_finding(finding)
    if is_api_by_design(finding, snippet):
        return {
            **finding,
            "validate_status": "rejected",
            "validate_reason": "api_by_design",
        }
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
        result = {**finding, "validate_status": status, "validate_reason": reason}
        result = _apply_validate_z3_verdict(
            result,
            snippet,
            enable_z3_verifier=enable_z3_verifier,
            z3_timeout_ms=z3_timeout_ms,
        )
        return _enforce_localization_evidence(result)
    except Exception as e:
        return {
            **finding,
            "validate_status": "needs-more-info",
            "validate_reason": f"validate exception: {e}",
        }


def _is_high_priority_validate_finding(finding: dict) -> bool:
    if bool(finding.get("high_priority_validate")):
        return True
    confidence = float(finding.get("localization_confidence", 0.0))
    if confidence >= 0.75:
        return True
    points = finding.get("suspicious_points")
    if not isinstance(points, list) or not points:
        return False
    sink = str(points[0].get("sink_source_type", "")).lower()
    return sink in {
        "memory-corruption",
        "buffer-overflow",
        "use-after-free",
        "format-string",
        "command-injection",
        "path-traversal",
    }


def _sort_for_validation(findings: list[dict]) -> list[dict]:
    return sorted(
        findings,
        key=lambda finding: (
            0 if _is_high_priority_validate_finding(finding) else 1,
            -float(finding.get("localization_confidence", 0.0)),
        ),
    )


def _enforce_localization_evidence(finding: dict) -> dict:
    """Require stronger evidence before low-confidence findings can be confirmed."""
    if not bool(finding.get("localization_enforced")):
        return finding
    status = str(finding.get("validate_status", "needs-more-info")).lower()
    confidence = float(finding.get("localization_confidence", 0.0))
    runtime = finding.get("validate_runtime")
    observed = False
    if isinstance(runtime, dict):
        observed = bool(runtime.get("vulnerability_observed"))
    if status == "confirmed" and confidence < 0.5 and not observed:
        reason = str(finding.get("validate_reason", "")).strip()
        prefix = "downgraded_low_localization_confidence_without_runtime_signal"
        finding = {
            **finding,
            "validate_status": "needs-more-info",
            "validate_reason": f"{prefix}: {reason}" if reason else prefix,
        }
    return finding


def _apply_validate_z3_verdict(
    finding: dict,
    snippet: dict,
    *,
    enable_z3_verifier: bool,
    z3_timeout_ms: int,
) -> dict:
    if not enable_z3_verifier:
        return finding
    verdict, reason = verify_validate_feasibility(
        finding,
        snippet,
        timeout_ms=z3_timeout_ms,
    )
    out = {
        **finding,
        "z3_validate_status": verdict,
        "z3_validate_reason": reason,
    }
    if verdict == "unsat":
        previous_reason = str(out.get("validate_reason", "")).strip()
        out["validate_status"] = "rejected"
        out["validate_reason"] = (
            f"z3_unsat:{reason}; {previous_reason}"
            if previous_reason
            else f"z3_unsat:{reason}"
        )
    return out


def _run_validate_findings(
    findings: list[dict],
    snippet_db: dict[str, dict],
    models: list[str],
    *,
    auth: dict[str, str],
    cache: JsonCache,
    parallel: int = 3,
    model_pool: ModelPool | None = None,
    enable_z3_verifier: bool = False,
    z3_timeout_ms: int = 50,
) -> list[dict]:
    if not findings:
        return []
    findings = _sort_for_validation(findings)

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
                        enable_z3_verifier=enable_z3_verifier,
                        z3_timeout_ms=z3_timeout_ms,
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
                        enable_z3_verifier=enable_z3_verifier,
                        z3_timeout_ms=z3_timeout_ms,
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


_BENCHMARK_METRICS = [
    "precision_at_top_n",
    "reject_rate",
    "duplicate_rate",
    "gap_closure_rate",
    "reproducible_confirmation_rate",
    "fuzz_target_compile_success_rate",
    "sanitizer_confirmed_rate",
    "triage_false_positive_drop",
    "runtime_per_confirmed_finding_seconds",
    "cost_per_confirmed_finding_usd",
]

_BENCHMARK_HIGHER_IS_BETTER = {
    "precision_at_top_n",
    "gap_closure_rate",
    "reproducible_confirmation_rate",
    "fuzz_target_compile_success_rate",
    "sanitizer_confirmed_rate",
    "triage_false_positive_drop",
}

_BENCHMARK_DEFAULT_THRESHOLDS = {
    "precision_at_top_n": 0.03,
    "reject_rate": 0.03,
    "duplicate_rate": 0.02,
    "gap_closure_rate": 0.05,
    "reproducible_confirmation_rate": 0.03,
    "fuzz_target_compile_success_rate": 0.05,
    "sanitizer_confirmed_rate": 0.03,
    "triage_false_positive_drop": 0.03,
    "runtime_per_confirmed_finding_seconds": 20.0,
    "cost_per_confirmed_finding_usd": 0.2,
}

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}


def _safe_ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return float(numerator) / float(denominator)


def _average(values: list[float]) -> float:
    if not values:
        return 0.0
    return sum(values) / len(values)


def _kpi_precision_top_n(findings: list[dict], top_n: int) -> float:
    ranked = sorted(
        findings,
        key=lambda item: _SEVERITY_RANK.get(
            str(item.get("severity", "LOW")).upper(),
            0,
        ),
        reverse=True,
    )
    top = ranked[: max(top_n, 1)]
    top_confirmed = sum(
        1
        for finding in top
        if str(
            finding.get("status", finding.get("validate_status", "")),
        ).lower()
        == "confirmed"
    )
    return _safe_ratio(top_confirmed, len(top))


def _kpi_duplicate_rate(findings: list[dict]) -> float:
    dedup_keys = set()
    for finding in findings:
        lines = finding.get("lines") or []
        line_start = int(lines[0]) if lines else 0
        dedup_keys.add(
            (
                str(finding.get("file") or finding.get("snippet_id") or ""),
                str(finding.get("class") or ""),
                line_start,
            ),
        )
    return 1.0 - _safe_ratio(len(dedup_keys), len(findings))


def _kpi_gap_closure(report: dict) -> float:
    gaps = report.get("gaps") or []
    if not gaps:
        return 1.0
    closed_gaps = 0
    for gap in gaps:
        if gap.get("closed") is True:
            closed_gaps += 1
            continue
        status = str(gap.get("status", "")).lower()
        if status in {"closed", "resolved", "covered", "fixed"}:
            closed_gaps += 1
    return _safe_ratio(closed_gaps, len(gaps))


def _kpi_fuzz_metrics(report: dict) -> dict:
    fuzz_artifacts = report.get("fuzz_artifacts") or []
    compile_successes = 0
    sanitizer_hits = 0
    reproduced = 0
    for artifact in fuzz_artifacts:
        if not isinstance(artifact, dict):
            continue
        payload = artifact.get("artifact")
        if not isinstance(payload, dict):
            continue
        if bool(payload.get("compile_succeeded")):
            compile_successes += 1
        if str(payload.get("sanitizer_signal", "")).strip():
            sanitizer_hits += 1
        if bool(payload.get("reproduced")):
            reproduced += 1
    fuzz_count = len([entry for entry in fuzz_artifacts if isinstance(entry, dict)])
    return {
        "fuzz_count": fuzz_count,
        "compile_successes": compile_successes,
        "sanitizer_hits": sanitizer_hits,
        "reproduced": reproduced,
    }


def _extract_report_kpis(
    report: dict, top_n: int, elapsed_seconds: float, cost_usd: float
) -> dict:
    findings = report.get("findings") or []
    summary = report.get("summary") or {}
    total_findings = len(findings)
    total_bucketed = (
        int(summary.get("fix_now", 0))
        + int(summary.get("backlog", 0))
        + int(summary.get("false_positive", 0))
    )
    rejected = int(summary.get("false_positive", 0))

    precision_at_top_n = _kpi_precision_top_n(findings, top_n)
    duplicate_rate = _kpi_duplicate_rate(findings)
    gap_closure_rate = _kpi_gap_closure(report)
    fuzz = _kpi_fuzz_metrics(report)

    confirmed_findings = sum(
        1
        for finding in findings
        if str(
            finding.get("status", finding.get("validate_status", "")),
        ).lower()
        == "confirmed"
    )

    return {
        "precision_at_top_n": precision_at_top_n,
        "reject_rate": _safe_ratio(rejected, total_bucketed),
        "duplicate_rate": duplicate_rate,
        "gap_closure_rate": gap_closure_rate,
        "reproducible_confirmation_rate": _safe_ratio(
            fuzz["reproduced"], fuzz["fuzz_count"]
        ),
        "fuzz_target_compile_success_rate": _safe_ratio(
            fuzz["compile_successes"], fuzz["fuzz_count"]
        ),
        "sanitizer_confirmed_rate": _safe_ratio(
            fuzz["sanitizer_hits"], fuzz["fuzz_count"]
        ),
        "triage_false_positive_drop": 1.0 - _safe_ratio(rejected, total_bucketed),
        "runtime_per_confirmed_finding_seconds": (
            0.0 if confirmed_findings == 0 else elapsed_seconds / confirmed_findings
        ),
        "cost_per_confirmed_finding_usd": (
            0.0 if confirmed_findings == 0 else cost_usd / confirmed_findings
        ),
        "confirmed_findings": confirmed_findings,
        "total_findings": total_findings,
        "runtime_seconds": elapsed_seconds,
        "cost_usd": cost_usd,
    }


def _load_json_dict(path: Path, fallback: dict) -> dict:
    if not path.exists():
        return fallback
    try:
        data = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return fallback
    return data if isinstance(data, dict) else fallback


def _resolve_benchmark_targets(
    corpus_path: Path, repo: Path, profile: str
) -> list[dict]:
    corpus = _load_json_dict(corpus_path, {"targets": []})
    targets = corpus.get("targets")
    if not isinstance(targets, list) or not targets:
        return [{"name": "default", "repo": str(repo), "profile": profile}]

    resolved: list[dict] = []
    for idx, target in enumerate(targets):
        if not isinstance(target, dict):
            continue
        raw_repo = str(target.get("repo", "")).strip()
        if not raw_repo:
            continue
        repo_path = Path(raw_repo)
        if not repo_path.is_absolute():
            repo_path = (corpus_path.parent / repo_path).resolve()
        resolved.append(
            {
                "name": str(target.get("name", f"target-{idx + 1}")),
                "repo": str(repo_path),
                "profile": str(target.get("profile", profile)),
            },
        )
    return resolved or [{"name": "default", "repo": str(repo), "profile": profile}]


def _load_thresholds(path: Path, profile: str) -> dict:
    thresholds_doc = _load_json_dict(path, {"defaults": {}, "profiles": {}})
    defaults = thresholds_doc.get("defaults")
    if not isinstance(defaults, dict):
        defaults = {}
    profiles = thresholds_doc.get("profiles")
    if not isinstance(profiles, dict):
        profiles = {}
    profile_overrides = profiles.get(profile)
    if not isinstance(profile_overrides, dict):
        profile_overrides = {}

    out: dict[str, float] = {}
    for metric in _BENCHMARK_METRICS:
        value = profile_overrides.get(metric, defaults.get(metric))
        if value is None:
            value = _BENCHMARK_DEFAULT_THRESHOLDS[metric]
        with contextlib.suppress(TypeError, ValueError):
            out[metric] = float(value)
    for metric in _BENCHMARK_METRICS:
        out.setdefault(metric, _BENCHMARK_DEFAULT_THRESHOLDS[metric])
    return out


def _build_benchmark_summary(
    profile_comparisons: list[dict],
    missing_baselines: list[str],
    gate_passed: bool,
    baseline_updated: bool,
) -> str:
    lines = [
        "# Benchmark Regression Gate",
        "",
        f"- Gate result: {'PASS' if gate_passed else 'FAIL'}",
        f"- Baseline updated: {'yes' if baseline_updated else 'no'}",
    ]
    if missing_baselines:
        lines.append(f"- Missing baselines: {', '.join(sorted(missing_baselines))}")
    lines.append("")
    for profile_result in profile_comparisons:
        profile = profile_result.get("profile", "unknown")
        lines.append(f"## Profile: {profile}")
        for metric in profile_result.get("metrics", []):
            status = metric.get("status", "within-threshold")
            lines.append(
                (
                    f"- {metric.get('name')}: current={metric.get('current'):.6f}, "
                    f"baseline={metric.get('baseline'):.6f}, "
                    f"delta={metric.get('delta'):+.6f}, "
                    f"allowed={metric.get('allowed_regression'):.6f} [{status}]"
                ),
            )
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def _update_baseline_if_requested(
    *,
    update_benchmark_baseline: bool,
    baseline_profiles: dict,
    profile_current: dict[str, dict],
    baseline_doc: dict,
    baseline_path: Path,
    missing_baselines: list[str],
) -> tuple[bool, list[str]]:
    if not update_benchmark_baseline:
        return False, missing_baselines
    baseline_profiles.update(profile_current)
    baseline_doc["profiles"] = baseline_profiles
    baseline_doc["updated_at"] = datetime.now(UTC).isoformat()
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(json.dumps(baseline_doc, indent=2) + "\n")
    return True, []


def _run_benchmark_targets(
    targets: list[dict],
    run_kwargs: dict,
    pkg_dir: Path,
    benchmark_top_n: int,
    benchmark_profile: str,
) -> tuple[dict[str, list[dict]], dict[str, dict]]:
    profile_runs: dict[str, list[dict]] = {}
    for target in targets:
        target_repo = Path(target["repo"])
        target_profile = str(target.get("profile", benchmark_profile))
        started = time.time()
        report = run("full", target_repo, **run_kwargs)
        elapsed_seconds = time.time() - started
        cfg = json.loads((pkg_dir / "config/defaults.json").read_text())
        run_id = f"full:{target_repo!s}"
        run_cost = 0.0
        state = StateDB(Path.cwd() / cfg["state_db"])
        try:
            run_cost = state.total_cost(run_id)
        finally:
            state.close()
        kpis = _extract_report_kpis(
            report,
            top_n=benchmark_top_n,
            elapsed_seconds=elapsed_seconds,
            cost_usd=run_cost,
        )
        profile_runs.setdefault(target_profile, []).append(
            {
                "target": target["name"],
                "repo": str(target_repo),
                "kpis": kpis,
            }
        )
    profile_current: dict[str, dict] = {}
    for profile_name, runs in profile_runs.items():
        profile_current[profile_name] = {
            metric: _average([float(r["kpis"][metric]) for r in runs])
            for metric in _BENCHMARK_METRICS
        }
    return profile_runs, profile_current


def _compare_profile_to_baseline(
    profile_name: str,
    current_kpis: dict,
    baseline_profiles: dict,
    thresholds_path: Path,
) -> tuple[dict | None, dict | None, str | None]:
    baseline_kpis = baseline_profiles.get(profile_name)
    if not isinstance(baseline_kpis, dict):
        return None, None, profile_name

    thresholds = _load_thresholds(thresholds_path, profile_name)
    metric_results: list[dict] = []
    profile_regressed = False
    for metric in _BENCHMARK_METRICS:
        current_value = float(current_kpis.get(metric, 0.0))
        baseline_value = float(baseline_kpis.get(metric, 0.0))
        delta = current_value - baseline_value
        allowed = float(thresholds.get(metric, _BENCHMARK_DEFAULT_THRESHOLDS[metric]))
        higher_is_better = metric in _BENCHMARK_HIGHER_IS_BETTER
        if higher_is_better:
            regressed = delta < (-allowed)
        else:
            regressed = delta > allowed
        if regressed:
            status = "regressed"
            profile_regressed = True
        elif abs(delta) <= allowed:
            status = "within-threshold"
        else:
            status = "improved"
        metric_results.append(
            {
                "name": metric,
                "current": current_value,
                "baseline": baseline_value,
                "delta": delta,
                "allowed_regression": allowed,
                "status": status,
                "direction": "higher_is_better"
                if higher_is_better
                else "lower_is_better",
            }
        )
    comparison = {"profile": profile_name, "metrics": metric_results}
    return comparison, thresholds, profile_name if profile_regressed else None


def run_benchmark_gate(
    repo: Path,
    *,
    benchmark_corpus: Path | None = None,
    benchmark_baseline: Path | None = None,
    benchmark_thresholds: Path | None = None,
    benchmark_output: Path | None = None,
    benchmark_profile: str = "library",
    benchmark_top_n: int = 10,
    update_benchmark_baseline: bool = False,
    **run_kwargs: object,
) -> dict:
    pkg_dir = Path(__file__).parent
    corpus_path = benchmark_corpus or (pkg_dir / "config/benchmark_corpus.json")
    baseline_path = benchmark_baseline or (pkg_dir / "config/benchmark_baselines.json")
    thresholds_path = benchmark_thresholds or (
        pkg_dir / "config/benchmark_thresholds.json"
    )
    output_path = benchmark_output or (
        Path.cwd() / "output/benchmark_regression_report.json"
    )

    targets = _resolve_benchmark_targets(corpus_path, repo, benchmark_profile)
    baseline_doc = _load_json_dict(baseline_path, {"profiles": {}})
    baseline_profiles = baseline_doc.get("profiles")
    if not isinstance(baseline_profiles, dict):
        baseline_profiles = {}

    profile_runs, profile_current = _run_benchmark_targets(
        targets,
        run_kwargs,
        pkg_dir,
        benchmark_top_n,
        benchmark_profile,
    )

    missing_baselines: list[str] = []
    profile_comparisons: list[dict] = []
    regressed_profiles: list[str] = []
    thresholds_used: dict[str, dict] = {}

    for profile_name, current_kpis in profile_current.items():
        comparison, thresholds, regressed = _compare_profile_to_baseline(
            profile_name,
            current_kpis,
            baseline_profiles,
            thresholds_path,
        )
        if comparison is None:
            missing_baselines.append(profile_name)
            continue
        if thresholds is not None:
            thresholds_used[profile_name] = thresholds
        if regressed is not None:
            regressed_profiles.append(regressed)
        profile_comparisons.append(comparison)

    baseline_updated, missing_baselines = _update_baseline_if_requested(
        update_benchmark_baseline=update_benchmark_baseline,
        baseline_profiles=baseline_profiles,
        profile_current=profile_current,
        baseline_doc=baseline_doc,
        baseline_path=baseline_path,
        missing_baselines=missing_baselines,
    )
    gate_passed = bool(not missing_baselines and not regressed_profiles)
    summary_text = _build_benchmark_summary(
        profile_comparisons=profile_comparisons,
        missing_baselines=missing_baselines,
        gate_passed=gate_passed,
        baseline_updated=baseline_updated,
    )

    artifact = {
        "generated_at": datetime.now(UTC).isoformat(),
        "gate_passed": gate_passed,
        "baseline_updated": baseline_updated,
        "missing_baselines": missing_baselines,
        "regressed_profiles": regressed_profiles,
        "corpus_path": str(corpus_path),
        "baseline_path": str(baseline_path),
        "thresholds_path": str(thresholds_path),
        "top_n": benchmark_top_n,
        "targets": targets,
        "profile_runs": profile_runs,
        "profile_current": profile_current,
        "profile_comparisons": profile_comparisons,
        "thresholds_used": thresholds_used,
        "summary_markdown": summary_text,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(artifact, indent=2))
    logger.info("benchmark regression artifact written to %s", output_path)

    if not gate_passed:
        msg = (
            "Benchmark regression gate failed. "
            f"Missing baselines={missing_baselines}, regressed_profiles={regressed_profiles}. "
            "Use --update-benchmark-baseline to intentionally refresh baselines."
        )
        raise RuntimeError(msg)
    return artifact


def run(  # noqa: PLR0913
    mode: str,
    repo: Path,
    *,
    auth_path: Path | None = None,
    output_dir: Path | None = None,
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
    run_patch_enabled: bool = False,
    refresh_models: bool = False,
    budget_ratio: float = 0.85,
    pooled: bool = False,
    load_packs_cache: bool = False,
    enable_fuzz_orchestrator: bool | None = None,
    enable_pbt: bool | None = None,
    pbt_enable_llm: bool | None = None,
    enable_exploit_synthesis: bool | None = None,
    enable_z3_validate: bool | None = None,
    z3_timeout_ms: int | None = None,
    cve_corpus: Path | None = None,
    no_fetch_cves: bool = False,
    no_scan_git_cves: bool = False,
) -> dict:
    pkg_dir = Path(__file__).parent
    work_dir = Path.cwd()
    cfg = json.loads((pkg_dir / "config/defaults.json").read_text())
    cfg = _apply_runtime_flags(
        cfg,
        enable_fuzz_orchestrator=enable_fuzz_orchestrator,
        enable_pbt=enable_pbt,
        pbt_enable_llm=pbt_enable_llm,
        enable_exploit_synthesis=enable_exploit_synthesis,
        enable_z3_validate=enable_z3_validate,
        z3_timeout_ms=z3_timeout_ms,
    )
    stages_cfg = _load_stages_config(pkg_dir)
    state = StateDB(work_dir / cfg["state_db"])
    cache = JsonCache(work_dir / cfg["cache_file"])

    run_id = f"{mode}:{repo!s}"
    state.create_run(repo_path=str(repo), run_id=run_id)
    _enforce_cost_limit(state, run_id, max_cost_usd)

    auth = load_auth_config(explicit_path=auth_path, script_dir=pkg_dir)
    state.put_meta("auth_providers", json.dumps(sorted(auth.keys())))

    global_max = max_concurrency or cfg.get("max_workers", 3)
    hunt_workers = _stage_workers(stages_cfg, "hunt", global_max)
    validate_workers = _stage_workers(stages_cfg, "validate", global_max)
    output_dir = output_dir if output_dir else work_dir / "output"
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
    _clear_model_limits_cache(pkg_dir, refresh_models)
    model_limits = fetch_model_limits(model_chain, pkg_dir)
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

    _inject_cve_entries(
        packs, repo, snippets, cache, cve_corpus, no_fetch_cves, no_scan_git_cves
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
    all_findings, localization_unreachable = _run_localization_stage(
        all_findings,
        snippet_db,
        cfg,
        output_dir,
    )
    state.put_meta("localization_unreachable_count", str(len(localization_unreachable)))

    pbt_enabled = bool(cfg.get("enable_pbt", False))
    if pbt_enabled:
        all_findings = _run_pbt_stage(
            all_findings,
            snippet_db,
            cfg,
            auth=auth,
            cache=cache,
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
        cfg,
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
        work_dir / cfg.get("suppressions_file", "output/suppressions.json"),
    )
    findings, registry_suppressed = registry.filter(promoted)
    state.put_meta("registry_suppressed", str(len(registry_suppressed)))

    chains = synthesize_exploit_chains(findings, snippets)
    fuzz_artifacts = _run_fuzz_orchestrator_stage(
        findings,
        snippet_db,
        cfg,
        output_dir,
        chains=chains,
        mode=mode,
    )
    pocs = _run_poc_stage(
        findings,
        snippet_db,
        output_dir,
        run_poc_enabled,
        poc_finding_id,
    )
    exploit_synthesis_records = _run_exploit_synthesis_stage(
        findings,
        snippet_db,
        pocs,
        output_dir,
        cfg,
        auth=auth,
        cache=cache,
    )
    patch_candidates = _run_patch_stage(
        findings,
        snippet_db,
        output_dir,
        run_patch_enabled,
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

    report = _assemble_report(
        repo=str(repo),
        findings=findings,
        chains=chains,
        gapfill_tasks=gapfill_tasks,
        trace_required=cfg["is_library_target"],
        exposure_metrics=exposure_metrics,
        pocs=pocs,
        patch_candidates=patch_candidates,
        fuzz_artifacts=fuzz_artifacts,
        exploit_synthesis_records=exploit_synthesis_records,
    )

    state.put_meta("last_mode", mode)
    state.finish_run(run_id)
    cache.put("last_report", report)
    return report


def _enforce_cost_limit(
    state: StateDB, run_id: str, max_cost_usd: float | None
) -> None:
    if max_cost_usd is None:
        return
    spent = state.total_cost(run_id)
    if spent >= max_cost_usd:
        state.finish_run(run_id, "cost_limit")
        msg = f"Cost limit ${max_cost_usd:.2f} reached (${spent:.2f} already spent)"
        raise RuntimeError(msg)


def _clear_model_limits_cache(pkg_dir: Path, refresh_models: bool) -> None:
    if not refresh_models:
        return
    p = pkg_dir / "config/model_limits.json"
    if p.exists():
        p.unlink()


def _inject_cve_entries(
    packs: list[dict],
    repo: Path,
    snippets: list[dict],
    cache: JsonCache,
    cve_corpus: Path | None,
    no_fetch_cves: bool,
    no_scan_git_cves: bool = False,
) -> None:
    from .stages.cve_corpus import filter_cves_by_domain
    from .stages.cve_fetcher import build_cve_corpus

    cve_entries = build_cve_corpus(
        repo,
        snippets,
        cache=cache,
        user_corpus_path=cve_corpus,
        no_fetch=no_fetch_cves,
        no_scan_git=no_scan_git_cves,
    )
    if not cve_entries:
        return
    for pack in packs:
        domain = pack.get("agent", "")
        relevant = filter_cves_by_domain(cve_entries, domain)
        if relevant:
            pack["known_entries"] = relevant
    logger.info("injected %d CVE entries across %d packs", len(cve_entries), len(packs))


def _assemble_report(
    *,
    repo: str,
    findings: list[dict],
    chains: list[dict],
    gapfill_tasks: list[dict],
    trace_required: bool,
    exposure_metrics: list[dict],
    pocs: list[dict],
    patch_candidates: list[dict],
    fuzz_artifacts: list[dict],
    exploit_synthesis_records: list[dict] | None = None,
) -> dict:
    report = build_report(
        repo=repo,
        findings=findings,
        chains=chains,
        gaps=[
            {"domain": t["domain"], "files": t["target_files"]} for t in gapfill_tasks
        ],
        trace_required=trace_required,
        exposure_metrics=exposure_metrics,
    )
    if pocs:
        report["pocs"] = pocs
    if patch_candidates:
        report["patch_candidates"] = patch_candidates
    if fuzz_artifacts:
        report["fuzz_artifacts"] = fuzz_artifacts
    if exploit_synthesis_records:
        report["exploit_synthesis"] = exploit_synthesis_records
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


def run_all(  # noqa: PLR0913
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
    run_patch_enabled: bool = False,
    refresh_models: bool = False,
    budget_ratio: float = 0.85,
    pooled: bool = False,
    load_packs_cache: bool = False,
    enable_fuzz_orchestrator: bool | None = None,
    enable_pbt: bool | None = None,
    pbt_enable_llm: bool | None = None,
    enable_exploit_synthesis: bool | None = None,
    enable_z3_validate: bool | None = None,
    z3_timeout_ms: int | None = None,
    cve_corpus: Path | None = None,
    no_fetch_cves: bool = False,
    no_scan_git_cves: bool = False,
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
            run_patch_enabled=run_patch_enabled,
            refresh_models=refresh_models,
            budget_ratio=budget_ratio,
            pooled=pooled,
            load_packs_cache=load_packs_cache,
            enable_fuzz_orchestrator=enable_fuzz_orchestrator,
            enable_pbt=enable_pbt,
            pbt_enable_llm=pbt_enable_llm,
            enable_exploit_synthesis=enable_exploit_synthesis,
            enable_z3_validate=enable_z3_validate,
            z3_timeout_ms=z3_timeout_ms,
            cve_corpus=cve_corpus,
            no_fetch_cves=no_fetch_cves,
            no_scan_git_cves=no_scan_git_cves,
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
    if mode not in ("full", "max-run", "all", "benchmark"):
        return
    if auth_json:
        return
    pkg_dir = Path(__file__).parent
    if (pkg_dir / "auth.json").exists():
        return
    if (Path.home() / ".local/share/opencode/auth.json").exists():
        return
    logger.warning(
        "No auth.json found; running with empty model pools (will produce 0 findings)",
    )


def _run_health_check(model_override: list[str] | None, auth_json: Path | None) -> None:
    from .stages.runtime import (
        JsonCache,
        fetch_model_limits,
        health_check_models,
        load_auth_config,
    )

    pkg_dir = Path(__file__).parent
    auth = load_auth_config(explicit_path=auth_json, script_dir=pkg_dir)
    cache = JsonCache(Path.cwd() / "output/cache.json")
    model_chain = model_override or []
    model_limits = fetch_model_limits(model_chain, pkg_dir)
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
        "run_patch_enabled": args.run_patch,
        "refresh_models": args.refresh_models,
        "budget_ratio": args.budget_ratio,
        "pooled": args.pooled,
        "load_packs_cache": args.load_packs_cache,
        "enable_fuzz_orchestrator": args.enable_fuzz_orchestrator,
        "enable_pbt": args.enable_pbt,
        "pbt_enable_llm": args.pbt_enable_llm,
        "enable_exploit_synthesis": args.enable_exploit_synthesis,
        "enable_z3_validate": args.enable_z3_validate,
        "z3_timeout_ms": args.z3_timeout_ms,
        "cve_corpus": args.cve_corpus,
        "no_fetch_cves": args.no_fetch_cves,
        "no_scan_git_cves": args.no_scan_git_cves,
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
            "benchmark",
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
    parser.add_argument("--enable-fuzz-orchestrator", action="store_true")
    parser.add_argument("--enable-pbt", action="store_true")
    parser.add_argument("--pbt-enable-llm", action="store_true")
    parser.add_argument(
        "--enable-z3-validate",
        action="store_true",
        help=(
            "Enable optional Z3 feasibility verifier during VALIDATE stage "
            "(pilot; default disabled)."
        ),
    )
    parser.add_argument(
        "--z3-timeout-ms",
        type=int,
        default=50,
        help="Timeout in milliseconds for each Z3 validate check.",
    )
    parser.add_argument(
        "--enable-exploit-synthesis",
        action="store_true",
        help=(
            "Run exploit synthesis stage: assess tier depth (T4→T1) "
            "for PoC-confirmed findings."
        ),
    )
    parser.add_argument(
        "--cve-corpus",
        type=Path,
        default=None,
        help="Path to CVE corpus JSON (known CVEs to exclude as negative examples).",
    )
    parser.add_argument(
        "--no-fetch-cves",
        action="store_true",
        help="Skip auto-fetching CVEs from OSV.dev; only use --cve-corpus if provided.",
    )
    parser.add_argument(
        "--no-scan-git-cves",
        action="store_true",
        help="Skip scanning git history for CVE references in commits and branches.",
    )
    parser.add_argument(
        "--poc",
        type=str,
        nargs="?",
        const="all",
        default=None,
        dest="poc_finding",
    )
    parser.add_argument("--poc-only", action="store_true", dest="poc_only")
    parser.add_argument(
        "--run-patch",
        action="store_true",
        dest="run_patch",
        help="Generate patch candidates for confirmed findings (PATCH stage).",
    )
    parser.add_argument("--log-file", type=Path, default=None)
    parser.add_argument("--benchmark-corpus", type=Path, default=None)
    parser.add_argument("--benchmark-baseline", type=Path, default=None)
    parser.add_argument("--benchmark-thresholds", type=Path, default=None)
    parser.add_argument("--benchmark-output", type=Path, default=None)
    parser.add_argument("--benchmark-profile", type=str, default="library")
    parser.add_argument("--benchmark-top-n", type=int, default=10)
    parser.add_argument("--update-benchmark-baseline", action="store_true")
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
    elif mode == "benchmark":
        run_benchmark_gate(
            Path(args.repo),
            benchmark_corpus=args.benchmark_corpus,
            benchmark_baseline=args.benchmark_baseline,
            benchmark_thresholds=args.benchmark_thresholds,
            benchmark_output=args.benchmark_output,
            benchmark_profile=args.benchmark_profile,
            benchmark_top_n=args.benchmark_top_n,
            update_benchmark_baseline=args.update_benchmark_baseline,
            **kwargs,
        )
    else:
        run(mode, Path(args.repo), **kwargs)


if __name__ == "__main__":
    main()
