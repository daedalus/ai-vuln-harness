"""Gapfill stage — identify under-covered domains and re-queue Hunt tasks.

After the Hunt → Validate loop, some domains may have yielded zero confirmed
findings — either because coverage was thin or because all candidates were
rejected.  Gapfill identifies those gaps and emits new recon tasks so the
next Hunt iteration covers them from a different angle.

This implements the Cloudflare / Project Glasswing Stage 4 (Gapfill), where
the pipeline explicitly checks which attack classes were visited but produced
nothing, then re-queues them before Dedupe so no surface is abandoned after a
single fruitless pass.
"""

from __future__ import annotations


def _covered_domains(findings: list[dict]) -> set[str]:
    """Return the set of domains that have at least one confirmed finding."""
    covered: set[str] = set()
    for f in findings:
        domain = str(f.get("domain") or f.get("class") or f.get("attack_class") or "")
        if domain and str(f.get("status", "")).lower() == "confirmed":
            covered.add(domain)
    return covered


def _hunted_domains(tasks: list[dict]) -> set[str]:
    """Return the set of domains that appeared in previous Hunt tasks."""
    return {str(t.get("domain") or "") for t in tasks if t.get("domain")}


def _domain_files(tasks: list[dict]) -> dict[str, set[str]]:
    """Build a mapping of domain → set of target files from existing tasks."""
    mapping: dict[str, set[str]] = {}
    for t in tasks:
        d = str(t.get("domain") or "")
        if d:
            for f in t.get("target_files") or []:
                mapping.setdefault(d, set()).add(f)
    return mapping


def build_gapfill_tasks(
    existing_tasks: list[dict],
    findings: list[dict],
    *,
    max_tasks: int = 5,
    scope_notes: str | None = None,
) -> list[dict]:
    """Return new Hunt tasks for domains hunted but yielding no confirmed findings.

    Parameters
    ----------
    existing_tasks:
        All Hunt tasks run so far (from Recon + previous Gapfill rounds).
    findings:
        All findings produced so far (any status).
    max_tasks:
        Maximum number of new tasks to emit (default 5).
    scope_notes:
        Optional operator scope notes forwarded into each task's
        ``scope_notes`` field (mirrors evilsocket/audit's ``--scope-notes``
        flag which appends notes verbatim to every stage's user_input).

    Returns
    -------
    list of new task dicts (may be empty when all hunted domains have ≥1
    confirmed finding).

    """
    hunted = _hunted_domains(existing_tasks)
    confirmed = _covered_domains(findings)
    gap_domains = hunted - confirmed

    files_by_domain = _domain_files(existing_tasks)

    new_tasks: list[dict] = []
    for idx, domain in enumerate(sorted(gap_domains)[:max_tasks], start=1):
        files = sorted(files_by_domain.get(domain, set()))
        task: dict = {
            "task_id": f"gapfill_{domain}_{idx}",
            "domain": domain,
            "attack_class": domain,
            "target_files": files,
            "rationale": (
                f"Gapfill: {domain!r} produced zero confirmed findings in the "
                "previous Hunt round; re-scanning from a different angle."
            ),
            "priority": "medium",
            "source": "gapfill",
        }
        if scope_notes:
            task["scope_notes"] = scope_notes
        task["simplicity_note"] = (
            "Prefer the simplest vulnerability class that accounts for the evidence. "
            "If a simpler bug class also explains the pattern, report that instead. "
            "Do not chain more than 3 preconditions into a single finding."
        )
        new_tasks.append(task)

    return new_tasks
