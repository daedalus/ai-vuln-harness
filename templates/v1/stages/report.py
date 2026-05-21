from __future__ import annotations

from datetime import datetime, timezone

from .contracts import standardize_finding
from .validate import is_api_by_design, requires_trace_before_fix_now

_SEV_RANK = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFORMATIONAL': 0}
_RANK_SEV = {v: k for k, v in _SEV_RANK.items()}


def _downgrade_severity(sev: str) -> str:
    """Return the next lower severity level."""
    rank = _SEV_RANK.get(str(sev).upper(), 0)
    return _RANK_SEV.get(max(rank - 1, 0), 'INFORMATIONAL')


def bucket_finding(finding: dict, trace_required: bool = True, trace_confirmed: bool = False) -> tuple[str, str]:
    f = standardize_finding(finding)
    sev = str(f.get('severity', 'LOW')).upper()
    status = f.get('status', 'raw')

    if status == 'rejected':
        return 'false_positive', f"Rejected by Validate: {f.get('validate_reason', 'insufficient evidence')}"

    if is_api_by_design(f, {'name': f.get('function_name', ''), 'content': f.get('desc', '')}):
        return 'backlog', 'API-by-design behavior; requires consumer misuse context'

    # Improvement ②: fix_now requires a non-empty, graph-verified call path.
    if sev in {'CRITICAL', 'HIGH'} and status == 'confirmed':
        call_path = f.get('call_path') or []
        if not call_path:
            return 'backlog', (
                'Blocked from fix_now: empty call_path. '
                'A verified call path from a known entry point is required.'
            )
        if not f.get('call_path_verified', True):
            return 'backlog', (
                f"Blocked from fix_now: call_path failed graph verification "
                f"({f.get('call_path_reason', 'unknown reason')}). "
                'Verify the path against the call graph before escalating.'
            )

    # Improvement ⑤: downgrade severity for unconfirmed/needs-more-info findings.
    if not f.get('poc_confirmed') and status in {'needs-more-info', 'raw'}:
        effective_sev = _downgrade_severity(sev)
        if effective_sev != sev:
            sev = effective_sev
            f = {**f, 'severity': sev}

    if trace_required and requires_trace_before_fix_now(True, trace_confirmed):
        if sev in {'CRITICAL', 'HIGH'} and status == 'confirmed':
            return 'backlog', 'Library target requires consumer Trace confirmation before fix_now'

    if sev in {'CRITICAL', 'HIGH'} and status == 'confirmed':
        return 'fix_now', f'Severity {sev} + status {status}. Confirmed reachable vulnerability.'

    return 'backlog', f'Severity {sev}, status {status}. Needs further evidence or is lower priority.'


def _dedup_key(finding: dict) -> tuple[str, str, int]:
    """Improvement ⑥: composite dedup key covering split-continuation snippets.

    Uses (file, class, source_lines_start) so that different snippet IDs for
    the same large function (split on line boundaries) still collapse to one
    record.  Falls back to (snippet_id, class, 0) when line metadata is absent.
    """
    lines = finding.get('lines') or []
    start_line = lines[0] if lines else 0
    file_key = str(finding.get('file') or finding.get('snippet_id') or '')
    return (file_key, str(finding.get('class') or ''), int(start_line))


def deduplicate(findings: list[dict]) -> list[dict]:
    """Deduplicate findings using the composite key (improvement ⑥).

    Keeps the highest-severity variant when collapsing duplicates.
    """
    seen: dict[tuple[str, str, int], dict] = {}
    rank = lambda f: _SEV_RANK.get(str(f.get('severity', '')).upper(), 0)
    for f in findings:
        key = _dedup_key(f)
        if key not in seen or rank(f) > rank(seen[key]):
            seen[key] = f
    return list(seen.values())


def build_report(
    repo: str,
    findings: list[dict],
    chains: list[dict],
    gaps: list[dict],
    trace_required: bool = True,
    exposure_metrics: dict | None = None,
) -> dict:
    deduped = deduplicate(findings)
    bucketed = []
    summary = {'fix_now': 0, 'backlog': 0, 'false_positive': 0, 'chains_feasible': 0}

    for idx, f in enumerate(deduped, start=1):
        bucket, rationale = bucket_finding(f, trace_required=trace_required)
        item = standardize_finding(f)
        item['id'] = f'finding-{idx:04d}'
        item['bucket'] = bucket
        item['bucket_rationale'] = rationale
        summary[bucket] += 1
        bucketed.append(item)

    summary['chains_feasible'] = sum(1 for c in chains if c.get('feasible'))
    if exposure_metrics:
        summary['avg_exposure_window_days'] = float(exposure_metrics.get('avg_exposure_window_days', 0.0))
        summary['median_exposure_window_days'] = float(exposure_metrics.get('median_exposure_window_days', 0.0))
        summary['oldest_open_exposure_days'] = float(exposure_metrics.get('oldest_open_exposure_days', 0.0))

    return {
        'repo': repo,
        'scan_date': datetime.now(timezone.utc).isoformat(),
        'bucket_definitions': {
            'fix_now': 'CRITICAL/HIGH + confirmed + non-empty graph-verified call path + reachable external-input path',
            'backlog': (
                'Needs trace confirmation, lower severity, API-by-design context, '
                'empty/unverified call path, or unconfirmed PoC (severity downgraded)'
            ),
            'false_positive': 'Rejected by Validate or no plausible path',
        },
        'summary': summary,
        'findings': bucketed,
        'chains': chains,
        'gaps': gaps,
        'exposure_window_kpis': exposure_metrics or {},
    }
