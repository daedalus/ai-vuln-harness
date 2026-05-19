from __future__ import annotations

from .contracts import standardize_finding
from .validate import is_api_by_design, requires_trace_before_fix_now


def bucket_finding(finding: dict, trace_required: bool = True, trace_confirmed: bool = False) -> tuple[str, str]:
    f = standardize_finding(finding)
    sev = str(f.get('severity', 'LOW')).upper()
    status = f.get('status', 'raw')

    if status == 'rejected':
        return 'false_positive', f"Rejected by Validate: {f.get('validate_reason', 'insufficient evidence')}"

    if is_api_by_design(f, {'name': f.get('function_name', ''), 'content': f.get('desc', '')}):
        return 'backlog', 'API-by-design behavior; requires consumer misuse context'

    if trace_required and requires_trace_before_fix_now(True, trace_confirmed):
        if sev in {'CRITICAL', 'HIGH'} and status == 'confirmed':
            return 'backlog', 'Library target requires consumer Trace confirmation before fix_now'

    if sev in {'CRITICAL', 'HIGH'} and status == 'confirmed':
        return 'fix_now', f'Severity {sev} + status {status}. Confirmed reachable vulnerability.'

    return 'backlog', f'Severity {sev}, status {status}. Needs further evidence or is lower priority.'


def build_report(repo: str, findings: list[dict], chains: list[dict], gaps: list[dict], trace_required: bool = True) -> dict:
    bucketed = []
    summary = {'fix_now': 0, 'backlog': 0, 'false_positive': 0, 'chains_feasible': 0}

    for idx, f in enumerate(findings, start=1):
        bucket, rationale = bucket_finding(f, trace_required=trace_required)
        item = standardize_finding(f)
        item['id'] = f'finding-{idx:04d}'
        item['bucket'] = bucket
        item['bucket_rationale'] = rationale
        summary[bucket] += 1
        bucketed.append(item)

    summary['chains_feasible'] = sum(1 for c in chains if c.get('feasible'))

    return {
        'repo': repo,
        'scan_date': '1970-01-01T00:00:00Z',
        'bucket_definitions': {
            'fix_now': 'CRITICAL/HIGH + confirmed + reachable external-input path',
            'backlog': 'Needs trace confirmation, lower severity, or API-by-design context',
            'false_positive': 'Rejected by Validate or no plausible path',
        },
        'summary': summary,
        'findings': bucketed,
        'chains': chains,
        'gaps': gaps,
    }
