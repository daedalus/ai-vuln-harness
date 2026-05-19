from __future__ import annotations

import json


def _balanced_json_prefix(line: str):
    depth = 0
    start = -1
    for i, c in enumerate(line):
        if c == '{':
            if depth == 0:
                start = i
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0 and start >= 0:
                candidate = line[start : i + 1]
                try:
                    return json.loads(candidate)
                except json.JSONDecodeError:
                    continue
    return None


def _extract_objects(text: str) -> list[dict]:
    objs = []
    decoder = json.JSONDecoder()
    i = 0
    while i < len(text):
        if text[i] not in '{[':
            i += 1
            continue
        try:
            obj, end = decoder.raw_decode(text[i:])
            if isinstance(obj, dict):
                objs.append(obj)
            elif isinstance(obj, list):
                objs.extend([x for x in obj if isinstance(x, dict)])
            i += end
        except json.JSONDecodeError:
            i += 1
    return objs


def parse_findings(text: str, domain: str = '') -> tuple[list[dict], list[dict]]:
    findings: list[dict] = []
    gaps: list[dict] = []
    saw_done = False

    if not text or not text.strip():
        return findings, gaps

    try:
        data = json.loads(text)
        if isinstance(data, dict):
            data = [data]
        if isinstance(data, list):
            for item in data:
                if not isinstance(item, dict):
                    continue
                _classify_item(item, findings, gaps)
                saw_done = saw_done or item.get('done') is True
            if saw_done and not findings and not gaps:
                gaps.append(_sentinel_gap(domain, 'sentinel-only JSON body'))
            return findings, gaps
    except json.JSONDecodeError:
        pass

    for obj in _extract_objects(text):
        _classify_item(obj, findings, gaps)
        saw_done = saw_done or obj.get('done') is True

    if not findings and not gaps and not saw_done:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = None
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                obj = _balanced_json_prefix(line)
            if not isinstance(obj, dict):
                continue
            _classify_item(obj, findings, gaps)
            saw_done = saw_done or obj.get('done') is True

    if saw_done and not findings and not gaps:
        gaps.append(_sentinel_gap(domain, 'sentinel-only output'))

    return findings, gaps


def _classify_item(item: dict, findings: list[dict], gaps: list[dict]) -> None:
    item.setdefault('status', 'raw')
    item.setdefault('poc_confirmed', False)
    if item.get('done') is True:
        return
    if 'coverage_gap' in item:
        gaps.append(item)
    elif 'snippet_id' in item:
        findings.append(item)


def _sentinel_gap(domain: str, reason: str) -> dict:
    return {
        'coverage_gap': domain or 'unknown-domain',
        'reason': reason,
    }
