from __future__ import annotations

import re

API_BY_DESIGN_PATTERNS = [
    r'.*printf.*',
    r'.*write.*',
    r'.*read.*',
    r'.*open.*',
    r'.*execute.*',
]


def build_validate_prompt(finding: dict, snippet: dict) -> str:
    return f"""Your job is to DISPROVE this vulnerability finding, not confirm it.

Finding:
- snippet_id: {finding.get('snippet_id', '?')}
- class: {finding.get('class', '?')}
- description: {finding.get('desc', '')}
- call_path: {finding.get('call_path', [])}

ACTUAL SOURCE CODE (file: {snippet.get('file', '?')}, lines {snippet.get('lines', '?')}):
```c
{snippet.get('content', '')}
```

Output ONLY JSON: {{"status": "confirmed|rejected|needs-more-info", "reason": "..."}}
"""


def is_api_by_design(finding: dict, snippet: dict) -> bool:
    name = str(snippet.get('name', '')).lower()
    clazz = str(finding.get('class', '')).lower()
    desc = str(finding.get('desc', '')).lower()

    if 'format-string' in clazz and 'printf' in name:
        return True
    if 'by design' in desc:
        return True
    return any(re.match(p, name) for p in API_BY_DESIGN_PATTERNS)


def requires_trace_before_fix_now(is_library_target: bool, trace_confirmed: bool) -> bool:
    return is_library_target and not trace_confirmed
