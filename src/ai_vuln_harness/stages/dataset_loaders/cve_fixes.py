"""CVEFixes loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..rag_kb import VulnerabilityKB


def load_cvefixes_from_file(
    kb: VulnerabilityKB,
    json_path: Path,
    max_patterns: int = 500,
) -> int:
    """Load CVE fix patterns from CVEFixes dataset.

    Returns the number of patterns loaded.
    """
    count = 0
    with open(json_path) as f:
        data = json.load(f)

    items = data if isinstance(data, list) else data.get("data", [])
    for item in items:
        if max_patterns > 0 and count >= max_patterns:
            break

        cve_id = item.get("cve_id", "")
        if not cve_id:
            continue

        message = item.get("message", "") or item.get("commit_message", "")
        description = item.get("description", "") or message[:500]

        patterns = []
        msg_lower = message.lower()
        cwe_keywords = {
            "sql injection": "CWE-89",
            "xss": "CWE-79",
            "cross-site scripting": "CWE-79",
            "command injection": "CWE-78",
            "path traversal": "CWE-22",
            "buffer overflow": "CWE-120",
            "use after free": "CWE-416",
            "double free": "CWE-415",
            "null pointer": "CWE-476",
            "integer overflow": "CWE-190",
            "format string": "CWE-134",
            "deserialization": "CWE-502",
            "ssrf": "CWE-918",
            "xxe": "CWE-611",
        }

        for keyword, cwe in cwe_keywords.items():
            if keyword in msg_lower:
                patterns.append(cwe)

        if not patterns:
            patterns = [cve_id]

        title = f"{cve_id}: {description[:100]}"
        kb.add_pattern(
            cwe=cve_id,
            title=title,
            description=description[:500],
            patterns=patterns[:5],
            language="generic",
            persist=True,
        )
        count += 1

    return count
