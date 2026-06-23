"""D2A (DeepDive) loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..rag_kb import VulnerabilityKB


def load_d2a_from_file(
    kb: VulnerabilityKB,
    json_path: Path,
    max_patterns: int = 500,
) -> int:
    """Load vulnerability patterns from D2A dataset JSON.

    Returns the number of patterns loaded.
    """
    count = 0
    with open(json_path) as f:
        data = json.load(f)

    items = data if isinstance(data, list) else data.get("data", [])
    for item in items:
        if max_patterns > 0 and count >= max_patterns:
            break

        commit_msg = item.get("commit_message", "") or item.get("message", "")
        cve_id = item.get("cve_id", "") or item.get("cve", "")

        if not commit_msg:
            continue

        patterns = []
        msg_lower = commit_msg.lower()
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

        if cve_id:
            patterns.append(cve_id)

        if not patterns:
            patterns = [f"D2A-{count}"]

        title = commit_msg[:100]
        kb.add_pattern(
            cwe=cve_id or f"D2A-{count}",
            title=title,
            description=commit_msg[:500],
            patterns=patterns[:5],
            language="generic",
            persist=True,
        )
        count += 1

    return count


def _create_d2a_representatives(kb: VulnerabilityKB) -> int:
    """Create representative D2A patterns based on known bug classes."""
    d2a_patterns = [
        {
            "cwe": "D2A-SQLI",
            "title": "SQL Injection (D2A)",
            "description": "SQL injection vulnerabilities from real-world bug fixes.",
            "patterns": ["sql", "injection", "query", "execute"],
        },
        {
            "cwe": "D2A-XSS",
            "title": "Cross-site Scripting (D2A)",
            "description": "XSS vulnerabilities from real-world bug fixes.",
            "patterns": ["xss", "script", "innerHTML", "escape"],
        },
        {
            "cwe": "D2A-CMDI",
            "title": "Command Injection (D2A)",
            "description": "Command injection vulnerabilities from real-world bug fixes.",
            "patterns": ["command", "injection", "system", "exec"],
        },
        {
            "cwe": "D2A-PATH",
            "title": "Path Traversal (D2A)",
            "description": "Path traversal vulnerabilities from real-world bug fixes.",
            "patterns": ["path", "traversal", "directory", "file"],
        },
        {
            "cwe": "D2A-DESER",
            "title": "Deserialization (D2A)",
            "description": "Insecure deserialization vulnerabilities from real-world bug fixes.",
            "patterns": ["deserialization", "pickle", "yaml", "marshal"],
        },
        {
            "cwe": "D2A-SSRF",
            "title": "Server-Side Request Forgery (D2A)",
            "description": "SSRF vulnerabilities from real-world bug fixes.",
            "patterns": ["ssrf", "request", "url", "fetch"],
        },
        {
            "cwe": "D2A-BOUND",
            "title": "Buffer Overflow (D2A)",
            "description": "Buffer overflow vulnerabilities from real-world bug fixes.",
            "patterns": ["buffer", "overflow", "bounds", "length"],
        },
        {
            "cwe": "D2A-UAF",
            "title": "Use After Free (D2A)",
            "description": "Use-after-free vulnerabilities from real-world bug fixes.",
            "patterns": ["use", "after", "free", "dangling"],
        },
    ]

    count = 0
    for p in d2a_patterns:
        if p["cwe"] not in [existing["cwe"] for existing in kb._patterns]:
            kb.add_pattern(**p)
            count += 1

    return count


def load_d2a_from_url(
    kb: VulnerabilityKB,
    url: str = "",
    cache_path: Path | None = None,
    max_patterns: int = 500,
) -> int:
    """Load D2A dataset from Hugging Face.

    Dataset: claudios/D2A (143K rows, C/C++ vulnerability detection)

    Returns the number of patterns loaded.
    """
    try:
        from datasets import load_dataset

        print("Loading D2A dataset from Hugging Face...")
        dataset = load_dataset("claudios/D2A", "code", split="train", streaming=True)

        count = 0
        for item in dataset:
            if max_patterns > 0 and count >= max_patterns:
                break

            bug_url = item.get("bug_url", "")
            bug_function = item.get("bug_function", "")

            if not bug_function:
                continue

            patterns = []
            func_lower = bug_function.lower()

            vuln_patterns = {
                "buffer overflow": "CWE-120",
                "use after free": "CWE-416",
                "double free": "CWE-415",
                "null pointer": "CWE-476",
                "integer overflow": "CWE-190",
                "out of bounds": "CWE-125",
                "uninitialized": "CWE-457",
                "memory leak": "CWE-401",
                "format string": "CWE-134",
                "race condition": "CWE-362",
            }

            for keyword, cwe in vuln_patterns.items():
                if keyword in func_lower:
                    patterns.append(cwe)

            if not patterns:
                patterns = [f"D2A-{item.get('id', count)}"]

            title = f"D2A: {bug_url.split('/')[-1] if bug_url else 'vulnerability'}"
            kb.add_pattern(
                cwe=f"D2A-{item.get('id', count)}",
                title=title[:100],
                description=bug_function[:500],
                patterns=patterns[:5],
                language="c",
                persist=True,
            )
            count += 1

        return count

    except ImportError:
        print("  datasets library not available. Install with: pip install datasets")
        return _create_d2a_representatives(kb)
    except Exception as e:
        print(f"  Failed to load D2A from Hugging Face: {e}")
        return _create_d2a_representatives(kb)
