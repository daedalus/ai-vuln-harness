"""OSV.dev loader."""

from __future__ import annotations

import json
import urllib.request
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from ..rag_kb import VulnerabilityKB

# pylint: disable=wrong-import-position
from .common import _default_cache_dir


def load_osv_from_file(
    kb: VulnerabilityKB,
    json_path: Path,
    max_patterns: int = 500,
) -> int:
    """Load vulnerability patterns from OSV.dev JSON.

    Returns the number of patterns loaded.
    """
    count = 0
    with open(json_path) as f:
        data = json.load(f)

    vulns = data if isinstance(data, list) else data.get("vulns", [])
    for vuln in vulns:
        if 0 < max_patterns <= count:
            break

        osv_id = vuln.get("id", "")
        summary = vuln.get("summary", "")
        details = vuln.get("details", "")
        aliases = vuln.get("aliases", [])
        severity = vuln.get("severity", [])

        if not summary and not details:
            continue

        patterns = []
        for alias in aliases:
            if alias.startswith("CVE-") or alias.startswith("GHSA-"):
                patterns.append(alias)

        for sev in severity:
            score = sev.get("score", "")
            if score and float(score) >= 7.0:
                patterns.append("high-severity")

        if not patterns:
            patterns = [osv_id] if osv_id else []

        title = summary[:100] if summary else details[:100]
        kb.add_pattern(
            cwe=osv_id or f"OSV-{count}",
            title=title,
            description=details[:500] if details else summary[:500],
            patterns=patterns[:5],
            language="generic",
            persist=True,
        )
        count += 1

    return count


def load_osv_from_url(
    kb: VulnerabilityKB,
    url: str = "https://api.osv.dev/v1/query",
    cache_path: Path | None = None,
    max_patterns: int = 500,
) -> int:
    """Download and load OSV.dev vulnerabilities.

    Returns the number of patterns loaded.
    """
    if cache_path is None:
        cache_path = _default_cache_dir() / "osv_vulns.json"

    if not cache_path.exists():
        print("Downloading OSV.dev vulnerabilities...")
        query_data = json.dumps({}).encode()
        req = urllib.request.Request(
            url,
            data=query_data,
            headers={
                "User-Agent": "ai-vuln-harness/1.0 (https://github.com/daedalus/ai-vuln-harness)",
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                data = response.read()
            with open(cache_path, "wb") as f:
                f.write(data)
            print(f"OSV.dev data cached to {cache_path}")
        except Exception as e:
            print(f"  OSV.dev API unavailable: {e}")
            return 0

    return load_osv_from_file(kb, cache_path, max_patterns)
