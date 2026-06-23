"""Snyk Vulnerability Database loader."""

from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..rag_kb import VulnerabilityKB

from .common import _default_cache_dir


def load_snyk_from_file(
    kb: VulnerabilityKB,
    json_path: Path,
    max_patterns: int = 500,
) -> int:
    """Load vulnerability patterns from Snyk database JSON.

    Returns the number of patterns loaded.
    """
    count = 0
    with open(json_path) as f:
        data = json.load(f)

    vulns = data if isinstance(data, list) else data.get("vulns", [])
    for vuln in vulns:
        if max_patterns > 0 and count >= max_patterns:
            break

        vuln_id = vuln.get("id", "")
        title = vuln.get("title", "")
        description = vuln.get("description", "")
        cvss = vuln.get("cvssScore", 0)
        cwe = vuln.get("CWE", [])

        if not title and not description:
            continue

        patterns = []
        if isinstance(cwe, list):
            for c in cwe:
                if isinstance(c, dict):
                    patterns.append(c.get("id", ""))
                else:
                    patterns.append(str(c))
        elif isinstance(cwe, str):
            patterns.append(cwe)

        if cvss and float(cvss) >= 7.0:
            patterns.append("high-severity")

        if not patterns:
            patterns = [vuln_id] if vuln_id else []

        kb.add_pattern(
            cwe=vuln_id or f"SNYK-{count}",
            title=title[:100],
            description=description[:500],
            patterns=patterns[:5],
            language="generic",
            persist=True,
        )
        count += 1

    return count


def load_snyk_from_url(
    kb: VulnerabilityKB,
    url: str = "https://api.snyk.io/v1",
    cache_path: Path | None = None,
    max_patterns: int = 500,
    api_key: str | None = None,
) -> int:
    """Download and load Snyk vulnerabilities.

    Note: Snyk API requires authentication. Pass api_key or set SNYK_API_KEY env var.

    Returns the number of patterns loaded.
    """
    if cache_path is None:
        cache_path = _default_cache_dir() / "snyk_vulns.json"

    if not cache_path.exists():
        key = api_key or os.environ.get("SNYK_API_KEY")
        if not key:
            print("  Skipping Snyk: No API key available (set SNYK_API_KEY env var)")
            return 0

        print(f"Downloading Snyk vulnerabilities from {url}...")
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "ai-vuln-harness/1.0",
                "Authorization": f"token {key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                data = response.read()
            with open(cache_path, "wb") as f:
                f.write(data)
            print(f"Snyk data cached to {cache_path}")
        except Exception as e:
            print(f"  Failed to download Snyk: {e}")
            return 0

    return load_snyk_from_file(kb, cache_path, max_patterns)
