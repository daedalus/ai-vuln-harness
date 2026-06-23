"""GitHub Advisory Database loader."""

from __future__ import annotations

import json
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..rag_kb import VulnerabilityKB

from .common import _default_cache_dir


def load_github_advisory_from_file(
    kb: VulnerabilityKB,
    json_path: Path,
    max_patterns: int = 500,
) -> int:
    """Load patterns from GitHub Advisory Database JSONL.

    Returns the number of patterns loaded.
    """
    count = 0
    with open(json_path) as f:
        for line in f:
            if max_patterns > 0 and count >= max_patterns:
                break

            line = line.strip()
            if not line:
                continue

            try:
                advisory = json.loads(line)
            except json.JSONDecodeError:
                continue

            ghsa_id = advisory.get("id", "")
            summary = advisory.get("summary", "")
            description = advisory.get("description", "")
            cwe_ids = advisory.get("cwes", [])

            if not summary and not description:
                continue

            patterns = []
            for cwe in cwe_ids:
                if isinstance(cwe, dict):
                    cwe_id = cwe.get("cwe_id", "")
                else:
                    cwe_id = str(cwe)
                if cwe_id:
                    patterns.append(cwe_id)

            if not patterns:
                patterns = [ghsa_id] if ghsa_id else []

            title = summary[:100] if summary else description[:100]
            kb.add_pattern(
                cwe=ghsa_id or f"GHSA-{count}",
                title=title,
                description=description[:500] if description else summary[:500],
                patterns=patterns[:5],
                language="generic",
                persist=True,
            )
            count += 1

    return count


def load_github_advisory_from_url(
    kb: VulnerabilityKB,
    url: str = "https://api.github.com/advisories?per_page=100&type=reviewed&ecosystem=npm",
    cache_path: Path | None = None,
    max_patterns: int = 500,
) -> int:
    """Download and load GitHub Advisory Database.

    Returns the number of patterns loaded.
    """
    if cache_path is None:
        cache_path = _default_cache_dir() / "github_advisories.json"

    if not cache_path.exists():
        print(f"Downloading GitHub Advisory Database from {url}...")
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": "ai-vuln-harness/1.0 (https://github.com/daedalus/ai-vuln-harness)",
                "Accept": "application/vnd.github+json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                data = response.read()
            advisories = json.loads(data)
            with open(cache_path, "w") as f:
                for adv in advisories:
                    f.write(json.dumps(adv) + "\n")
            print(f"GitHub Advisory Database cached to {cache_path}")
        except Exception as e:
            print(f"  Failed to download GitHub Advisory: {e}")
            return 0

    return load_github_advisory_from_file(kb, cache_path, max_patterns)
