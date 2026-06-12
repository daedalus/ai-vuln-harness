"""NVD CVE JSON loader.

Uses the olbat/nvdcve mirror (individual CVE JSON files via GitHub Pages)
or git clone for bulk loading.
"""

from __future__ import annotations

import json
import subprocess
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..rag_kb import VulnerabilityKB

from .common import _default_cache_dir


def load_nvd_cve_from_file(
    kb: VulnerabilityKB,
    json_path: Path,
    max_patterns: int = 1000,
    verbose: bool = False,
) -> int:
    """Load CVE definitions from NVD JSON feed.

    Returns the number of patterns loaded.
    """
    count = 0
    with open(json_path) as f:
        data = json.load(f)

    cve_items = data.get("CVE_Items", [])
    for item in cve_items:
        if max_patterns > 0 and count >= max_patterns:
            break

        cve_data = item.get("cve", {})
        cve_id = cve_data.get("CVE_data_meta", {}).get("ID", "")
        if not cve_id:
            continue

        descriptions = cve_data.get("description", {}).get("description_data", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        if not description:
            continue

        weaknesses = cve_data.get("weakness", {}).get("description_data", [])
        cwe_ids = []
        for w in weaknesses:
            val = w.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
            elif val.startswith("CWE"):
                cwe_ids.append(f"CWE-{val[3:]}")

        title = f"{cve_id}: {description[:100]}"
        patterns = cwe_ids if cwe_ids else [cve_id]

        kb.add_pattern(
            cwe=cve_id,
            title=title,
            description=description[:500],
            patterns=patterns[:5],
            language="generic", persist=True,
        )
        count += 1

    return count


def _load_single_cve(kb: VulnerabilityKB, cve_id: str, verbose: bool = False) -> bool:
    """Load a single CVE from the olbat/nvdcve GitHub Pages mirror.

    Returns True if successfully loaded, False otherwise.
    """
    url = f"https://olbat.github.io/nvdcve/{cve_id}.json"
    req = urllib.request.Request(url, headers={
        "User-Agent": "ai-vuln-harness/1.0 (https://github.com/daedalus/ai-vuln-harness)",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            data = json.loads(response.read())

        descriptions = data.get("cve", {}).get("description", {}).get("description_data", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        if not description:
            return False

        weaknesses = data.get("cve", {}).get("weakness", {}).get("description_data", [])
        cwe_ids = []
        for w in weaknesses:
            val = w.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
            elif val.startswith("CWE"):
                cwe_ids.append(f"CWE-{val[3:]}")

        patterns = cwe_ids if cwe_ids else [cve_id]

        kb.add_pattern(
            cwe=cve_id,
            title=f"{cve_id}: {description[:100]}",
            description=description[:500],
            patterns=patterns[:5],
            language="generic", persist=True,
        )
        if verbose:
            print(f"    Loaded {cve_id}: {description[:60]}...")
        return True
    except Exception:
        return False


def _clone_nvdcve_repo(cache_dir: Path, verbose: bool = False) -> Path | None:
    """Clone the olbat/nvdcve repository.

    Returns the path to the nvdcve directory, or None on failure.
    """
    repo_dir = cache_dir / "nvdcve"
    if repo_dir.exists():
        if verbose:
            print(f"  Using cached repo at {repo_dir}")
        return repo_dir

    print(f"Cloning olbat/nvdcve repository...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "https://github.com/olbat/nvdcve.git", str(repo_dir)],
            check=True,
            capture_output=True,
            timeout=300,
        )
        if verbose:
            print(f"  Cloned to {repo_dir}")
        return repo_dir
    except Exception as e:
        print(f"  Failed to clone nvdcve: {e}")
        return None


def load_nvdcve_from_clone(
    kb: VulnerabilityKB,
    clone_dir: Path | None = None,
    max_patterns: int = 500,
    verbose: bool = False,
) -> int:
    """Load CVEs from a cloned nvdcve repository.

    The nvdcve repo has individual CVE JSON files in the nvdcve/ directory.
    Format: {id, descriptions: [{lang, value}], weaknesses: [{description: [{value}]}]}

    Returns the number of patterns loaded.
    """
    if clone_dir is None:
        clone_dir = _clone_nvdcve_repo(_default_cache_dir(), verbose)

    if clone_dir is None:
        return 0

    nvdcve_dir = clone_dir / "nvdcve"
    if not nvdcve_dir.exists():
        if verbose:
            print(f"  nvdcve directory not found at {nvdcve_dir}")
        return 0

    count = 0
    json_files = sorted(nvdcve_dir.glob("CVE-*.json"))

    if verbose:
        print(f"  Found {len(json_files)} CVE JSON files")

    for json_file in json_files:
        if max_patterns > 0 and count >= max_patterns:
            break

        try:
            with open(json_file) as f:
                data = json.load(f)

            cve_id = data.get("id", "") or json_file.stem

            # Extract English description (new format)
            descriptions = data.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break

            # Fallback to old format
            if not description:
                descriptions = data.get("cve", {}).get("description", {}).get("description_data", [])
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

            if not description:
                continue

            # Extract CWE IDs (new format)
            weaknesses = data.get("weaknesses", [])
            cwe_ids = []
            for w in weaknesses:
                for desc in w.get("description", []):
                    val = desc.get("value", "")
                    if val.startswith("CWE-"):
                        cwe_ids.append(val)
                    elif val.startswith("CWE"):
                        cwe_ids.append(f"CWE-{val[3:]}")

            # Fallback to old format
            if not cwe_ids:
                weaknesses = data.get("cve", {}).get("weakness", {}).get("description_data", [])
                for w in weaknesses:
                    val = w.get("value", "")
                    if val.startswith("CWE-"):
                        cwe_ids.append(val)
                    elif val.startswith("CWE"):
                        cwe_ids.append(f"CWE-{val[3:]}")

            patterns = cwe_ids if cwe_ids else [cve_id]

            kb.add_pattern(
                cwe=cve_id,
                title=f"{cve_id}: {description[:100]}",
                description=description[:500],
                patterns=patterns[:5],
                language="generic", persist=True,
            )
            count += 1

            if verbose and count % 100 == 0:
                print(f"    Loaded {count} CVEs...")

        except Exception:
            continue

    return count


def load_nvd_cve_from_url(
    kb: VulnerabilityKB,
    url: str = "",
    cache_path: Path | None = None,
    max_patterns: int = 1000,
    verbose: bool = False,
) -> int:
    """Load CVE definitions from olbat/nvdcve.

    Tries git clone first, falls back to GitHub Pages individual files.

    Returns the number of patterns loaded.
    """
    if verbose:
        print("Loading CVEs from olbat/nvdcve...")

    # Try git clone first (faster for bulk loading)
    clone_dir = _clone_nvdcve_repo(_default_cache_dir(), verbose)
    if clone_dir:
        count = load_nvdcve_from_clone(kb, clone_dir, max_patterns, verbose)
        if count > 0:
            return count

    # Fall back to GitHub Pages individual files
    if verbose:
        print("  Falling back to GitHub Pages individual files...")

    count = 0
    for year in [2024, 2023]:
        if max_patterns > 0 and count >= max_patterns:
            break
        if verbose:
            print(f"  Loading CVEs from {year}...")
        for i in range(1, min(max_patterns // 2 + 1, 1000)):
            if max_patterns > 0 and count >= max_patterns:
                break
            cve_id = f"CVE-{year}-{i:04d}"
            if _load_single_cve(kb, cve_id, verbose):
                count += 1
            if verbose and count % 100 == 0:
                print(f"    Loaded {count} CVEs...")

    return count
