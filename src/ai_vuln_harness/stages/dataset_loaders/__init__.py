# pylint: disable=wrong-import-position
"""Vulnerability Dataset Loaders for CWE/CVE Knowledge Base.

Provides loaders for:
- MITRE CWE XML: 900+ CWE definitions with relationships
- NVD CVE JSON: 250K+ CVE descriptions with CVSS scores
- CVEFixes: CVE fix commits with before/after code
- Exploit-DB: 40K+ exploit code with platform/type tags
- GitHub Advisory Database: GitHub-specific security advisories
- VulDeePecker: Multi-class vulnerability detection samples
- OSV.dev: Ecosystem-specific vulnerabilities
- Snyk Vulnerability Database: Package vulnerabilities
- D2A (DeepDive): Real-world bugs with fixing commits
- Juliet Test Suite: Synthetic vulnerability samples

Reference: https://cwe.mitre.org, https://nvd.nist.gov, https://www.exploit-db.com,
           https://github.com/advisories, https://github.com/lin-tan-gal/VulDeePecker
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

from ..rag_kb import VulnerabilityKB
from .common import _default_cache_dir, _default_db_dir
from .cve_fixes import load_cvefixes_from_file
from .d2a import load_d2a_from_file, load_d2a_from_url
from .exploitdb import load_exploitdb_from_file, load_exploitdb_from_url
from .github_advisory import (
    load_github_advisory_from_file,
    load_github_advisory_from_url,
)
from .juliet import load_juliet_from_file, load_juliet_representatives
from .mitre_cwe import load_mitre_cwe_from_file, load_mitre_cwe_from_url
from .nvd_cve import (
    load_nvd_cve_from_file,
    load_nvd_cve_from_url,
    load_nvdcve_from_clone,
)
from .osv import load_osv_from_file, load_osv_from_url
from .snyk import load_snyk_from_file, load_snyk_from_url

__all__ = [
    "VulnerabilityKB",
    "_default_cache_dir",
    "_default_db_dir",
    "load_mitre_cwe_from_file",
    "load_mitre_cwe_from_url",
    "load_nvd_cve_from_file",
    "load_nvd_cve_from_url",
    "load_nvdcve_from_clone",
    "load_cvefixes_from_file",
    "load_exploitdb_from_file",
    "load_exploitdb_from_url",
    "load_github_advisory_from_file",
    "load_github_advisory_from_url",
    "load_osv_from_file",
    "load_osv_from_url",
    "load_snyk_from_file",
    "load_snyk_from_url",
    "load_d2a_from_file",
    "load_d2a_from_url",
    "load_juliet_from_file",
    "load_juliet_representatives",
]


# pylint: disable=too-many-branches,too-many-statements
def load_all_public_datasets(  # noqa: MC0001
    kb: VulnerabilityKB,
    cache_dir: Path | None = None,
    max_per_dataset: int = 500,
    datasets: list[str] | None = None,
    verbose: bool = False,
) -> dict:
    """Load public datasets into the knowledge base.

    Parameters
    ----------
    kb:
        The VulnerabilityKB instance to populate.
    cache_dir:
        Directory for caching downloaded files.
    max_per_dataset:
        Maximum patterns to load per dataset.
    datasets:
        List of datasets to load. None = all available.
        Options: "mitre_cwe", "nvd_cve", "exploitdb", "github", "osv",
                 "snyk", "d2a", "vuldeepecker", "juliet"
    verbose:
        Enable verbose output for download progress.

    Returns
    -------
    Dict with counts per dataset.
    """
    if cache_dir is None:
        cache_dir = _default_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)

    all_datasets = [
        "mitre_cwe",
        "nvd_cve",
        "exploitdb",
        "github",
        "osv",
        "snyk",
        "d2a",
        "juliet",
    ]
    datasets_to_load = datasets or all_datasets

    summary = dict.fromkeys(all_datasets, 0)
    summary["total"] = 0

    # Load MITRE CWE
    if "mitre_cwe" in datasets_to_load:
        try:
            print("Loading MITRE CWE dataset...")
            cwe_path = cache_dir / "cwec_v4.16.xml"
            if cwe_path.exists():
                count = load_mitre_cwe_from_file(kb, cwe_path, max_per_dataset)
            else:
                count = load_mitre_cwe_from_url(
                    kb, cache_path=cwe_path, max_patterns=max_per_dataset
                )
            summary["mitre_cwe"] = count
            if verbose:
                print(f"  ✓ Loaded {count} CWE patterns")
            else:
                print(f"  ✓ Loaded {count} CWE patterns")
        except Exception as e:
            print(f"  ✗ Failed to load CWE: {e}")

    # Load NVD CVE
    if "nvd_cve" in datasets_to_load:
        try:
            print("Loading NVD CVE dataset...")
            count = load_nvd_cve_from_url(
                kb, max_patterns=max_per_dataset, verbose=verbose
            )
            summary["nvd_cve"] = count
            print(f"  ✓ Loaded {count} CVE patterns")
        except Exception as e:
            print(f"  ✗ Failed to load CVE: {e}")

    # Load Exploit-DB
    if "exploitdb" in datasets_to_load:
        try:
            print("Loading Exploit-DB dataset...")
            edb_path = cache_dir / "exploitdb.csv"
            if edb_path.exists():
                count = load_exploitdb_from_file(kb, edb_path, max_per_dataset)
            else:
                count = load_exploitdb_from_url(
                    kb, cache_path=edb_path, max_patterns=max_per_dataset
                )
            summary["exploitdb"] = count
            print(f"  ✓ Loaded {count} Exploit-DB patterns")
        except Exception as e:
            print(f"  ✗ Failed to load Exploit-DB: {e}")

    # Load GitHub Advisory
    if "github" in datasets_to_load:
        try:
            print("Loading GitHub Advisory Database...")
            gh_path = cache_dir / "github_advisories.json"
            if gh_path.exists():
                count = load_github_advisory_from_file(kb, gh_path, max_per_dataset)
            else:
                count = load_github_advisory_from_url(
                    kb, cache_path=gh_path, max_patterns=max_per_dataset
                )
            summary["github"] = count
            print(f"  ✓ Loaded {count} GitHub Advisory patterns")
        except Exception as e:
            print(f"  ✗ Failed to load GitHub Advisory: {e}")

    # Load OSV.dev
    if "osv" in datasets_to_load:
        try:
            print("Loading OSV.dev dataset...")
            osv_path = cache_dir / "osv_vulns.json"
            if osv_path.exists():
                count = load_osv_from_file(kb, osv_path, max_per_dataset)
            else:
                count = load_osv_from_url(
                    kb, cache_path=osv_path, max_patterns=max_per_dataset
                )
            summary["osv"] = count
            print(f"  ✓ Loaded {count} OSV.dev patterns")
        except Exception as e:
            print(f"  ✗ Failed to load OSV.dev: {e}")

    # Load Snyk
    if "snyk" in datasets_to_load:
        try:
            print("Loading Snyk Vulnerability Database...")
            snyk_path = cache_dir / "snyk_vulns.json"
            if snyk_path.exists():
                count = load_snyk_from_file(kb, snyk_path, max_per_dataset)
            else:
                count = load_snyk_from_url(
                    kb, cache_path=snyk_path, max_patterns=max_per_dataset
                )
            summary["snyk"] = count
            print(f"  ✓ Loaded {count} Snyk patterns")
        except Exception as e:
            print(f"  ✗ Failed to load Snyk: {e}")

    # Load D2A
    if "d2a" in datasets_to_load:
        try:
            print("Loading D2A dataset...")
            count = load_d2a_from_url(kb, max_patterns=max_per_dataset)
            summary["d2a"] = count
            print(f"  ✓ Loaded {count} D2A patterns")
        except Exception as e:
            print(f"  ✗ Failed to load D2A: {e}")

    # Load Juliet Test Suite
    if "juliet" in datasets_to_load:
        try:
            print("Loading Juliet Test Suite patterns...")
            count = load_juliet_representatives(kb)
            summary["juliet"] = count
            print(f"  ✓ Loaded {count} Juliet patterns")
        except Exception as e:
            print(f"  ✗ Failed to load Juliet: {e}")

    summary["total"] = sum(summary[ds] for ds in all_datasets)
    print(f"\nTotal patterns in KB: {kb.size}")
    return summary
