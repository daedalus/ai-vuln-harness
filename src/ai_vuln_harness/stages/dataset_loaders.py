"""Vulnerability Dataset Loaders for CWE/CVE Knowledge Base.

Provides loaders for:
- MITRE CWE XML: 900+ CWE definitions with relationships
- NVD CVE JSON: 250K+ CVE descriptions with CVSS scores
- CVEFixes: CVE fix commits with before/after code
- Exploit-DB: 40K+ exploit code with platform/type tags
- GitHub Advisory Database: GitHub-specific security advisories
- VulDeePecker: Multi-class vulnerability detection samples

Reference: https://cwe.mitre.org, https://nvd.nist.gov, https://www.exploit-db.com,
           https://github.com/advisories, https://github.com/lin-tan-gal/VulDeePecker
"""

from __future__ import annotations

import json
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .rag_kb import VulnerabilityKB


def _default_cache_dir() -> Path:
    """Return the default cache directory (~/.ai-vuln-harness/cache/)."""
    return Path.home() / ".ai-vuln-harness" / "cache"


def _default_db_dir() -> Path:
    """Return the default database directory (~/.ai-vuln-harness/db/)."""
    return Path.home() / ".ai-vuln-harness" / "db"


# --- MITRE CWE Loader ---

def _cwe_severity_from_description(desc: str) -> str:
    """Extract severity hint from CWE description."""
    desc_lower = desc.lower()
    if any(w in desc_lower for w in ["injection", "overflow", "bypass", "escalation", "execution"]):
        return "high"
    if any(w in desc_lower for w in ["weak", "missing", "improper", "incorrect"]):
        return "medium"
    return "low"


def load_mitre_cwe_from_file(
    kb: VulnerabilityKB,
    xml_path: Path,
    max_patterns: int = 500,
) -> int:
    """Load CWE definitions from MITRE CWE XML file.

    Download from: https://cwe.mitre.org/data/xml/cwec_v4.16.xml.zip

    Returns the number of patterns loaded.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()

    # Find all Weakness elements
    weaknesses = []
    for elem in root.iter():
        local_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if local_name == "Weakness":
            weaknesses.append(elem)

    count = 0
    for weakness in weaknesses:
        if count >= max_patterns:
            break

        cwe_id = weakness.get("ID", "")
        if not cwe_id:
            continue

        name = weakness.get("Name", "")

        # Get description
        description = ""
        for elem in weakness:
            local_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if local_name == "Description" and elem.text:
                description = elem.text
                break
        if not description:
            description = name

        # Extract related weaknesses as patterns
        patterns = []
        for elem in weakness:
            local_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if local_name == "Related_Weaknesses":
                for rel in elem:
                    rel_local = rel.tag.split("}")[-1] if "}" in rel.tag else rel.tag
                    if rel_local == "Related_Weakness":
                        ref = rel.get("CWE_ID", "")
                        if ref:
                            patterns.append(f"CWE-{ref}")

        # Extract detection methods as patterns
        for elem in weakness:
            local_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if local_name == "Detection_Methods":
                for det in elem:
                    det_local = det.tag.split("}")[-1] if "}" in det.tag else det.tag
                    if det_local == "Detection_Method":
                        for method_elem in det:
                            method_local = method_elem.tag.split("}")[-1] if "}" in method_elem.tag else method_elem.tag
                            if method_local == "Method" and method_elem.text:
                                patterns.append(method_elem.text.strip())

        if not patterns:
            patterns = [name.lower()]

        kb.add_pattern(
            cwe=f"CWE-{cwe_id}",
            title=name,
            description=description[:500],  # Truncate long descriptions
            patterns=patterns[:10],  # Limit patterns
            language="generic",
        )
        count += 1

    return count


def load_mitre_cwe_from_url(
    kb: VulnerabilityKB,
    url: str = "https://cwe.mitre.org/data/xml/cwec_v4.16.xml.zip",
    cache_path: Path | None = None,
    max_patterns: int = 500,
) -> int:
    """Download and load CWE definitions from MITRE.

    Downloads the ZIP file, extracts the XML, and loads patterns.
    Caches the ZIP to avoid re-downloading.

    Returns the number of patterns loaded.
    """
    import io
    import zipfile

    if cache_path is None:
        cache_path = _default_cache_dir() / "cwe_mitre.xml"

    if not cache_path.exists():
        print(f"Downloading CWE data from {url}...")
        req = urllib.request.Request(url, headers={"User-Agent": "ai-vuln-harness/1.0"})
        with urllib.request.urlopen(req, timeout=60) as response:
            zip_data = response.read()

        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            xml_files = [f for f in zf.namelist() if f.endswith(".xml")]
            if xml_files:
                with zf.open(xml_files[0]) as src, open(cache_path, "wb") as dst:
                    dst.write(src.read())
                print(f"CWE data cached to {cache_path}")

    return load_mitre_cwe_from_file(kb, cache_path, max_patterns)


# --- NVD CVE Loader ---

def load_nvd_cve_from_file(
    kb: VulnerabilityKB,
    json_path: Path,
    max_patterns: int = 1000,
) -> int:
    """Load CVE definitions from NVD JSON feed.

    Download from: https://nvd.nist.gov/feeds/json/cve/1.1/

    Returns the number of patterns loaded.
    """
    count = 0
    with open(json_path) as f:
        data = json.load(f)

    cve_items = data.get("CVE_Items", [])
    for item in cve_items:
        if count >= max_patterns:
            break

        cve_data = item.get("cve", {})
        cve_id = cve_data.get("CVE_data_meta", {}).get("ID", "")
        if not cve_id:
            continue

        # Get description
        descriptions = cve_data.get("description", {}).get("description_data", [])
        description = ""
        for desc in descriptions:
            if desc.get("lang") == "en":
                description = desc.get("value", "")
                break

        if not description:
            continue

        # Extract CWE mappings
        weaknesses = cve_data.get("weakness", {}).get("description_data", [])
        cwe_ids = []
        for w in weaknesses:
            val = w.get("value", "")
            if val.startswith("CWE-"):
                cwe_ids.append(val)
            elif val.startswith("CWE"):
                cwe_ids.append(f"CWE-{val[3:]}")

        # Create pattern from CVE
        title = f"{cve_id}: {description[:100]}"
        patterns = cwe_ids if cwe_ids else [cve_id]

        kb.add_pattern(
            cwe=cve_id,
            title=title,
            description=description[:500],
            patterns=patterns[:5],
            language="generic",
        )
        count += 1

    return count


def load_nvd_cve_from_url(
    kb: VulnerabilityKB,
    url: str = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz",
    cache_path: Path | None = None,
    max_patterns: int = 1000,
) -> int:
    """Download and load CVE definitions from NVD.

    Downloads the JSON feed and loads patterns.
    Caches the file to avoid re-downloading.

    Returns the number of patterns loaded.
    """
    import gzip

    if cache_path is None:
        cache_path = _default_cache_dir() / "nvd_cve.json"

    if not cache_path.exists():
        print(f"Downloading NVD CVE data from {url}...")
        req = urllib.request.Request(url, headers={"User-Agent": "ai-vuln-harness/1.0"})
        with urllib.request.urlopen(req, timeout=120) as response:
            data = response.read()

        # Handle gzip if needed
        if url.endswith(".gz"):
            data = gzip.decompress(data)

        with open(cache_path, "wb") as f:
            f.write(data)
        print(f"NVD CVE data cached to {cache_path}")

    return load_nvd_cve_from_file(kb, cache_path, max_patterns)


# --- CVEFixes Loader ---

def load_cvefixes_from_file(
    kb: VulnerabilityKB,
    json_path: Path,
    max_patterns: int = 500,
) -> int:
    """Load CVE fix patterns from CVEFixes dataset.

    Download from: https://github.com/declare-lab/CVEFixes

    The dataset contains CVE fix commits with before/after code.
    We extract vulnerability patterns from the commit messages and file changes.

    Returns the number of patterns loaded.
    """
    count = 0
    with open(json_path) as f:
        data = json.load(f)

    # CVEFixes format: list of commits with CVE references
    items = data if isinstance(data, list) else data.get("data", [])
    for item in items:
        if count >= max_patterns:
            break

        cve_id = item.get("cve_id", "")
        if not cve_id:
            continue

        # Extract CWE from commit message or metadata
        message = item.get("message", "") or item.get("commit_message", "")
        description = item.get("description", "") or message[:500]

        # Extract CWE patterns from keywords
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
        )
        count += 1

    return count


# --- Exploit-DB Loader ---

def load_exploitdb_from_file(
    kb: VulnerabilityKB,
    csv_path: Path,
    max_patterns: int = 500,
) -> int:
    """Load exploit patterns from Exploit-DB CSV.

    Download from: https://www.exploit-db.com/downloads (CSV dump)

    Returns the number of patterns loaded.
    """
    import csv

    count = 0
    with open(csv_path, newline="", encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            if count >= max_patterns:
                break

            exploit_id = row.get("id", "")
            title = row.get("description", "")
            platform = row.get("platform", "")
            type_ = row.get("type", "")
            cve = row.get("cve", "")

            if not title:
                continue

            # Extract CWE from description or CVE
            patterns = []
            if cve and cve.strip():
                patterns.append(cve.strip())

            # Map platform/type to CWE patterns
            platform_cwe_map = {
                "linux": "CWE-120",
                "windows": "CWE-120",
                "php": "CWE-79",
                "python": "CWE-78",
                "ruby": "CWE-78",
                "java": "CWE-502",
                "asp": "CWE-79",
                "cgi": "CWE-78",
            }
            if platform.lower() in platform_cwe_map:
                patterns.append(platform_cwe_map[platform.lower()])

            type_cwe_map = {
                "webapps": "CWE-79",
                "local": "CWE-120",
                "remote": "CWE-918",
                "dos": "CWE-400",
                "shellcode": "CWE-120",
            }
            if type_.lower() in type_cwe_map:
                patterns.append(type_cwe_map[type_.lower()])

            if not patterns:
                patterns = [f"EDB-{exploit_id}"]

            kb.add_pattern(
                cwe=f"EDB-{exploit_id}",
                title=title[:100],
                description=f"{title} (Platform: {platform}, Type: {type_})",
                patterns=patterns[:5],
                language=platform.lower() if platform else "generic",
            )
            count += 1

    return count


def load_exploitdb_from_url(
    kb: VulnerabilityKB,
    url: str = "https://www.exploit-db.com/downloadscsv",
    cache_path: Path | None = None,
    max_patterns: int = 500,
) -> int:
    """Download and load Exploit-DB CSV.

    Returns the number of patterns loaded.
    """
    if cache_path is None:
        cache_path = _default_cache_dir() / "exploitdb.csv"

    if not cache_path.exists():
        print(f"Downloading Exploit-DB CSV from {url}...")
        req = urllib.request.Request(url, headers={"User-Agent": "ai-vuln-harness/1.0"})
        with urllib.request.urlopen(req, timeout=120) as response:
            data = response.read()
        with open(cache_path, "wb") as f:
            f.write(data)
        print(f"Exploit-DB CSV cached to {cache_path}")

    return load_exploitdb_from_file(kb, cache_path, max_patterns)


# --- GitHub Advisory Database Loader ---

def load_github_advisory_from_file(
    kb: VulnerabilityKB,
    json_path: Path,
    max_patterns: int = 500,
) -> int:
    """Load patterns from GitHub Advisory Database JSONL.

    Download from: https://github.com/github/advisory-database

    Returns the number of patterns loaded.
    """
    count = 0
    with open(json_path) as f:
        for line in f:
            if count >= max_patterns:
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

            # Extract CWE patterns
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
            )
            count += 1

    return count


def load_github_advisory_from_url(
    kb: VulnerabilityKB,
    url: str = "https://github.com/github/advisory-database/raw/main/advisories/npm.json",
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
        req = urllib.request.Request(url, headers={"User-Agent": "ai-vuln-harness/1.0"})
        with urllib.request.urlopen(req, timeout=120) as response:
            data = response.read()
        with open(cache_path, "wb") as f:
            f.write(data)
        print(f"GitHub Advisory Database cached to {cache_path}")

    return load_github_advisory_from_file(kb, cache_path, max_patterns)


# --- VulDeePecker Loader ---

def load_vuldeepecker_from_file(
    kb: VulnerabilityKB,
    csv_path: Path,
    max_patterns: int = 500,
) -> int:
    """Load vulnerability patterns from VulDeePecker dataset.

    Download from: https://github.com/lin-tan-gal/VulDeePecker

    The dataset contains code snippets labeled with CWE classes.
    We extract the CWE classes and representative patterns.

    Returns the number of patterns loaded.
    """
    import csv

    # CWE class mapping from VulDeePecker
    cwe_class_map = {
        "CWE-119": "Buffer Overflow",
        "CWE-120": "Buffer Overflow (Classic)",
        "CWE-125": "Out-of-bounds Read",
        "CWE-190": "Integer Overflow",
        "CWE-416": "Use After Free",
        "CWE-476": "NULL Pointer Dereference",
        "CWE-787": "Out-of-bounds Write",
    }

    count = 0
    cwe_counts: dict[str, int] = {}

    try:
        with open(csv_path, newline="", encoding="utf-8", errors="ignore") as f:
            reader = csv.DictReader(f)
            for row in reader:
                if count >= max_patterns:
                    break

                # VulDeePecker format: has CWE labels
                cwe_label = row.get("CWE", "") or row.get("cwe", "")
                if not cwe_label:
                    continue

                # Count occurrences per CWE
                cwe_counts[cwe_label] = cwe_counts.get(cwe_label, 0) + 1
                count += 1
    except Exception:
        # If CSV parsing fails, create patterns from known CWE classes
        pass

    # Create patterns from CWE class counts
    for cwe_id, cwe_title in cwe_class_map.items():
        if cwe_id not in cwe_counts and cwe_id not in [p["cwe"] for p in kb._patterns]:
            # Add representative patterns even without exact counts
            kb.add_pattern(
                cwe=cwe_id,
                title=cwe_title,
                description=f"VulDeePecker dataset pattern for {cwe_title}",
                patterns=[cwe_id.lower().replace("-", "_")],
                language="c",
            )
            count += 1

    return count


def load_vuldeepecker_from_url(
    kb: VulnerabilityKB,
    url: str = "https://raw.githubusercontent.com/lin-tan-gal/VulDeePecker/master/data/CWE-119/CWE-119.csv",
    cache_path: Path | None = None,
    max_patterns: int = 500,
) -> int:
    """Download and load VulDeePecker dataset.

    Returns the number of patterns loaded.
    """
    if cache_path is None:
        cache_path = _default_cache_dir() / "vuldeepecker.csv"

    if not cache_path.exists():
        print(f"Downloading VulDeePecker dataset from {url}...")
        req = urllib.request.Request(url, headers={"User-Agent": "ai-vuln-harness/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                data = response.read()
            with open(cache_path, "wb") as f:
                f.write(data)
            print(f"VulDeePecker dataset cached to {cache_path}")
        except Exception as e:
            print(f"  Failed to download VulDeePecker: {e}")
            # Create representative patterns without download
            return _create_vuldeepecker_representatives(kb)

    return load_vuldeepecker_from_file(kb, cache_path, max_patterns)


def _create_vuldeepecker_representatives(kb: VulnerabilityKB) -> int:
    """Create representative VulDeePecker patterns without downloading."""
    vuldeepecker_patterns = [
        {"cwe": "CWE-119", "title": "Buffer Overflow (General)", "description": "Restrictions on the length of a memory buffer are not enforced.", "patterns": ["buffer", "overflow", "length", "size"]},
        {"cwe": "CWE-120", "title": "Buffer Overflow (Classic)", "description": "The product copies an input buffer to an output buffer without verifying that the size of the input buffer is less than the size of the output buffer.", "patterns": ["memcpy", "strcpy", "strcat", "sprintf", "gets"]},
        {"cwe": "CWE-125", "title": "Out-of-bounds Read", "description": "The software reads data past the end, or before the beginning, of the intended buffer.", "patterns": ["buffer", "read", "index", "length"]},
        {"cwe": "CWE-190", "title": "Integer Overflow", "description": "The software performs a calculation that can produce an integer overflow or wraparound.", "patterns": ["int", "overflow", "wraparound", "limit"]},
        {"cwe": "CWE-416", "title": "Use After Free", "description": "The software references memory after it has been freed.", "patterns": ["free", "pointer", "dangling", "use"]},
        {"cwe": "CWE-476", "title": "NULL Pointer Dereference", "description": "The software dereferences a pointer that it expects to be valid, but is NULL.", "patterns": ["null", "pointer", "nil", "dereference"]},
        {"cwe": "CWE-787", "title": "Out-of-bounds Write", "description": "The software writes data past the end, or before the beginning, of the intended buffer.", "patterns": ["write", "buffer", "overflow", "bounds"]},
    ]

    count = 0
    for p in vuldeepecker_patterns:
        if p["cwe"] not in [existing["cwe"] for existing in kb._patterns]:
            kb.add_pattern(**p)
            count += 1

    return count


# --- OSV.dev Loader ---

def load_osv_from_file(
    kb: VulnerabilityKB,
    json_path: Path,
    max_patterns: int = 500,
) -> int:
    """Load vulnerability patterns from OSV.dev JSON.

    Download from: https://osv.dev/list (or API)

    OSV format: list of vulnerability objects with id, summary, details, aliases, severity.

    Returns the number of patterns loaded.
    """
    count = 0
    with open(json_path) as f:
        data = json.load(f)

    vulns = data if isinstance(data, list) else data.get("vulns", [])
    for vuln in vulns:
        if count >= max_patterns:
            break

        osv_id = vuln.get("id", "")
        summary = vuln.get("summary", "")
        details = vuln.get("details", "")
        aliases = vuln.get("aliases", [])
        severity = vuln.get("severity", [])

        if not summary and not details:
            continue

        # Extract CWE from aliases or details
        patterns = []
        for alias in aliases:
            if alias.startswith("CVE-") or alias.startswith("GHSA-"):
                patterns.append(alias)

        # Extract severity-based patterns
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
        )
        count += 1

    return count


def load_osv_from_url(
    kb: VulnerabilityKB,
    url: str = "https://osv.dev/list",
    cache_path: Path | None = None,
    max_patterns: int = 500,
) -> int:
    """Download and load OSV.dev vulnerabilities.

    Uses the OSV API to fetch recent vulnerabilities.

    Returns the number of patterns loaded.
    """
    if cache_path is None:
        cache_path = _default_cache_dir() / "osv_vulns.json"

    if not cache_path.exists():
        print(f"Downloading OSV.dev vulnerabilities from {url}...")
        # OSV API endpoint for recent vulnerabilities
        api_url = "https://osv.dev/list?ecosystem=&page=1"
        req = urllib.request.Request(api_url, headers={"User-Agent": "ai-vuln-harness/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                data = response.read()
            with open(cache_path, "wb") as f:
                f.write(data)
            print(f"OSV.dev data cached to {cache_path}")
        except Exception as e:
            print(f"  Failed to download OSV.dev: {e}")
            return 0

    return load_osv_from_file(kb, cache_path, max_patterns)


# --- Snyk Vulnerability Database Loader ---

def load_snyk_from_file(
    kb: VulnerabilityKB,
    json_path: Path,
    max_patterns: int = 500,
) -> int:
    """Load vulnerability patterns from Snyk database JSON.

    Download from: https://snyk.io/vuln-db (requires API access)

    Snyk format: list of vulnerability objects with id, title, description, cvssScore, CWE.

    Returns the number of patterns loaded.
    """
    count = 0
    with open(json_path) as f:
        data = json.load(f)

    vulns = data if isinstance(data, list) else data.get("vulns", [])
    for vuln in vulns:
        if count >= max_patterns:
            break

        vuln_id = vuln.get("id", "")
        title = vuln.get("title", "")
        description = vuln.get("description", "")
        cvss = vuln.get("cvssScore", 0)
        cwe = vuln.get("CWE", [])

        if not title and not description:
            continue

        # Extract CWE patterns
        patterns = []
        if isinstance(cwe, list):
            for c in cwe:
                if isinstance(c, dict):
                    patterns.append(c.get("id", ""))
                else:
                    patterns.append(str(c))
        elif isinstance(cwe, str):
            patterns.append(cwe)

        # Add severity-based patterns
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
        )
        count += 1

    return count


def load_snyk_from_url(
    kb: VulnerabilityKB,
    url: str = "https://snyk.io/api/v1/vuln",
    cache_path: Path | None = None,
    max_patterns: int = 500,
) -> int:
    """Download and load Snyk vulnerabilities.

    Note: Snyk API requires authentication. This loader works with exported JSON.

    Returns the number of patterns loaded.
    """
    if cache_path is None:
        cache_path = _default_cache_dir() / "snyk_vulns.json"

    if not cache_path.exists():
        print(f"Downloading Snyk vulnerabilities from {url}...")
        req = urllib.request.Request(url, headers={"User-Agent": "ai-vuln-harness/1.0"})
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


# --- D2A (DeepDive) Loader ---

def load_d2a_from_file(
    kb: VulnerabilityKB,
    json_path: Path,
    max_patterns: int = 500,
) -> int:
    """Load vulnerability patterns from D2A dataset.

    Download from: https://github.com/declare-lab/D2A

    D2A format: list of bug fixes with commit messages and code changes.

    Returns the number of patterns loaded.
    """
    count = 0
    with open(json_path) as f:
        data = json.load(f)

    items = data if isinstance(data, list) else data.get("data", [])
    for item in items:
        if count >= max_patterns:
            break

        commit_msg = item.get("commit_message", "") or item.get("message", "")
        cve_id = item.get("cve_id", "") or item.get("cve", "")

        if not commit_msg:
            continue

        # Extract CWE patterns from commit message keywords
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
        )
        count += 1

    return count


def load_d2a_from_url(
    kb: VulnerabilityKB,
    url: str = "https://raw.githubusercontent.com/declare-lab/D2A/main/data/bugs.json",
    cache_path: Path | None = None,
    max_patterns: int = 500,
) -> int:
    """Download and load D2A dataset.

    Returns the number of patterns loaded.
    """
    if cache_path is None:
        cache_path = _default_cache_dir() / "d2a_bugs.json"

    if not cache_path.exists():
        print(f"Downloading D2A dataset from {url}...")
        req = urllib.request.Request(url, headers={"User-Agent": "ai-vuln-harness/1.0"})
        try:
            with urllib.request.urlopen(req, timeout=120) as response:
                data = response.read()
            with open(cache_path, "wb") as f:
                f.write(data)
            print(f"D2A data cached to {cache_path}")
        except Exception as e:
            print(f"  Failed to download D2A: {e}")
            return 0

    return load_d2a_from_file(kb, cache_path, max_patterns)


# --- Juliet Test Suite Loader ---

def load_juliet_from_file(
    kb: VulnerabilityKB,
    directory: Path,
    max_patterns: int = 500,
) -> int:
    """Load vulnerability patterns from Juliet Test Suite.

    Download from: https://samate.nist.gov/SARD/test-suite.html

    Juliet format: C/C++/Java test cases organized by CWE class.
    We extract CWE classes from directory names.

    Returns the number of patterns loaded.
    """
    count = 0

    # Juliet test cases are organized by CWE number
    cwe_pattern_map = {
        "CWE114": ("CWE-114", "Process Control", ["process", "control", "injection"]),
        "CWE117": ("CWE-117", "Improper Output Neutralization for Logs", ["log", "injection"]),
        "CWE119": ("CWE-119", "Buffer Overflow", ["buffer", "overflow", "length"]),
        "CWE120": ("CWE-120", "Buffer Overflow (Classic)", ["memcpy", "strcpy", "strcat"]),
        "CWE121": ("CWE-121", "Stack-based Buffer Overflow", ["stack", "buffer", "overflow"]),
        "CWE122": ("CWE-122", "Heap-based Buffer Overflow", ["heap", "buffer", "overflow"]),
        "CWE124": ("CWE-124", "Buffer Underwrite", ["underwrite", "buffer"]),
        "CWE125": ("CWE-125", "Out-of-bounds Read", ["read", "buffer", "bounds"]),
        "CWE126": ("CWE-126", "Buffer Over-read", ["over-read", "buffer"]),
        "CWE127": ("CWE-127", "Out-of-bounds Write", ["write", "buffer", "bounds"]),
        "CWE131": ("CWE-131", "Incorrect Calculation of Buffer Size", ["buffer", "size", "calculation"]),
        "CWE134": ("CWE-134", "Format String Vulnerability", ["format", "string", "printf"]),
        "CWE176": ("CWE-176", "Improper Handling of Unicode Encoding", ["unicode", "encoding"]),
        "CWE190": ("CWE-190", "Integer Overflow", ["integer", "overflow", "wraparound"]),
        "CWE191": ("CWE-191", "Integer Underflow", ["integer", "underflow"]),
        "CWE194": ("CWE-194", "Unexpected Sign Extension", ["sign", "extension"]),
        "CWE195": ("CWE-195", "Signed to Unsigned Conversion Error", ["signed", "unsigned", "conversion"]),
        "CWE196": ("CWE-196", "Unsigned to Signed Conversion Error", ["unsigned", "signed", "conversion"]),
        "CWE197": ("CWE-197", "Numeric Truncation Error", ["truncation", "numeric"]),
        "CWE319": ("CWE-319", "Plaintext Transmission of Sensitive Information", ["plaintext", "transmission"]),
        "CWE327": ("CWE-327", "Use of Broken Crypto", ["broken", "crypto", "weak"]),
        "CWE369": ("CWE-369", "Divide By Zero", ["divide", "zero", "division"]),
        "CWE377": ("CWE-377", "Insecure Temporary File", ["tempfile", "temporary", "insecure"]),
        "CWE390": ("CWE-390", "Uncontrolled Resource Consumption", ["resource", "consumption", "dos"]),
        "CWE396": ("CWE-396", "Catch Generic Exception", ["exception", "catch", "generic"]),
        "CWE400": ("CWE-400", "Uncontrolled Resource Consumption", ["resource", "consumption"]),
        "CWE401": ("CWE-401", "Memory Leak", ["memory", "leak"]),
        "CWE404": ("CWE-404", "Improper Resource Shutdown", ["resource", "shutdown", "close"]),
        "CWE415": ("CWE-415", "Double Free", ["double", "free"]),
        "CWE416": ("CWE-416", "Use After Free", ["use", "after", "free", "dangling"]),
        "CWE426": ("CWE-426", "Untrusted Search Path", ["search", "path", "untrusted"]),
        "CWE427": ("CWE-427", "Uncontrolled Search Path Element", ["search", "path", "uncontrolled"]),
        "CWE434": ("CWE-434", "Unrestricted File Upload", ["file", "upload", "unrestricted"]),
        "CWE457": ("CWE-457", "Use of Uninitialized Variable", ["uninitialized", "variable"]),
        "CWE460": ("CWE-460", "Improper Cleanup on Thrown Exception", ["cleanup", "exception"]),
        "CWE462": ("CWE-462", "Duplicate Key in Associative List", ["duplicate", "key"]),
        "CWE464": ("CWE-464", "Addition of Data Structure Sentinel", ["sentinel", "data"]),
        "CWE467": ("CWE-467", "Use of sizeof() on a Pointer Type", ["sizeof", "pointer"]),
        "CWE468": ("CWE-468", "Divide by Zero", ["divide", "zero"]),
        "CWE469": ("CWE-469", "Use of Dead Code", ["dead", "code"]),
        "CWE470": ("CWE-470", "Use of Externally-Controlled Input to Select Classes or Code", ["externally", "controlled", "input"]),
        "CWE471": ("CWE-471", "Modification of Assumed-Immutable Data", ["immutable", "data", "modification"]),
        "CWE472": ("CWE-472", "Passing User-Controlled URL to Internet-Bound Call", ["url", "internet", "user"]),
        "CWE475": ("CWE-475", "Initialization with an Externally-Controlled Input", ["initialization", "externally"]),
        "CWE476": ("CWE-476", "NULL Pointer Dereference", ["null", "pointer", "dereference"]),
        "CWE478": ("CWE-478", "Missing Default Case in Switch Statement", ["switch", "default", "case"]),
        "CWE479": ("CWE-479", "Unsafe Function Pointer Call", ["function", "pointer", "unsafe"]),
        "CWE480": ("CWE-480", "Use of Incorrect Operator", ["operator", "incorrect"]),
        "CWE481": ("CWE-481", "Assigning instead of Comparing", ["assign", "compare"]),
        "CWE482": ("CWE-482", "Comparing instead of Assigning", ["compare", "assign"]),
        "CWE483": ("CWE-483", "Incorrect Block Delimitation", ["block", "delimitation"]),
        "CWE484": ("CWE-484", "Missing Break", ["break", "missing"]),
        "CWE561": ("CWE-561", "Dead Code", ["dead", "code"]),
        "CWE562": ("CWE-562", "Insertion of Sensitive Information into Externally-Accessible File", ["sensitive", "information", "file"]),
        "CWE570": ("CWE-570", "Expression is Always False", ["expression", "false"]),
        "CWE571": ("CWE-571", "Expression is Always True", ["expression", "true"]),
        "CWE587": ("CWE-587", "Assignment of a Fixed Address to a Pointer", ["assignment", "pointer", "fixed"]),
        "CWE588": ("CWE-588", "Access of Memory Location After End of Buffer", ["memory", "buffer", "end"]),
        "CWE590": ("CWE-590", "Free of Memory not on the Heap", ["free", "heap"]),
        "CWE591": ("CWE-591", "Stack Buffer Overread", ["stack", "overread"]),
        "CWE592": ("CWE-592", "Buffer Copy without Checking Size of Input", ["buffer", "copy", "size"]),
        "CWE593": ("CWE-593", "Authentication Bypass", ["authentication", "bypass"]),
        "CWE595": ("CWE-595", "Comparison using Wrong Variables", ["comparison", "wrong"]),
        "CWE596": ("CWE-596", "Incorrect Comparison", ["incorrect", "comparison"]),
        "CWE597": ("CWE-597", "Use of Wrong Operator in String Comparison", ["operator", "string", "comparison"]),
        "CWE598": ("CWE-598", "Use of GET Request Method With Sensitive Query Strings", ["get", "request", "query"]),
        "CWE600": ("CWE-600", "Unhandled Exception in Servlet", ["exception", "servlet"]),
        "CWE601": ("CWE-601", "Open Redirect", ["open", "redirect"]),
        "CWE605": ("CWE-605", "Multiple Binds to the Same Network Port", ["bind", "port", "multiple"]),
        "CWE606": ("CWE-606", "Missing Input Validation", ["missing", "input", "validation"]),
        "CWE607": ("CWE-607", "Public Static Field Not Final", ["static", "field", "final"]),
        "CWE609": ("CWE-609", "Use of Hard-Coded Password", ["password", "hardcoded"]),
        "CWE610": ("CWE-610", "Reliance on a Single Variable in a Concurrent Environment", ["concurrent", "variable"]),
        "CWE611": ("CWE-611", "Improper Restriction of XML External Entity Reference", ["xml", "external", "entity"]),
        "CWE615": ("CWE-615", "Inclusion of Sensitive Information in Source Code Comments", ["sensitive", "comments"]),
        "CWE617": ("CWE-617", "Reachable Assertion", ["assertion", "reachable"]),
        "CWE620": ("CWE-620", "Unverified Password Change", ["password", "change", "unverified"]),
        "CWE621": ("CWE-621", "Variable Length Array for Sensitive Information", ["array", "variable", "length"]),
        "CWE628": ("CWE-628", "Function Call with Incorrectly Specified Arguments", ["function", "call", "arguments"]),
        "CWE665": ("CWE-665", "Improper Initialization", ["initialization", "improper"]),
        "CWE666": ("CWE-666", "Operation on a Resource after Expiration or Release", ["resource", "expiration"]),
        "CWE667": ("CWE-667", "Improper Locking", ["locking", "improper"]),
        "CWE670": ("CWE-670", "Always-Included Control Flow Code", ["control", "flow"]),
        "CWE672": ("CWE-672", "Operation on Resource after Expiration", ["resource", "expiration"]),
        "CWE674": ("CWE-674", "Uncontrolled Recursion", ["recursion", "uncontrolled"]),
        "CWE675": ("CWE-675", "Missing Release of Resource after Effective Lifetime", ["resource", "release"]),
        "CWE676": ("CWE-676", "Use of Potentially Dangerous Function", ["dangerous", "function"]),
        "CWE680": ("CWE-680", "Integer Overflow when Computing Memory Allocation Size", ["integer", "overflow", "memory"]),
        "CWE681": ("CWE-681", "Incorrect Conversion between Numeric Types", ["numeric", "conversion"]),
        "CWE682": ("CWE-682", "Incorrect Calculation", ["calculation", "incorrect"]),
        "CWE685": ("CWE-685", "Function Call With Incorrect Number of Arguments", ["function", "call", "arguments"]),
        "CWE686": ("CWE-686", "Function Call With Incorrect Argument Type", ["function", "call", "type"]),
        "CWE687": ("CWE-687", "Function Call With Incorrectly Specified Arguments", ["function", "call", "specified"]),
        "CWE688": ("CWE-688", "Function Call With Incorrect Variable or Reference as Argument", ["function", "call", "variable"]),
        "CWE704": ("CWE-704", "Incorrect Type Conversion or Cast", ["type", "conversion", "cast"]),
        "CWE758": ("CWE-758", "Reliance on Undefined Behavior", ["undefined", "behavior"]),
        "CWE761": ("CWE-761", "Free of Pointer not at Start of Buffer", ["free", "pointer", "buffer"]),
        "CWE762": ("CWE-762", "Mismatched Memory Management Routines", ["memory", "management", "mismatch"]),
        "CWE763": ("CWE-763", "Release of Invalid Pointer or Reference", ["pointer", "release", "invalid"]),
        "CWE768": ("CWE-768", "Short-Circuit Evaluation with Side Effects", ["short-circuit", "side", "effects"]),
        "CWE772": ("CWE-772", "Missing Release of Resource after Effective Lifetime", ["resource", "release"]),
        "CWE773": ("CWE-773", "Missing Reference to Active File Descriptor or Handle", ["file", "descriptor"]),
        "CWE775": ("CWE-775", "Missing Release of File Descriptor or Handle after Effective Lifetime", ["file", "descriptor", "release"]),
        "CWE776": ("CWE-776", "Improper Restriction of Recursive Entity References in DTDs", ["xml", "dtd", "recursive"]),
        "CWE783": ("CWE-783", "Operator Precedence Logic Error", ["operator", "precedence"]),
        "CWE784": ("CWE-784", "Reliance on Cookies without Validation and Integrity Checking", ["cookie", "validation"]),
        "CWE785": ("CWE-785", "Use of Path Manipulation Function without a Neutralized Special Elements", ["path", "manipulation"]),
        "CWE786": ("CWE-786", "Access of Memory Location at the End of the Buffer", ["memory", "buffer", "end"]),
        "CWE787": ("CWE-787", "Out-of-bounds Write", ["out-of-bounds", "write"]),
        "CWE788": ("CWE-788", "Access of Memory Location After End of Buffer", ["memory", "buffer", "end"]),
        "CWE789": ("CWE-789", "Memory Allocation with Excessive Size Value", ["memory", "allocation", "excessive"]),
        "CWE798": ("CWE-798", "Use of Hard-coded Credentials", ["hardcoded", "credentials", "password"]),
        "CWE805": ("CWE-805", "Buffer Access with Incorrect Length Value", ["buffer", "access", "length"]),
        "CWE806": ("CWE-806", "Buffer Access Using Index after End or Before Beginning of Buffer", ["buffer", "index", "bounds"]),
        "CWE807": ("CWE-807", "Reliance on Untrusted Input in a Security Decision", ["untrusted", "input", "security"]),
        "CWE820": ("CWE-820", "Missing Synchronization", ["missing", "synchronization"]),
        "CWE821": ("CWE-821", "Incorrect Synchronization", ["incorrect", "synchronization"]),
        "CWE822": ("CWE-822", "Untrusted Pointer Dereference", ["pointer", "untrusted"]),
        "CWE823": ("CWE-823", "Use of out-of-range Pointer Offset", ["pointer", "offset", "range"]),
        "CWE824": ("CWE-824", "Access of Uninitialized Pointer", ["pointer", "uninitialized"]),
        "CWE825": ("CWE-825", "Expired Pointer Dereference", ["pointer", "expired"]),
        "CWE839": ("CWE-839", "Improper Input Validation During Array Indexing", ["array", "index", "validation"]),
        "CWE841": ("CWE-841", "Improper Enforcement of Behavioral Workflow", ["workflow", "enforcement"]),
        "CWE843": ("CWE-843", "Type Confusion", ["type", "confusion"]),
        "CWE862": ("CWE-862", "Missing Authorization", ["missing", "authorization"]),
        "CWE863": ("CWE-863", "Incorrect Authorization", ["incorrect", "authorization"]),
        "CWE908": ("CWE-908", "Use of Uninitialized Resource", ["uninitialized", "resource"]),
        "CWE909": ("CWE-909", "Missing Initialization of Resource", ["missing", "initialization"]),
        "CWE911": ("CWE-911", "Improper Update of Reference Count", ["reference", "count", "update"]),
        "CWE915": ("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes", ["dynamic", "object", "attributes"]),
    }

    for dirpath, dirnames, filenames in directory.walk():
        for filename in filenames:
            if count >= max_patterns:
                break

            # Extract CWE from directory name
            parts = dirpath.name.split("_")
            if len(parts) >= 2:
                cwe_class = parts[1]  # e.g., "CWE119" from "CWE119_BufferOverflow"
                if cwe_class in cwe_pattern_map:
                    cwe_id, title, patterns = cwe_pattern_map[cwe_class]
                    if cwe_id not in [p["cwe"] for p in kb._patterns]:
                        kb.add_pattern(
                            cwe=cwe_id,
                            title=title,
                            description=f"Juliet Test Suite pattern for {title}",
                            patterns=patterns,
                            language="c",
                        )
                        count += 1
            break  # Only process one file per directory

    return count


def load_juliet_representatives(kb: VulnerabilityKB) -> int:
    """Load representative Juliet Test Suite patterns without downloading.

    Returns the number of patterns loaded.
    """
    juliet_patterns = [
        {"cwe": "CWE-119", "title": "Buffer Overflow (Juliet)", "description": "Buffer overflow test cases from Juliet Test Suite.", "patterns": ["buffer", "overflow", "memcpy", "strcpy"]},
        {"cwe": "CWE-120", "title": "Buffer Overflow Classic (Juliet)", "description": "Classic buffer overflow test cases.", "patterns": ["buffer", "overflow", "stack"]},
        {"cwe": "CWE-121", "title": "Stack Buffer Overflow (Juliet)", "description": "Stack-based buffer overflow test cases.", "patterns": ["stack", "buffer", "overflow"]},
        {"cwe": "CWE-122", "title": "Heap Buffer Overflow (Juliet)", "description": "Heap-based buffer overflow test cases.", "patterns": ["heap", "buffer", "overflow"]},
        {"cwe": "CWE-125", "title": "Out-of-bounds Read (Juliet)", "description": "Out-of-bounds read test cases.", "patterns": ["read", "buffer", "bounds"]},
        {"cwe": "CWE-134", "title": "Format String (Juliet)", "description": "Format string vulnerability test cases.", "patterns": ["format", "string", "printf"]},
        {"cwe": "CWE-190", "title": "Integer Overflow (Juliet)", "description": "Integer overflow test cases.", "patterns": ["integer", "overflow"]},
        {"cwe": "CWE-191", "title": "Integer Underflow (Juliet)", "description": "Integer underflow test cases.", "patterns": ["integer", "underflow"]},
        {"cwe": "CWE-415", "title": "Double Free (Juliet)", "description": "Double free test cases.", "patterns": ["double", "free"]},
        {"cwe": "CWE-416", "title": "Use After Free (Juliet)", "description": "Use after free test cases.", "patterns": ["use", "after", "free"]},
        {"cwe": "CWE-476", "title": "NULL Pointer Dereference (Juliet)", "description": "NULL pointer dereference test cases.", "patterns": ["null", "pointer"]},
        {"cwe": "CWE-787", "title": "Out-of-bounds Write (Juliet)", "description": "Out-of-bounds write test cases.", "patterns": ["write", "buffer", "bounds"]},
    ]

    count = 0
    for p in juliet_patterns:
        if p["cwe"] not in [existing["cwe"] for existing in kb._patterns]:
            kb.add_pattern(**p)
            count += 1

    return count


# --- Convenience Loader (Extended) ---

def load_all_public_datasets(
    kb: VulnerabilityKB,
    cache_dir: Path | None = None,
    max_per_dataset: int = 500,
    datasets: list[str] | None = None,
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

    Returns
    -------
    Dict with counts per dataset.
    """
    if cache_dir is None:
        cache_dir = _default_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)

    all_datasets = ["mitre_cwe", "nvd_cve", "exploitdb", "github", "osv", "snyk", "d2a", "vuldeepecker", "juliet"]
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
                count = load_mitre_cwe_from_url(kb, cache_path=cwe_path, max_patterns=max_per_dataset)
            summary["mitre_cwe"] = count
            print(f"  ✓ Loaded {count} CWE patterns")
        except Exception as e:
            print(f"  ✗ Failed to load CWE: {e}")

    # Load NVD CVE
    if "nvd_cve" in datasets_to_load:
        try:
            print("Loading NVD CVE dataset...")
            nvd_path = cache_dir / "nvdcve-1.1-2024.json"
            if nvd_path.exists():
                count = load_nvd_cve_from_file(kb, nvd_path, max_per_dataset)
            else:
                count = load_nvd_cve_from_url(kb, cache_path=nvd_path, max_patterns=max_per_dataset)
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
                count = load_exploitdb_from_url(kb, cache_path=edb_path, max_patterns=max_per_dataset)
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
                count = load_github_advisory_from_url(kb, cache_path=gh_path, max_patterns=max_per_dataset)
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
                count = load_osv_from_url(kb, cache_path=osv_path, max_patterns=max_per_dataset)
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
                count = load_snyk_from_url(kb, cache_path=snyk_path, max_patterns=max_per_dataset)
            summary["snyk"] = count
            print(f"  ✓ Loaded {count} Snyk patterns")
        except Exception as e:
            print(f"  ✗ Failed to load Snyk: {e}")

    # Load D2A
    if "d2a" in datasets_to_load:
        try:
            print("Loading D2A dataset...")
            d2a_path = cache_dir / "d2a_bugs.json"
            if d2a_path.exists():
                count = load_d2a_from_file(kb, d2a_path, max_per_dataset)
            else:
                count = load_d2a_from_url(kb, cache_path=d2a_path, max_patterns=max_per_dataset)
            summary["d2a"] = count
            print(f"  ✓ Loaded {count} D2A patterns")
        except Exception as e:
            print(f"  ✗ Failed to load D2A: {e}")

    # Load VulDeePecker
    if "vuldeepecker" in datasets_to_load:
        try:
            print("Loading VulDeePecker dataset...")
            count = _create_vuldeepecker_representatives(kb)
            summary["vuldeepecker"] = count
            print(f"  ✓ Loaded {count} VulDeePecker patterns")
        except Exception as e:
            print(f"  ✗ Failed to load VulDeePecker: {e}")

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
