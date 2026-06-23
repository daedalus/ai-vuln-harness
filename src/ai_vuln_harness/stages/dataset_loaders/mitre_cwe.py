"""MITRE CWE XML loader."""

from __future__ import annotations

import urllib.request
import xml.etree.ElementTree as ET  # noqa: N817
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

    from ..rag_kb import VulnerabilityKB

from .common import _default_cache_dir  # pylint: disable=wrong-import-position


# pylint: disable=too-many-branches
def load_mitre_cwe_from_file(  # noqa: MC0001
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

    weaknesses = []
    for elem in root.iter():
        local_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
        if local_name == "Weakness":
            weaknesses.append(elem)

    count = 0
    for weakness in weaknesses:
        if 0 < max_patterns <= count:
            break

        cwe_id = weakness.get("ID", "")
        if not cwe_id:
            continue

        name = weakness.get("Name", "")

        description = ""
        for elem in weakness:
            local_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if local_name == "Description" and elem.text:
                description = elem.text
                break
        if not description:
            description = name

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

        for elem in weakness:
            local_name = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
            if local_name == "Detection_Methods":
                for det in elem:
                    det_local = det.tag.split("}")[-1] if "}" in det.tag else det.tag
                    if det_local == "Detection_Method":
                        for method_elem in det:
                            method_local = (
                                method_elem.tag.split("}")[-1]
                                if "}" in method_elem.tag
                                else method_elem.tag
                            )
                            if method_local == "Method" and method_elem.text:
                                patterns.append(method_elem.text.strip())

        if not patterns:
            patterns = [name.lower()]

        kb.add_pattern(
            cwe=f"CWE-{cwe_id}",
            title=name,
            description=description[:500],
            patterns=patterns[:10],
            language="generic",
            persist=True,
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
