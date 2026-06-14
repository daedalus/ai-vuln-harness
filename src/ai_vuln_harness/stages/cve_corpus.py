from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path

_CVE_CLASS_TO_DOMAIN: dict[str, str] = {
    "buffer-overflow": "mem-safety",
    "heap-overflow": "mem-safety",
    "stack-overflow": "mem-safety",
    "use-after-free": "mem-safety",
    "double-free": "mem-safety",
    "integer-overflow": "mem-safety",
    "integer-underflow": "mem-safety",
    "out-of-bounds": "mem-safety",
    "null-pointer": "mem-safety",
    "memory-leak": "resource",
    "fd-leak": "resource",
    "resource-exhaustion": "resource",
    "format-string": "format-str",
    "weak-crypto": "crypto",
    "iv-reuse": "crypto",
    "padding-oracle": "crypto",
    "hardcoded-key": "crypto",
    "entropy": "crypto",
    "auth-bypass": "auth",
    "privilege-escalation": "auth",
    "session-fixation": "auth",
    "command-injection": "injection",
    "sql-injection": "injection",
    "path-traversal": "path-traversal",
    "symlink": "path-traversal",
    "toctou": "ipc",
    "race-condition": "concurrency",
    "deadlock": "concurrency",
    "signal-safety": "concurrency",
    "untrusted-sink": "data-flow",
    "hardcoded-secret": "secrets",
    "credential-exposure": "secrets",
}


def _class_to_domain(class_name: str) -> str | None:
    norm = class_name.strip().lower().replace("_", "-").replace(" ", "-")
    return _CVE_CLASS_TO_DOMAIN.get(norm)


def load_cve_corpus(path: Path) -> list[dict]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, list):
        msg = f"cve_corpus: expected a JSON array, got {type(raw).__name__}"
        raise ValueError(msg)
    validated: list[dict] = []
    for i, entry in enumerate(raw):
        if not isinstance(entry, dict):
            msg = f"cve_corpus[{i}]: expected object, got {type(entry).__name__}"
            raise ValueError(msg)
        if "cve_id" not in entry:
            msg = f"cve_corpus[{i}]: missing required field 'cve_id'"
            raise ValueError(msg)
        validated.append(
            {
                "cve_id": str(entry["cve_id"]),
                "description": str(entry.get("description", "")),
                "class": str(entry.get("class", "")),
                "file": str(entry.get("file", "")),
                "function": str(entry.get("function", "")),
                "severity": str(entry.get("severity", "UNKNOWN")),
            }
        )
    return validated


def filter_cves_by_domain(corpus: list[dict], domain: str) -> list[dict]:
    if domain == "all":
        return corpus
    return [
        cve
        for cve in corpus
        if cve.get("class") and _class_to_domain(cve["class"]) == domain
    ]


def format_cve_entries(entries: list[dict]) -> str:
    if not entries:
        return "  (none)"
    lines = ["  Known CVEs in this domain (DO NOT report these as new findings):"]
    for e in entries:
        cve = e["cve_id"]
        desc = e["description"]
        cls = e["class"]
        lines.append(f"  - {cve} [{cls}]: {desc}")
    return "\n".join(lines)


def suppress_known_cves(
    findings: list[dict],
    corpus: list[dict],
) -> tuple[list[dict], list[dict]]:
    """Suppress findings that match known CVEs from the corpus.

    A finding is considered a known CVE match if:
    1. Its description contains a CVE ID that appears in the corpus, OR
    2. Its vuln_class matches a corpus entry's class AND its description
       shares significant keywords with the corpus entry's description.

    Parameters
    ----------
    findings:
        List of finding dicts from the hunt.
    corpus:
        List of CVE corpus entries (from ``load_cve_corpus`` or
        ``build_cve_corpus``).

    Returns
    -------
    ``(novel, known)`` — findings that are novel (potential zero days)
    and findings that match known CVEs (suppressed).
    """
    if not corpus:
        return findings, []

    # Build lookup structures from corpus
    corpus_cve_ids: set[str] = set()
    corpus_classes: dict[str, list[dict]] = {}
    corpus_desc_keywords: dict[str, set[str]] = {}

    for entry in corpus:
        cve_id = entry.get("cve_id", "")
        if cve_id:
            corpus_cve_ids.add(cve_id.upper())

        cls = entry.get("class", "").lower().strip()
        if cls:
            corpus_classes.setdefault(cls, []).append(entry)

        desc = entry.get("description", "").lower()
        if desc:
            keywords = set(w for w in desc.split() if len(w) > 3)
            corpus_desc_keywords.setdefault(cls, keywords)

    novel: list[dict] = []
    known: list[dict] = []

    for f in findings:
        is_known = False
        reason = ""

        # Check 1: finding mentions a known CVE ID
        f_desc = str(f.get("desc") or f.get("description") or "").upper()
        for cve_id in corpus_cve_ids:
            if cve_id in f_desc:
                is_known = True
                reason = f"matches known CVE {cve_id}"
                break

        # Check 2: same class + description keyword overlap
        if not is_known:
            f_class = str(f.get("class") or f.get("vuln_class") or "").lower().strip()
            f_desc_lower = str(f.get("desc") or f.get("description") or "").lower()
            f_words = set(w for w in f_desc_lower.split() if len(w) > 3)

            if f_class in corpus_classes:
                for entry in corpus_classes[f_class]:
                    entry_keywords = corpus_desc_keywords.get(f_class, set())
                    overlap = f_words & entry_keywords
                    # Require at least 3 keyword overlap to suppress
                    if len(overlap) >= 3:
                        is_known = True
                        reason = f"matches {entry.get('cve_id', '?')} (class={f_class}, keywords={overlap})"
                        break

        if is_known:
            f["suppressed_by_cve_corpus"] = True
            f["suppression_reason"] = reason
            known.append(f)
        else:
            novel.append(f)

    return novel, known
