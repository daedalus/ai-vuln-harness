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
