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
    threshold: float = 0.75,
) -> tuple[list[dict], list[dict]]:
    """Suppress findings that semantically match known CVEs from the corpus.

    Uses embedding cosine similarity to detect findings describing the same
    vulnerability as a known CVE, even when wording differs significantly.

    Matching strategy (in priority order):
    1. Exact CVE ID mention in description (fast path, no embeddings needed)
    2. Embedding cosine similarity >= threshold against any corpus entry

    Parameters
    ----------
    findings:
        List of finding dicts from the hunt.
    corpus:
        List of CVE corpus entries (from ``load_cve_corpus`` or
        ``build_cve_corpus``).
    threshold:
        Minimum cosine similarity for semantic match (default 0.75).

    Returns
    -------
    ``(novel, known)`` — findings that are novel (potential zero days)
    and findings that match known CVEs (suppressed).
    """
    if not corpus:
        return findings, []

    # --- Fast path: exact CVE ID match (no embeddings needed) ---
    corpus_cve_ids: set[str] = set()
    for entry in corpus:
        cve_id = entry.get("cve_id", "")
        if cve_id:
            corpus_cve_ids.add(cve_id.upper())

    novel: list[dict] = []
    known: list[dict] = []
    need_semantic: list[tuple[int, dict]] = []  # (index, finding)

    for idx, f in enumerate(findings):
        f_desc = str(f.get("desc") or f.get("description") or "").upper()
        matched = False
        for cve_id in corpus_cve_ids:
            if cve_id in f_desc:
                f["suppressed_by_cve_corpus"] = True
                f["suppression_reason"] = f"exact CVE ID match: {cve_id}"
                known.append(f)
                matched = True
                break
        if not matched:
            need_semantic.append((idx, f))

    # --- Semantic path: embedding cosine similarity ---
    if need_semantic:
        try:
            from ai_vuln_harness.stages.embeddings import EmbeddingIndex

            index = EmbeddingIndex()
            if not index.available:
                # No embeddings available — fall back to keyword matching
                novel.extend(f for _, f in need_semantic)
                return novel, known

            # Build text representations
            finding_texts = [
                f"{f.get('class', '')} {f.get('desc', '')} {f.get('description', '')}"
                for _, f in need_semantic
            ]
            corpus_texts = [
                f"{e.get('class', '')} {e.get('description', '')} {e.get('cve_id', '')}"
                for e in corpus
            ]

            # Encode all texts in one batch for efficiency
            all_texts = finding_texts + corpus_texts
            index.encode_findings([{"desc": t} for t in all_texts])
            all_embeddings = index._embeddings

            if all_embeddings is None or len(all_embeddings) == 0:
                novel.extend(f for _, f in need_semantic)
                return novel, known

            n_findings = len(finding_texts)
            finding_embs = all_embeddings[:n_findings]
            corpus_embs = all_embeddings[n_findings:]

            # Use FAISS for fast similarity search
            import faiss
            import numpy as np

            dim = finding_embs.shape[1]
            corpus_np = corpus_embs.astype("float32")
            faiss.normalize_L2(corpus_np)
            faiss_index = faiss.IndexFlatIP(dim)
            faiss_index.add(corpus_np)

            # Query each finding against corpus
            finding_np = finding_embs.astype("float32")
            faiss.normalize_L2(finding_np)
            k = min(len(corpus), 5)
            distances, indices = faiss_index.search(finding_np, k)

            for i, (orig_idx, f) in enumerate(need_semantic):
                matched = False
                for j in range(k):
                    sim = float(distances[i, j])
                    cve_idx = int(indices[i, j])
                    if cve_idx < 0 or cve_idx >= len(corpus):
                        continue
                    if sim >= threshold:
                        entry = corpus[cve_idx]
                        f["suppressed_by_cve_corpus"] = True
                        f["suppression_reason"] = (
                            f"semantic match: {entry.get('cve_id', '?')} "
                            f"(similarity={sim:.3f})"
                        )
                        known.append(f)
                        matched = True
                        break
                if not matched:
                    novel.append(f)

        except ImportError:
            # Embeddings not available — pass through
            novel.extend(f for _, f in need_semantic)

    return novel, known
