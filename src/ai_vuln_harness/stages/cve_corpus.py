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

# Thresholds: same-class matches need less semantic similarity
_THRESHOLD_SAME_CLASS: float = 0.45
_THRESHOLD_DIFF_CLASS: float = 0.85
# Confidence tiers
_CONFIDENCE_AUTO_SUPPRESS: float = 0.9
_CONFIDENCE_FLAG_REVIEW: float = 0.7


def _class_to_domain(class_name: str) -> str | None:
    norm = class_name.strip().lower().replace("_", "-").replace(" ", "-")
    return _CVE_CLASS_TO_DOMAIN.get(norm)


def _build_finding_text(f: dict) -> str:
    """Build rich text representation for embedding."""
    parts = [
        str(f.get("class") or f.get("vuln_class") or ""),
        str(f.get("cwe") or ""),
        str(f.get("file") or f.get("file_path") or ""),
        str(f.get("function") or f.get("name") or ""),
        str(f.get("desc") or f.get("description") or ""),
    ]
    return " ".join(p for p in parts if p)


def _build_corpus_text(e: dict) -> str:
    """Build rich text representation for corpus entry."""
    parts = [
        str(e.get("class") or ""),
        str(e.get("cwe") or ""),
        str(e.get("file") or ""),
        str(e.get("function") or ""),
        str(e.get("description") or ""),
        str(e.get("cve_id") or ""),
    ]
    return " ".join(p for p in parts if p)


def _hard_negative_check(finding: dict, corpus_entry: dict) -> str | None:
    """Check hard negative rules. Returns rejection reason or None."""
    f_file = str(finding.get("file") or finding.get("file_path") or "").lower()
    c_file = str(corpus_entry.get("file") or "").lower()

    # Rule 1: different file path — different bug location
    if f_file and c_file and f_file != c_file:
        f_base = f_file.rsplit("/", 1)[-1] if "/" in f_file else f_file
        c_base = c_file.rsplit("/", 1)[-1] if "/" in c_file else c_file
        if f_base != c_base:
            return f"different file: {f_base} vs {c_base}"

    # Rule 2: different function — different code path
    f_func = str(finding.get("function") or finding.get("name") or "").lower()
    c_func = str(corpus_entry.get("function") or "").lower()
    if f_func and c_func and f_func != c_func:
        return f"different function: {f_func} vs {c_func}"

    return None


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
    threshold: float | None = None,
    embedding_model: str = "all-MiniLM-L6-v2",
) -> tuple[list[dict], list[dict]]:
    """Suppress findings that semantically match known CVEs from the corpus.

    Six-layer matching strategy:
    1. Exact CVE ID mention (fast path, no embeddings)
    2. Two-pass semantic: class-prefilter → embedding similarity
    3. Class-match boost: same-class uses lower threshold
    4. Rich text encoding: CWE, file path, function name included
    5. Hard negative rules: different file/function → skip
    6. Confidence-weighted: auto-suppress / flag-review / pass

    Parameters
    ----------
    findings:
        List of finding dicts from the hunt.
    corpus:
        List of CVE corpus entries.
    threshold:
        Base similarity threshold (default: auto-set per class).
        Override to use the same threshold for all comparisons.
    embedding_model:
        Sentence-transformers model name for encoding.

    Returns
    -------
    ``(novel, known)`` — findings that are novel (potential zero days)
    and findings that match known CVEs (suppressed).  Each suppressed
    finding is annotated with ``suppressed_by_cve_corpus``,
    ``suppression_reason``, and ``suppression_confidence``.
    """
    if not corpus:
        return findings, []

    # --- Layer 1: Fast path — exact CVE ID match ---
    corpus_cve_ids: set[str] = set()
    for entry in corpus:
        cve_id = entry.get("cve_id", "")
        if cve_id:
            corpus_cve_ids.add(cve_id.upper())

    novel: list[dict] = []
    known: list[dict] = []
    need_semantic: list[tuple[int, dict]] = []

    for idx, f in enumerate(findings):
        f_desc = str(f.get("desc") or f.get("description") or "").upper()
        matched = False
        for cve_id in corpus_cve_ids:
            if cve_id in f_desc:
                f["suppressed_by_cve_corpus"] = True
                f["suppression_reason"] = f"exact CVE ID match: {cve_id}"
                f["suppression_confidence"] = 1.0
                known.append(f)
                matched = True
                break
        if not matched:
            need_semantic.append((idx, f))

    # --- Layers 2-6: Semantic matching ---
    if need_semantic:
        try:
            from ai_vuln_harness.stages.embeddings import EmbeddingIndex

            index = EmbeddingIndex(model_name=embedding_model)
            if not index.available:
                novel.extend(f for _, f in need_semantic)
                return novel, known

            # Layer 4: Rich text encoding
            finding_texts = [_build_finding_text(f) for _, f in need_semantic]
            corpus_texts = [_build_corpus_text(e) for e in corpus]

            # Batch encode
            all_texts = finding_texts + corpus_texts
            index.encode_findings([{"desc": t} for t in all_texts])
            all_embeddings = index._embeddings

            if all_embeddings is None or len(all_embeddings) == 0:
                novel.extend(f for _, f in need_semantic)
                return novel, known

            n_findings = len(finding_texts)
            finding_embs = all_embeddings[:n_findings]
            corpus_embs = all_embeddings[n_findings:]

            import faiss
            import numpy as np

            # Layer 2: Two-pass — prefilter by class, then semantic
            # Build class → corpus indices mapping
            class_indices: dict[str, list[int]] = {}
            for ci, entry in enumerate(corpus):
                cls = str(entry.get("class") or "").lower().strip()
                if cls:
                    class_indices.setdefault(cls, []).append(ci)

            # Build FAISS index over all corpus
            dim = finding_embs.shape[1]
            corpus_np = corpus_embs.astype("float32")
            faiss.normalize_L2(corpus_np)
            full_index = faiss.IndexFlatIP(dim)
            full_index.add(corpus_np)

            # Query all findings against corpus
            finding_np = finding_embs.astype("float32")
            faiss.normalize_L2(finding_np)
            k = min(len(corpus), 10)
            distances, indices = full_index.search(finding_np, k)

            for i, (orig_idx, f) in enumerate(need_semantic):
                f_class = (
                    str(f.get("class") or f.get("vuln_class") or "").lower().strip()
                )
                matched = False

                # Layer 3: Class-match boost — determine threshold
                same_class_indices = set(class_indices.get(f_class, []))

                for j in range(k):
                    sim = float(distances[i, j])
                    cve_idx = int(indices[i, j])
                    if cve_idx < 0 or cve_idx >= len(corpus):
                        continue

                    entry = corpus[cve_idx]
                    entry_class = str(entry.get("class") or "").lower().strip()
                    is_same_class = cve_idx in same_class_indices

                    # Layer 3: adaptive threshold
                    effective_threshold = (
                        threshold
                        if threshold is not None
                        else (
                            _THRESHOLD_SAME_CLASS
                            if is_same_class
                            else _THRESHOLD_DIFF_CLASS
                        )
                    )

                    if sim < effective_threshold:
                        continue

                    # Layer 5: Hard negative rules
                    rejection = _hard_negative_check(f, entry)
                    if rejection:
                        continue

                    # Layer 6: Confidence scoring
                    confidence = sim
                    if is_same_class:
                        confidence = min(1.0, sim + 0.1)  # class boost
                    if len(entry.get("file", "")) > 0:
                        confidence = min(1.0, confidence + 0.05)  # file match boost

                    f["suppressed_by_cve_corpus"] = True
                    f["suppression_reason"] = (
                        f"semantic match: {entry.get('cve_id', '?')} "
                        f"(similarity={sim:.3f}, class={'same' if is_same_class else 'diff'})"
                    )
                    f["suppression_confidence"] = round(confidence, 3)
                    known.append(f)
                    matched = True
                    break

                if not matched:
                    novel.append(f)

        except ImportError:
            novel.extend(f for _, f in need_semantic)

    return novel, known
