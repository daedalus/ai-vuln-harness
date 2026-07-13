"""Crash corpus collection — gather PoC inputs for regression testing.

After POC confirms findings, collect the PoC inputs into a structured
corpus directory for regression testing and fuzzer seeding. Each PoC
is stored as a file with a manifest.json describing the corpus.

This implements the Glasswing-Open crash corpus pattern.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path  # noqa: TC003 — used at runtime

logger = logging.getLogger(__name__)


def collect_crash_corpus(
    pocs: list[dict],
    findings: list[dict],
    output_dir: Path,
    *,
    corpus_name: str = "crash_corpus",
) -> dict:
    """Collect PoC inputs into a structured corpus directory.

    Parameters
    ----------
    pocs:
        List of PoC result dicts from the POC stage.
    findings:
        List of finding dicts (for metadata).
    output_dir:
        Base output directory.
    corpus_name:
        Name of the corpus subdirectory.

    Returns
    -------
    dict with corpus metadata (file_count, manifest_path, etc.)
    """
    corpus_dir = output_dir / corpus_name
    corpus_dir.mkdir(parents=True, exist_ok=True)

    # Build finding lookup by ID
    finding_map: dict[str, dict] = {}
    for f in findings:
        fid = f.get("finding_id") or f.get("snippet_id") or ""
        if fid:
            finding_map[fid] = f

    entries: list[dict] = []
    for i, poc in enumerate(pocs):
        finding_id = poc.get("finding_id") or poc.get("snippet_id") or f"poc_{i}"
        poc_input = poc.get("poc_input") or poc.get("crash_input") or ""
        if not poc_input:
            continue

        # Write PoC input file
        poc_file = corpus_dir / f"{finding_id}.bin"
        try:
            if isinstance(poc_input, bytes):
                poc_file.write_bytes(poc_input)
            else:
                poc_file.write_text(str(poc_input), encoding="utf-8")
        except Exception as e:
            logger.warning("crash_corpus: failed to write %s: %s", poc_file, e)
            continue

        # Build entry metadata
        finding = finding_map.get(finding_id, {})
        entry = {
            "finding_id": finding_id,
            "file": str(poc_file.relative_to(output_dir)),
            "class": finding.get("class") or poc.get("class") or "unknown",
            "severity": finding.get("severity") or "unknown",
            "source_file": finding.get("file") or "",
            "crash_signal": poc.get("crash_signal") or "",
            "asan_output": (poc.get("asan_output") or "")[:500],
        }
        entries.append(entry)

    # Write manifest
    manifest = {
        "name": corpus_name,
        "created_by": "ai-vuln-harness",
        "file_count": len(entries),
        "entries": entries,
    }
    manifest_path = corpus_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    logger.info(
        "crash_corpus: collected %d PoC inputs into %s",
        len(entries),
        corpus_dir,
    )

    return {
        "corpus_dir": str(corpus_dir),
        "manifest_path": str(manifest_path),
        "file_count": len(entries),
    }


def load_crash_corpus(corpus_dir: Path) -> list[dict]:
    """Load a crash corpus manifest.

    Returns a list of entry dicts, or empty list if no manifest exists.
    """
    manifest_path = corpus_dir / "manifest.json"
    if not manifest_path.exists():
        return []
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        return manifest.get("entries", [])
    except Exception as e:
        logger.warning("crash_corpus: failed to load %s: %s", manifest_path, e)
        return []
