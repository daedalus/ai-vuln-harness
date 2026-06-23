#!/usr/bin/env python3
"""Script to populate the vulnerability knowledge base with real datasets.

Downloads and loads:
- MITRE CWE definitions (900+ CWEs)
- NVD CVE descriptions (recent year)
- Exploit-DB (40K+ exploits)
- GitHub Advisory Database
- OSV.dev, Snyk, D2A, VulDeePecker, Juliet

Usage:
    python -m ai_vuln_harness.scripts.populate_kb
    python -m ai_vuln_harness.scripts.populate_kb --output ~/.ai-vuln-harness/db/custom.db
    python -m ai_vuln_harness.scripts.populate_kb --datasets mitre_cwe nvd_cve
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# pylint: disable=wrong-import-position
from ai_vuln_harness.stages.dataset_loaders import (
    _default_db_dir,
    load_all_public_datasets,
)
from ai_vuln_harness.stages.rag_kb import VulnerabilityKB


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Populate vulnerability knowledge base with public datasets",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=_default_db_dir() / "vuln_kb.db",
        help="Output database path (default: ~/.ai-vuln-harness/db/vuln_kb.db)",
    )
    parser.add_argument(
        "--max-per-dataset",
        type=int,
        default=0,
        help="Maximum patterns per dataset (0 = no limit, default: 0)",
    )
    parser.add_argument(
        "--datasets",
        nargs="+",
        default=None,
        choices=[
            "mitre_cwe",
            "nvd_cve",
            "exploitdb",
            "github",
            "osv",
            "snyk",
            "d2a",
            "juliet",
        ],
        help="Specific datasets to load (default: all)",
    )
    parser.add_argument(
        "--faiss",
        action="store_true",
        help="Build and persist a FAISS index (requires faiss-cpu + sentence-transformers)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset database (drop and recreate) before loading",
    )
    args = parser.parse_args()

    # Ensure output directory exists
    args.output.parent.mkdir(parents=True, exist_ok=True)

    if args.reset and args.output.exists():
        print(f"Resetting database at {args.output}...")
        args.output.unlink()

    print(f"Initializing knowledge base at {args.output}...")
    with VulnerabilityKB(args.output, use_faiss=args.faiss, reset=args.reset) as kb:
        print(f"Starting size: {kb.size} patterns")

        # Load datasets
        summary = load_all_public_datasets(
            kb,
            max_per_dataset=args.max_per_dataset,
            datasets=args.datasets,
        )

        print(f"\n{'=' * 50}")
        print("Summary:")
        for ds, count in summary.items():
            if ds != "total":
                print(f"  {ds}: {count}")
        print(f"  {'total':<15}: {summary['total']}")
        print(f"  {'KB size':<15}: {kb.size}")
        print(f"{'=' * 50}")

        # Force-build search index and persist FAISS if enabled
        if args.faiss:
            print("\nBuilding FAISS index...")
            kb._build_faiss_index()  # pylint: disable=protected-access
            if kb._built_faiss:  # pylint: disable=protected-access
                faiss_path = args.output.with_suffix(".faiss")
                print(f"FAISS index saved to {faiss_path}")
            else:
                print(
                    "WARNING: FAISS index build failed (check faiss-cpu + sentence-transformers)"
                )
        else:
            kb._build_tfidf_index()  # pylint: disable=protected-access

        # Quick test search
        print("\nTest search: 'SQL injection'")
        results = kb.search("SQL injection", top_k=3)
        for r in results:
            print(f"  {r['cwe']}: {r['title'][:50]}... (score={r['score']})")


if __name__ == "__main__":
    main()
