"""Juliet Test Suite loader."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..rag_kb import VulnerabilityKB


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

    cwe_pattern_map = {
        "CWE119": (
            "CWE-119",
            "Buffer Overflow",
            ["buffer", "overflow", "memcpy", "strcpy"],
        ),
        "CWE120": (
            "CWE-120",
            "Buffer Overflow (Classic)",
            ["buffer", "overflow", "stack"],
        ),
        "CWE121": ("CWE-121", "Stack Buffer Overflow", ["stack", "buffer", "overflow"]),
        "CWE122": ("CWE-122", "Heap Buffer Overflow", ["heap", "buffer", "overflow"]),
        "CWE125": ("CWE-125", "Out-of-bounds Read", ["read", "buffer", "bounds"]),
        "CWE134": ("CWE-134", "Format String", ["format", "string", "printf"]),
        "CWE190": ("CWE-190", "Integer Overflow", ["integer", "overflow"]),
        "CWE191": ("CWE-191", "Integer Underflow", ["integer", "underflow"]),
        "CWE415": ("CWE-415", "Double Free", ["double", "free"]),
        "CWE416": ("CWE-416", "Use After Free", ["use", "after", "free"]),
        "CWE476": ("CWE-476", "NULL Pointer Dereference", ["null", "pointer"]),
        "CWE787": ("CWE-787", "Out-of-bounds Write", ["write", "buffer", "bounds"]),
    }

    for dirpath, dirnames, filenames in directory.walk():
        for filename in filenames:
            if max_patterns > 0 and count >= max_patterns:
                break

            parts = dirpath.name.split("_")
            if len(parts) >= 2:
                cwe_class = parts[1]
                if cwe_class in cwe_pattern_map:
                    cwe_id, title, patterns = cwe_pattern_map[cwe_class]
                    if cwe_id not in [p["cwe"] for p in kb._patterns]:
                        kb.add_pattern(
                            cwe=cwe_id,
                            title=title,
                            description=f"Juliet Test Suite pattern for {title}",
                            patterns=patterns,
                            language="c",
                            persist=True,
                        )
                        count += 1
            break

    return count


def load_juliet_representatives(kb: VulnerabilityKB) -> int:
    """Load representative Juliet Test Suite patterns without downloading.

    Returns the number of patterns loaded.
    """
    juliet_patterns = [
        {
            "cwe": "CWE-119",
            "title": "Buffer Overflow (Juliet)",
            "description": "Buffer overflow test cases from Juliet Test Suite.",
            "patterns": ["buffer", "overflow", "memcpy", "strcpy"],
        },
        {
            "cwe": "CWE-120",
            "title": "Buffer Overflow Classic (Juliet)",
            "description": "Classic buffer overflow test cases.",
            "patterns": ["buffer", "overflow", "stack"],
        },
        {
            "cwe": "CWE-121",
            "title": "Stack Buffer Overflow (Juliet)",
            "description": "Stack-based buffer overflow test cases.",
            "patterns": ["stack", "buffer", "overflow"],
        },
        {
            "cwe": "CWE-122",
            "title": "Heap Buffer Overflow (Juliet)",
            "description": "Heap-based buffer overflow test cases.",
            "patterns": ["heap", "buffer", "overflow"],
        },
        {
            "cwe": "CWE-125",
            "title": "Out-of-bounds Read (Juliet)",
            "description": "Out-of-bounds read test cases.",
            "patterns": ["read", "buffer", "bounds"],
        },
        {
            "cwe": "CWE-134",
            "title": "Format String (Juliet)",
            "description": "Format string vulnerability test cases.",
            "patterns": ["format", "string", "printf"],
        },
        {
            "cwe": "CWE-190",
            "title": "Integer Overflow (Juliet)",
            "description": "Integer overflow test cases.",
            "patterns": ["integer", "overflow"],
        },
        {
            "cwe": "CWE-191",
            "title": "Integer Underflow (Juliet)",
            "description": "Integer underflow test cases.",
            "patterns": ["integer", "underflow"],
        },
        {
            "cwe": "CWE-415",
            "title": "Double Free (Juliet)",
            "description": "Double free test cases.",
            "patterns": ["double", "free"],
        },
        {
            "cwe": "CWE-416",
            "title": "Use After Free (Juliet)",
            "description": "Use after free test cases.",
            "patterns": ["use", "after", "free"],
        },
        {
            "cwe": "CWE-476",
            "title": "NULL Pointer Dereference (Juliet)",
            "description": "NULL pointer dereference test cases.",
            "patterns": ["null", "pointer"],
        },
        {
            "cwe": "CWE-787",
            "title": "Out-of-bounds Write (Juliet)",
            "description": "Out-of-bounds write test cases.",
            "patterns": ["write", "buffer", "bounds"],
        },
    ]

    count = 0
    for p in juliet_patterns:
        if p["cwe"] not in [existing["cwe"] for existing in kb._patterns]:
            kb.add_pattern(**p)
            count += 1

    return count
