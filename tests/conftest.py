from __future__ import annotations

from pathlib import Path

import pytest

STAGES_DIR = Path(__file__).parent.parent / "src" / "ai_vuln_harness" / "stages"
FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_snippet() -> dict:
    return {
        "id": "sha256:abc123:def456",
        "file": "src/test.c",
        "language": "c",
        "kind": "function",
        "name": "test_func",
        "lines": [1, 10],
        "content": "void test_func() { char buf[10]; gets(buf); }",
        "imports": ["stdio.h"],
        "callees": ["gets"],
        "callers": [],
        "token_count": 42,
        "continuation": False,
    }


@pytest.fixture
def sample_finding() -> dict:
    return {
        "id": "finding:001",
        "snippet_id": "sha256:abc123:def456",
        "class": "buffer-overflow",
        "severity": "HIGH",
        "desc": "Buffer overflow via gets()",
        "status": "raw",
        "poc_confirmed": False,
        "bucket_rationale": "",
        "call_path": [],
    }


@pytest.fixture
def sample_pack() -> dict:
    return {
        "agent": "mem-safety",
        "snippets": [
            {
                "id": "sha256:abc123:def456",
                "file": "src/test.c",
                "language": "c",
                "kind": "function",
                "name": "test_func",
                "content": "void test_func() { char buf[10]; gets(buf); }",
                "token_count": 42,
            }
        ],
        "prompt": "Check for buffer overflow in the provided code.",
    }
