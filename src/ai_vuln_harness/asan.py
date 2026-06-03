# Copyright 2026 Anthropic PBC
# SPDX-License-Identifier: Apache-2.0
#
# Adapted from defending-code-reference-harness (Anthropic's reference
# implementation for autonomous vulnerability discovery).  ASAN output
# parsing shared by dedup, runtime bug-sharing, and exploit synthesis.
from __future__ import annotations

import re

_ASAN_FRAME = re.compile(
    r"^\s*#(\d+)\s+0x[0-9a-fA-F]+\s+in\s+(.+?)\s*$",
    re.MULTILINE,
)
_SOURCE_LOC = re.compile(r"\s[/\w][^\s:]*:\d+(?=(?::\d+)?$)")
_ASSERTION = re.compile(r"(\S+:\d+): (\w+): Assertion .+ failed")


def project_frames(crash_output: str, n: int = 3) -> list[str]:
    """Top-N frames from the crash stack that have project source info.

    Walks frames in order; collects those with a ``file:line`` source location
    (skipping interceptor/library frames).  Stops at the second stack section
    (``allocated by`` / ``freed by``) so UAF alloc frames don't leak in.
    Returns up to *n* frames; empty list if none parsed.  If no frame has
    source info, returns ``[frame #0 as-is]`` as a fallback.
    """
    frames = _ASAN_FRAME.findall(crash_output)
    if not frames:
        m = _ASSERTION.search(crash_output)
        if m:
            return [f"{m.group(2)} {m.group(1)}"]
        return []
    prev_n = -1
    fallback: str | None = None
    out: list[str] = []
    for n_str, body in frames:
        fn = int(n_str)
        if fn <= prev_n:
            break
        prev_n = fn
        if fallback is None:
            fallback = body
        m = _SOURCE_LOC.search(body)
        if m:
            out.append(body[: m.end()])
            if len(out) >= n:
                break
    return out or ([fallback] if fallback else [])


def top_frame(crash_output: str) -> str | None:
    """First project-source frame from the crash stack (convenience wrapper)."""
    frames = project_frames(crash_output, n=1)
    return frames[0] if frames else None


_ASAN_SUMMARY = re.compile(r"SUMMARY:\s*AddressSanitizer:\s*(\S+)")
_OP = re.compile(
    r"^(READ|WRITE) of size \d+|signal is caused by a (READ|WRITE) memory access",
    re.MULTILINE,
)


def crash_reason(crash_output: str) -> dict[str, str | None]:
    """Extract ``crash_type`` + ``operation`` from sanitizer output.

    Display-only: feeds dedup, excerpts, and synthesis metadata.  Not a
    decision input — agents judge semantic duplicates from raw ASAN.
    """
    m = _ASAN_SUMMARY.search(crash_output)
    crash_type = m.group(1) if m else None
    if crash_type in (None, "ABRT") and _ASSERTION.search(crash_output):
        crash_type = "assertion-failure"

    op = _OP.search(crash_output)
    operation = (op.group(1) or op.group(2)) if op else None

    return {"crash_type": crash_type, "operation": operation}


def asan_excerpt(crash_output: str, max_frames: int = 10) -> str:
    """SUMMARY line + first N stack frames, for dedup context.

    ~500 bytes per excerpt — enough for comparing signatures semantically
    without the full 10 KB trace.
    """
    lines = crash_output.splitlines()
    out: list[str] = []
    frame_count = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("SUMMARY:") or "ERROR: AddressSanitizer:" in stripped:
            out.append(stripped)
        elif stripped.startswith("#") and " 0x" in stripped:
            out.append(stripped)
            frame_count += 1
            if frame_count >= max_frames:
                break
    if not out:
        out = [ln.strip() for ln in lines if ln.strip()][:3]
    return "\n".join(out)
