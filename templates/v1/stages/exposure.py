"""Exposure window annotation — compute how long each vulnerability existed.

Uses ``git log --follow`` to find the first and last commit dates for each
vulnerable file. Computes an exposure window in days: from first commit to
either the fix commit (resolved findings) or the present (open findings).

Output KPIs: avg/median exposure window, oldest open exposure, resolved count.
"""

from __future__ import annotations

import statistics
import subprocess
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pathlib import Path


def _parse_iso8601(value: str) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def _git_file_bounds(
    repo: Path,
    file_path: str,
) -> tuple[datetime | None, datetime | None]:
    try:
        first = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "log",
                "--follow",
                "--reverse",
                "--format=%cI",
                "--",
                file_path,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        last = subprocess.run(
            [
                "git",
                "-C",
                str(repo),
                "log",
                "--follow",
                "-n",
                "1",
                "--format=%cI",
                "--",
                file_path,
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None, None

    if first.returncode != 0 or last.returncode != 0:
        return None, None

    first_date = (
        _parse_iso8601(first.stdout.splitlines()[0])
        if first.stdout.splitlines()
        else None
    )
    last_date = (
        _parse_iso8601(last.stdout.splitlines()[0])
        if last.stdout.splitlines()
        else None
    )
    return first_date, last_date


def _annotate_one_window(
    finding: dict,
    repo: Path,
    now: datetime,
) -> tuple[dict, float | None, bool]:
    file_path = str(finding.get("file") or "")
    if not file_path:
        return finding, None, False

    first_seen, latest_commit = _git_file_bounds(repo, file_path)
    if first_seen is None:
        return finding, None, False

    is_resolved = str(finding.get("status", "")).lower() in {"rejected", "fixed"}
    end = latest_commit if is_resolved and latest_commit else now
    window_days = max(0.0, (end - first_seen).total_seconds() / 86400.0)

    entry = {
        **finding,
        "exposure_window": {
            "first_seen_commit_date": first_seen.isoformat(),
            "fixed_commit_date": end.isoformat() if is_resolved else None,
            "days": round(window_days, 2),
            "resolved": is_resolved,
        },
    }
    return entry, window_days, is_resolved


def annotate_exposure_windows(
    findings: list[dict],
    repo: Path,
) -> tuple[list[dict], dict]:
    now = datetime.now(timezone.utc)  # noqa: UP017 — from datetime import datetime makes datetime.UTC invalid
    tracked: list[dict] = []
    windows: list[float] = []
    resolved = 0

    for finding in findings:
        entry, window_days, is_resolved = _annotate_one_window(finding, repo, now)
        tracked.append(entry)
        if window_days is not None:
            windows.append(window_days)
        if is_resolved:
            resolved += 1

    open_windows = [
        float(v)
        for f in tracked
        if (ew := f.get("exposure_window"))
        and not ew.get("resolved")
        and isinstance(v := ew.get("days"), (int, float))
    ]

    metrics = {
        "findings_tracked": len([f for f in tracked if f.get("exposure_window")]),
        "resolved_findings": resolved,
        "open_findings": len(open_windows),
        "avg_exposure_window_days": round(statistics.mean(windows), 2)
        if windows
        else 0.0,
        "median_exposure_window_days": round(statistics.median(windows), 2)
        if windows
        else 0.0,
        "oldest_open_exposure_days": round(max(open_windows), 2)
        if open_windows
        else 0.0,
    }
    return tracked, metrics
