"""Scan Checkpoint — premature exit prevention.

Prevents stages from completing with empty output without warning.
When a stage produces zero findings or suspiciously fast results,
this module flags the issue and suggests recovery actions.

This implements the Glasswing-Open scan-checkpoint pattern.
"""

from __future__ import annotations

import logging
import time

logger = logging.getLogger(__name__)


class ScanCheckpoint:
    """Track stage health and detect premature exit conditions."""

    def __init__(self) -> None:
        self._stage_times: dict[str, float] = {}
        self._stage_counts: dict[str, int] = {}
        self._warnings: list[dict] = []

    def start_stage(self, stage_name: str) -> None:
        """Record stage start time."""
        self._stage_times[stage_name] = time.monotonic()

    def end_stage(self, stage_name: str, finding_count: int) -> list[dict]:
        """Record stage end and check for issues.

        Returns a list of warning dicts.
        """
        warnings: list[dict] = []
        start = self._stage_times.get(stage_name)
        elapsed = time.monotonic() - start if start else 0
        self._stage_counts[stage_name] = finding_count

        # Check 1: Zero findings from a stage that should produce output
        if finding_count == 0 and stage_name in ("hunt", "validate"):
            warnings.append(
                {
                    "stage": stage_name,
                    "issue": "zero_findings",
                    "message": f"{stage_name} produced 0 findings — possible crash, empty scope, or model failure",
                    "action": "requeue with different attack class or broader scope",
                }
            )

        # Check 2: Suspiciously fast completion (< 5 seconds for hunt)
        if elapsed < 5.0 and stage_name == "hunt":
            warnings.append(
                {
                    "stage": stage_name,
                    "issue": "too_fast",
                    "message": f"{stage_name} completed in {elapsed:.1f}s — likely crashed or hit rate limit",
                    "action": "check logs for errors, requeue if needed",
                }
            )

        # Check 3: All findings rejected by validate
        if stage_name == "validate" and finding_count == 0:
            prev_count = self._stage_counts.get("hunt", 0)
            if prev_count > 0:
                warnings.append(
                    {
                        "stage": stage_name,
                        "issue": "all_rejected",
                        "message": f"validate rejected all {prev_count} hunt findings — check for overly strict validation",
                        "action": "review validation criteria, consider relaxing confidence threshold",
                    }
                )

        for w in warnings:
            logger.warning("scan_checkpoint: %s — %s", w["issue"], w["message"])

        self._warnings.extend(warnings)
        return warnings

    @property
    def all_warnings(self) -> list[dict]:
        """All warnings accumulated across stages."""
        return self._warnings

    def summary(self) -> dict:
        """Return a summary of stage health."""
        return {
            "stages": dict(self._stage_counts),
            "warnings": len(self._warnings),
            "warning_details": self._warnings,
        }
