"""Tests for detect_reward_hack in stages/validate.py.

Covers:
- Identical calls that flip rejected→confirmed → should flag reward hacking.
- Varied calls (no structural similarity) → should NOT flag.
- Identical calls with no status flip → should NOT flag.
- Edge cases: fewer than 3 calls, empty history.
"""

from __future__ import annotations

import unittest

from ai_vuln_harness.stages.validate import detect_reward_hack

_IDENTICAL_REASON = (
    "The buffer overflow exists because the destination buffer is smaller "
    "than the source and no bounds check is performed before the copy."
)

_DIFFERENT_REASONS = [
    "The function validates input length before copying.",
    "There is a bounds check at line 42 that prevents overflow.",
    "The destination buffer is heap-allocated with sufficient size.",
    "No evidence of attacker-controlled input reaching this code path.",
]


def _call(status: str, reason: str) -> dict:
    return {"status": status, "reason": reason}


class TestDetectRewardHackFlags(unittest.TestCase):
    """detect_reward_hack should return True and mutate calls when hacking detected."""

    def test_three_identical_rejected_then_confirmed(self):
        """Three near-identical calls with rejected→confirmed flip triggers flag."""
        history = [
            _call("rejected", _IDENTICAL_REASON),
            _call("rejected", _IDENTICAL_REASON),
            _call("confirmed", _IDENTICAL_REASON),
        ]
        result = detect_reward_hack(history)
        self.assertTrue(result)

    def test_multiple_identical_with_flip(self):
        """Five identical calls with one flip also triggers flag."""
        history = [
            _call("rejected", _IDENTICAL_REASON),
            _call("rejected", _IDENTICAL_REASON),
            _call("rejected", _IDENTICAL_REASON),
            _call("rejected", _IDENTICAL_REASON),
            _call("confirmed", _IDENTICAL_REASON),
        ]
        result = detect_reward_hack(history)
        self.assertTrue(result)

    def test_calls_mutated_to_needs_more_info(self):
        """When flagged, all call statuses are downgraded to needs-more-info."""
        history = [
            _call("rejected", _IDENTICAL_REASON),
            _call("rejected", _IDENTICAL_REASON),
            _call("confirmed", _IDENTICAL_REASON),
        ]
        detect_reward_hack(history)
        for call in history:
            self.assertEqual(call["status"], "needs-more-info")

    def test_calls_annotated_with_reward_hacked(self):
        """When flagged, all calls gain reward_hacked=True."""
        history = [
            _call("rejected", _IDENTICAL_REASON),
            _call("rejected", _IDENTICAL_REASON),
            _call("confirmed", _IDENTICAL_REASON),
        ]
        detect_reward_hack(history)
        for call in history:
            self.assertTrue(call.get("reward_hacked"))


class TestDetectRewardHackDoesNotFlag(unittest.TestCase):
    """detect_reward_hack should return False when no hacking detected."""

    def test_varied_calls_not_flagged(self):
        """Structurally different reasons should not trigger flag."""
        history = [_call("rejected", r) for r in _DIFFERENT_REASONS]
        result = detect_reward_hack(history)
        self.assertFalse(result)

    def test_identical_calls_no_flip(self):
        """Identical reasons but no rejected→confirmed flip should not flag."""
        history = [
            _call("rejected", _IDENTICAL_REASON),
            _call("rejected", _IDENTICAL_REASON),
            _call("rejected", _IDENTICAL_REASON),
        ]
        result = detect_reward_hack(history)
        self.assertFalse(result)

    def test_confirmed_to_confirmed_not_flagged(self):
        """All-confirmed identical history is not a flip pattern."""
        history = [
            _call("confirmed", _IDENTICAL_REASON),
            _call("confirmed", _IDENTICAL_REASON),
            _call("confirmed", _IDENTICAL_REASON),
        ]
        result = detect_reward_hack(history)
        self.assertFalse(result)

    def test_fewer_than_three_calls(self):
        """Less than 3 calls can never trigger the detector."""
        history = [
            _call("rejected", _IDENTICAL_REASON),
            _call("confirmed", _IDENTICAL_REASON),
        ]
        result = detect_reward_hack(history)
        self.assertFalse(result)

    def test_empty_history(self):
        """Empty call history returns False."""
        result = detect_reward_hack([])
        self.assertFalse(result)

    def test_single_call(self):
        """Single call returns False."""
        result = detect_reward_hack([_call("confirmed", _IDENTICAL_REASON)])
        self.assertFalse(result)

    def test_only_two_identical_with_flip(self):
        """Two identical calls (below threshold of 3) with flip should not flag."""
        history = [
            _call("rejected", _IDENTICAL_REASON),
            _call("confirmed", _IDENTICAL_REASON),
        ]
        result = detect_reward_hack(history)
        self.assertFalse(result)


if __name__ == "__main__":
    unittest.main()
