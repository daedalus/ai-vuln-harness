"""Tests for confabulation_risk and build_negation_probe_prompt in stages/validate.py.

Covers:
- confabulation_risk returns True when confirmed + plausible_fp.
- confabulation_risk returns False for all other status combinations.
- build_negation_probe_prompt includes the vulnerability class and correct JSON schema.
"""

from __future__ import annotations

import unittest

from ai_vuln_harness.stages.validate import (
    build_negation_probe_prompt,
    confabulation_risk,
)


class TestConfabulationRisk(unittest.TestCase):
    """confabulation_risk correctly identifies contradictory model outputs."""

    def test_confirmed_and_plausible_fp_returns_true(self):
        """confirmed validate + plausible_fp negation → True (confabulation)."""
        validate_result = {"status": "confirmed", "reason": "found buffer overflow"}
        negation_result = {"status": "plausible_fp", "reason": "bounds check exists"}
        self.assertTrue(confabulation_risk(validate_result, negation_result))

    def test_confirmed_and_implausible_fp_returns_false(self):
        """confirmed validate + implausible_fp negation → False (no confabulation)."""
        validate_result = {"status": "confirmed", "reason": "found buffer overflow"}
        negation_result = {
            "status": "implausible_fp",
            "reason": "no credible argument",
        }
        self.assertFalse(confabulation_risk(validate_result, negation_result))

    def test_rejected_and_plausible_fp_returns_false(self):
        """rejected validate + plausible_fp negation → False (finding was rejected)."""
        validate_result = {"status": "rejected", "reason": "bounds checked"}
        negation_result = {"status": "plausible_fp", "reason": "no issue found"}
        self.assertFalse(confabulation_risk(validate_result, negation_result))

    def test_needs_more_info_and_plausible_fp_returns_false(self):
        """needs-more-info validate + plausible_fp negation → False."""
        validate_result = {"status": "needs-more-info", "reason": "unclear"}
        negation_result = {"status": "plausible_fp", "reason": "some argument"}
        self.assertFalse(confabulation_risk(validate_result, negation_result))

    def test_rejected_and_implausible_fp_returns_false(self):
        """rejected validate + implausible_fp negation → False."""
        validate_result = {"status": "rejected", "reason": "safe"}
        negation_result = {"status": "implausible_fp", "reason": "no argument"}
        self.assertFalse(confabulation_risk(validate_result, negation_result))

    def test_empty_dicts_return_false(self):
        """Missing status keys return False (no confabulation)."""
        self.assertFalse(confabulation_risk({}, {}))

    def test_only_validate_status_set(self):
        """Only validate status set, negation missing → False."""
        validate_result = {"status": "confirmed"}
        self.assertFalse(confabulation_risk(validate_result, {}))

    def test_only_negation_status_set(self):
        """Only negation status set, validate missing → False."""
        negation_result = {"status": "plausible_fp"}
        self.assertFalse(confabulation_risk({}, negation_result))

    def test_status_values_are_case_sensitive(self):
        """Status comparison is case-sensitive ('Confirmed' != 'confirmed')."""
        validate_result = {"status": "Confirmed"}
        negation_result = {"status": "plausible_fp"}
        self.assertFalse(confabulation_risk(validate_result, negation_result))


class TestBuildNegationProbePrompt(unittest.TestCase):
    """build_negation_probe_prompt generates a correct negation prompt."""

    def _finding(self) -> dict:
        return {
            "snippet_id": "sha256:abc:def",
            "class": "buffer-overflow",
            "desc": "Buffer overflow via gets()",
            "call_path": ["main", "process_input"],
        }

    def _snippet(self) -> dict:
        return {
            "file": "src/input.c",
            "lines": [10, 25],
            "content": "void process_input(char *s) { char buf[10]; gets(buf); }",
        }

    def test_prompt_is_string(self):
        """Prompt is a non-empty string."""
        prompt = build_negation_probe_prompt(self._finding(), self._snippet())
        self.assertIsInstance(prompt, str)
        self.assertTrue(len(prompt) > 0)

    def test_prompt_mentions_vulnerability_class(self):
        """Prompt includes the vulnerability class."""
        prompt = build_negation_probe_prompt(self._finding(), self._snippet())
        self.assertIn("buffer-overflow", prompt)

    def test_prompt_asks_for_false_positive_argument(self):
        """Prompt instructs the model to argue it is NOT a vulnerability."""
        prompt = build_negation_probe_prompt(self._finding(), self._snippet())
        self.assertIn("NOT a vulnerability", prompt)

    def test_prompt_includes_source_code(self):
        """Prompt includes the actual source code snippet."""
        prompt = build_negation_probe_prompt(self._finding(), self._snippet())
        self.assertIn("gets(buf)", prompt)

    def test_prompt_includes_json_schema(self):
        """Prompt requests JSON output with plausible_fp|implausible_fp schema."""
        prompt = build_negation_probe_prompt(self._finding(), self._snippet())
        self.assertIn("plausible_fp", prompt)
        self.assertIn("implausible_fp", prompt)

    def test_prompt_includes_snippet_id(self):
        """Prompt includes the snippet_id for traceability."""
        prompt = build_negation_probe_prompt(self._finding(), self._snippet())
        self.assertIn("sha256:abc:def", prompt)

    def test_prompt_includes_file_name(self):
        """Prompt includes the source file name."""
        prompt = build_negation_probe_prompt(self._finding(), self._snippet())
        self.assertIn("src/input.c", prompt)

    def test_empty_finding_and_snippet(self):
        """build_negation_probe_prompt handles empty dicts without raising."""
        prompt = build_negation_probe_prompt({}, {})
        self.assertIsInstance(prompt, str)


if __name__ == "__main__":
    unittest.main()
