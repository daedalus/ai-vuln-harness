"""Tests for refusal detection in stages/runtime.py."""

import json
import unittest
import urllib.request
import ssl
from unittest.mock import patch, MagicMock

from ai_vuln_harness.stages.runtime import (
    _is_refusal,
    _refusal_counts,
    _call_llm_with_retry,
    get_refusal_counts,
    reset_refusal_counts,
)


class IsRefusalTests(unittest.TestCase):
    """Tests for _is_refusal() pattern matching."""

    # --- True positives (should detect as refusal) ---

    def test_openai_unable_to_assist(self):
        self.assertTrue(_is_refusal("I'm unable to assist with that request."))

    def test_openai_cannot_help(self):
        self.assertTrue(_is_refusal("I cannot help with this task."))

    def test_openai_cant_assist(self):
        self.assertTrue(_is_refusal("I can't assist with that."))

    def test_anthropic_appreciate_but_cant(self):
        self.assertTrue(_is_refusal(
            "I appreciate your interest, but I can't help with that."
        ))

    def test_anthropic_not_comfortable(self):
        self.assertTrue(_is_refusal(
            "I don't feel comfortable providing assistance with this."
        ))

    def test_generic_must_decline(self):
        self.assertTrue(_is_refusal("I must decline this request."))

    def test_generic_wont_assist(self):
        self.assertTrue(_is_refusal("I won't assist with that."))

    def test_generic_not_authorized(self):
        self.assertTrue(_is_refusal("I am not authorized to provide this information."))

    def test_chinese_refusal(self):
        self.assertTrue(_is_refusal("我无法提供此类帮助"))

    def test_multiline_refusal(self):
        content = """I understand you're asking about security analysis.

However, I'm unable to assist with that request as it goes against my guidelines.

Is there something else I can help with?"""
        self.assertTrue(_is_refusal(content))

    # --- False negatives (should NOT detect as refusal) ---

    def test_normal_finding_not_refusal(self):
        content = '{"findings": [{"class": "sql-injection", "severity": "HIGH"}]}'
        self.assertFalse(_is_refusal(content))

    def test_code_analysis_not_refusal(self):
        content = """The code contains a potential SQL injection vulnerability
in the login function at line 42. User input is passed directly to
cursor.execute() without parameterization."""
        self.assertFalse(_is_refusal(content))

    def test_empty_content(self):
        self.assertFalse(_is_refusal(""))

    def test_short_content(self):
        self.assertFalse(_is_refusal("OK"))

    def test_json_at_start_not_refusal(self):
        content = '{"status": "ok", "message": "I can help with that"}'
        self.assertFalse(_is_refusal(content))

    def test_finding_with_can_not_in_context(self):
        content = """I can analyze this code. The vulnerability is that the buffer
can not hold more than 10 bytes, leading to overflow."""
        self.assertFalse(_is_refusal(content))

    def test_no_first_person_refusal(self):
        """Refusal patterns require first-person frame, not just keywords."""
        content = "The system cannot assist with unauthorized access attempts."
        self.assertFalse(_is_refusal(content))

    def test_mixed_content_with_json_not_refusal(self):
        content = """Analysis complete. Here are the findings:

```json
{"findings": []}
```

I cannot identify any vulnerabilities in this code."""
        # Has JSON braces in first 200 chars
        self.assertFalse(_is_refusal(content))


class RefusalCountTests(unittest.TestCase):
    """Tests for refusal counting infrastructure."""

    def setUp(self):
        reset_refusal_counts()

    def test_get_refusal_counts_empty(self):
        counts = get_refusal_counts()
        self.assertEqual(counts, {})

    def test_reset_clears_counts(self):
        _refusal_counts["test/model"] = 5
        reset_refusal_counts()
        self.assertEqual(get_refusal_counts(), {})

    def test_counts_are_dict(self):
        counts = get_refusal_counts()
        self.assertIsInstance(counts, dict)


class RefusalRetryTests(unittest.TestCase):
    """Tests for refusal retry logic in _call_llm_with_retry."""

    def setUp(self):
        reset_refusal_counts()

    def _make_request(self):
        req = urllib.request.Request(
            url="https://example.com/chat/completions",
            data=json.dumps({"model": "test"}).encode(),
            headers={"Content-Type": "application/json"},
        )
        return req, ssl.create_default_context()

    def test_refusal_retries_then_succeeds(self):
        """First call returns refusal, second call returns valid content."""
        call_count = 0
        refusal_content = "I'm unable to assist with that request."

        def mock_call_once(req, ctx, timeout, model_name, provider):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return refusal_content
            return '{"findings": [{"class": "sql-injection"}]}'

        req, ctx = self._make_request()
        with patch("ai_vuln_harness.stages.runtime._call_llm_once", side_effect=mock_call_once):
            with patch("ai_vuln_harness.stages.runtime.time.sleep"):
                result = _call_llm_with_retry(
                    req, ctx, 30, "test-model", "test-provider",
                    "https://example.com", None, None,
                )

        self.assertEqual(call_count, 2)
        self.assertIn("findings", result)
        self.assertEqual(get_refusal_counts().get("test-provider/test-model"), 1)

    def test_refusal_retries_exhausted(self):
        """All 3 attempts return refusal — returns refusal content."""
        def mock_call_once(req, ctx, timeout, model_name, provider):
            return "I cannot help with that."

        req, ctx = self._make_request()
        with patch("ai_vuln_harness.stages.runtime._call_llm_once", side_effect=mock_call_once):
            with patch("ai_vuln_harness.stages.runtime.time.sleep"):
                result = _call_llm_with_retry(
                    req, ctx, 30, "test-model", "test-provider",
                    "https://example.com", None, None,
                )

        self.assertTrue(_is_refusal(result))
        self.assertEqual(get_refusal_counts().get("test-provider/test-model"), 2)

    def test_no_refusal_no_retry(self):
        """Non-refusal response returns immediately."""
        call_count = 0

        def mock_call_once(req, ctx, timeout, model_name, provider):
            nonlocal call_count
            call_count += 1
            return '{"findings": []}'

        req, ctx = self._make_request()
        with patch("ai_vuln_harness.stages.runtime._call_llm_once", side_effect=mock_call_once):
            result = _call_llm_with_retry(
                req, ctx, 30, "test-model", "test-provider",
                "https://example.com", None, None,
            )

        self.assertEqual(call_count, 1)
        self.assertEqual(get_refusal_counts(), {})


if __name__ == "__main__":
    unittest.main()
