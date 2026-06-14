"""Tests for refusal detection in stages/runtime.py."""

import json
import unittest
import urllib.request
import ssl
from unittest.mock import patch, MagicMock

from ai_vuln_harness.stages.runtime import (
    _is_refusal,
    _refusal_counts,
    _mutate_prompt,
    _rebuild_request_with_prompt,
    _call_llm_with_retry,
    _REFUSAL_MUTATIONS,
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


class PromptMutationTests(unittest.TestCase):
    """Tests for _mutate_prompt and _rebuild_request_with_prompt."""

    def test_mutate_prompt_attempt_0(self):
        """First mutation adds security research preamble."""
        result = _mutate_prompt("analyze this code", 0)
        self.assertIn("security research", result)
        self.assertIn("analyze this code", result)

    def test_mutate_prompt_attempt_1(self):
        """Second mutation adds defensive audit framing."""
        result = _mutate_prompt("analyze this code", 1)
        self.assertIn("defensive security audit", result)
        self.assertIn("analyze this code", result)

    def test_mutate_prompt_attempt_2(self):
        """Third mutation uses empty preamble (strips trigger)."""
        result = _mutate_prompt("analyze this code", 2)
        self.assertEqual(result, "analyze this code")

    def test_mutate_prompt_high_attempt_clamps(self):
        """Attempts beyond available mutations use last mutation."""
        result = _mutate_prompt("test", 99)
        self.assertEqual(result, "test")

    def test_rebuild_request_preserves_method_and_headers(self):
        """Rebuilt request keeps original URL, headers, method."""
        payload = {
            "model": "test",
            "messages": [{"role": "user", "content": "original"}],
        }
        req = urllib.request.Request(
            url="https://example.com/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json", "Authorization": "Bearer key"},
            method="POST",
        )
        new_req = _rebuild_request_with_prompt(req, "mutated prompt")
        self.assertEqual(new_req.full_url, req.full_url)
        self.assertEqual(new_req.headers.get("Authorization"), "Bearer key")

    def test_rebuild_request_replaces_user_message(self):
        """Rebuilt request has mutated user message."""
        payload = {
            "model": "test",
            "messages": [
                {"role": "system", "content": "You are helpful"},
                {"role": "user", "content": "original prompt"},
            ],
        }
        req = urllib.request.Request(
            url="https://example.com/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        new_req = _rebuild_request_with_prompt(req, "mutated prompt")
        new_payload = json.loads(new_req.data.decode())
        messages = new_payload["messages"]
        self.assertEqual(messages[0]["role"], "system")
        self.assertEqual(messages[0]["content"], "You are helpful")
        self.assertEqual(messages[1]["role"], "user")
        self.assertEqual(messages[1]["content"], "mutated prompt")

    def test_rebuild_request_preserves_system_message(self):
        """System message is not modified during prompt mutation."""
        payload = {
            "model": "test",
            "messages": [
                {"role": "system", "content": "system prompt"},
                {"role": "user", "content": "user prompt"},
            ],
        }
        req = urllib.request.Request(
            url="https://example.com/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        new_req = _rebuild_request_with_prompt(req, "changed")
        new_payload = json.loads(new_req.data.decode())
        self.assertEqual(new_payload["messages"][0]["content"], "system prompt")


class RefusalRetryTests(unittest.TestCase):
    """Tests for refusal retry logic in _call_llm_with_retry."""

    def setUp(self):
        reset_refusal_counts()

    def _make_request(self, prompt="analyze this code"):
        payload = {
            "model": "test",
            "messages": [{"role": "user", "content": prompt}],
        }
        req = urllib.request.Request(
            url="https://example.com/chat/completions",
            data=json.dumps(payload).encode(),
            headers={"Content-Type": "application/json"},
        )
        return req, ssl.create_default_context()

    def test_refusal_retries_then_succeeds(self):
        """First call returns refusal, second call returns valid content."""
        call_count = 0
        refusal_content = "I'm unable to assist with that request."
        seen_prompts = []

        def mock_call_once(req, ctx, timeout, model_name, provider):
            nonlocal call_count
            call_count += 1
            payload = json.loads(req.data.decode())
            user_msg = payload.get("messages", [{}])[-1].get("content", "")
            seen_prompts.append(user_msg)
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
        # Verify prompt was mutated on retry
        self.assertEqual(seen_prompts[0], "analyze this code")
        self.assertIn("security research", seen_prompts[1])

    def test_refusal_retries_exhausted(self):
        """All 3 attempts return refusal — returns refusal content."""
        seen_prompts = []

        def mock_call_once(req, ctx, timeout, model_name, provider):
            payload = json.loads(req.data.decode())
            user_msg = payload.get("messages", [{}])[-1].get("content", "")
            seen_prompts.append(user_msg)
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
        # Verify prompt mutated on each retry
        self.assertEqual(seen_prompts[0], "analyze this code")
        self.assertIn("security research", seen_prompts[1])
        self.assertIn("defensive security audit", seen_prompts[2])

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
