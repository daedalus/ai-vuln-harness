"""Adversarial tests for KL-divergence hallucination detection and cosine
similarity semantic deduplication.

These target boundary conditions, evasion patterns, and failure modes that
the standard unit tests do not cover.
"""

import unittest

from ai_vuln_harness.stages.shield import (
    deduplicate_semantic,
    detect_hallucination_kl,
)


# ===================================================================
# Adversarial: KL-divergence hallucination detection
# ===================================================================


class KlSynonymAttackTests(unittest.TestCase):
    """Model uses synonyms of code identifiers instead of exact matches."""

    def test_synonym_not_in_code(self):
        snippet = {"content": "void allocate_buffer() { char *p = malloc(64); }"}
        finding = {"desc": "alloc_memory in alloc_buffer uses malloc", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertTrue(detected, f"synonyms should be flagged: {reason}")

    def test_partial_match_underscore_variant(self):
        snippet = {"content": "void process_user_data() { char buf[256]; }"}
        finding = {"desc": "process_user_info buffer overflow", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertTrue(detected, f"partial name match should be flagged: {reason}")


class KlSubstringBoundaryTests(unittest.TestCase):
    """Token boundary edge cases (\\b regex)."""

    def test_desc_token_is_prefix_of_code_token(self):
        snippet = {"content": "void initializer_function() { int initialized; }"}
        finding = {"desc": "initializer called before init", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertTrue(
            detected, f'prefix "init" should not match "initializer": {reason}'
        )

    def test_desc_token_is_suffix_of_code_token(self):
        snippet = {"content": "void memcopy_impl() { }"}
        finding = {"desc": "copy_impl function", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertTrue(detected, f'"copy_impl" not in code: {reason}')

    def token_with_digits_not_extracted(self):
        snippet = {"content": "void parse_buf_2() { }"}
        finding = {"desc": "parse_buf second iteration overflow", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertFalse(
            detected, "digits-only variant should not cause false positive"
        )

    def test_mixed_case_variants(self):
        snippet = {
            "content": "void ParseHttpRequest() { char Buffer[256]; int overflow; }"
        }
        finding = {"desc": "ParseHttpRequest Buffer overflow", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertFalse(detected, f"case-normalized tokens should match: {reason}")


class KlDilutionAttackTests(unittest.TestCase):
    """Hide hallucinated term inside a long desc of matching tokens."""

    def test_single_hallucinated_token_diluted(self):
        snippet = {
            "content": (
                "void copy_data() { char source[256]; char dest[256]; "
                "for(int idx=0; idx<256; idx++) { dest[idx] = source[idx]; } "
                "int length = 256; }"
            )
        }
        finding = {
            "desc": (
                "copy_data copies source into dest using idx loop with length boundary. "
                "pointer_arithmetic_underflow occurs when offset is negative."
            ),
            "call_path": [],
        }
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertTrue(
            detected, f"diluted hallucinated term should be caught: {reason}"
        )

    def test_mostly_matching_tokens_passes(self):
        """All desc tokens present in code → should pass."""
        snippet = {
            "content": (
                "void receive_message() { char packet_buffer[1024]; "
                "int received_length = read(0, packet_buffer, 1024); "
                "memcpy(dest, packet_buffer, received_length); }"
            )
        }
        finding = {
            "desc": ("receive_message reads packet_buffer received_length memcpy dest"),
            "call_path": [],
        }
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertFalse(detected, f"all tokens match, should pass: {reason}")


class KlGenericSecurityLanguageTests(unittest.TestCase):
    """Desc uses generic security terms common in any code review."""

    def test_generic_overflow_language_without_code_evidence(self):
        snippet = {"content": "void helper() { int counter = 0; counter++; }"}
        finding = {
            "desc": (
                "buffer overflow possible via heap memory corruption "
                "leading to arbitrary code execution"
            ),
            "call_path": [],
        }
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertTrue(detected, f"generic claims without code evidence: {reason}")

    def test_generic_terms_that_happen_to_match(self):
        snippet = {
            "content": (
                "void buffer_overflow() { char buffer[256]; char memory[256]; "
                "char heap[256]; size_t size = 256; }"
            )
        }
        finding = {"desc": "buffer overflow memory heap size", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertFalse(detected, f"generic terms that match should pass: {reason}")


class KlEdgeCaseTests(unittest.TestCase):
    """Boundary and edge cases."""

    def test_code_with_only_short_identifiers(self):
        snippet = {"content": "int f() { int a; int b; int c; a = b + c; return a; }"}
        finding = {"desc": "integer overflow in arithmetic addition", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertTrue(detected, "code has no tokens >=4 chars, should flag")

    def test_desc_single_token_missing(self):
        snippet = {"content": "void known_function() { do_work(); }"}
        finding = {"desc": "known_function hallucinated_extra", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertTrue(detected, "single extra token should be caught")

    def test_desc_single_token_present(self):
        snippet = {"content": "void exact_match_function() { }"}
        finding = {"desc": "exact_match_function", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertFalse(detected, "single token present should pass")

    def test_desc_tokens_all_too_short(self):
        snippet = {"content": "void abc() { }"}
        finding = {"desc": "a b c d e f g", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=5.0)
        self.assertIn("no-desc-tokens", reason, "single-char tokens should be skipped")

    def test_zero_threshold_flags_everything(self):
        snippet = {"content": "void foo() { int x; }"}
        finding = {"desc": "some random tokens here please", "call_path": []}
        detected, reason = detect_hallucination_kl(finding, snippet, threshold=0.0)
        self.assertTrue(detected, "threshold=0 should flag any mismatch")

    def test_infinite_threshold_never_flags(self):
        snippet = {"content": "void foo() { int x; }"}
        finding = {"desc": "completely unrelated nonsense words here", "call_path": []}
        detected, _ = detect_hallucination_kl(finding, snippet, threshold=1e9)
        self.assertFalse(detected, "infinite threshold should never flag")


# ===================================================================
# Adversarial: Cosine similarity deduplication
# ===================================================================


class CosineWordReorderTests(unittest.TestCase):
    """Same tokens, different order → identical TF vectors."""

    def test_identical_tokens_different_order(self):
        findings = [
            {
                "snippet_id": "a",
                "desc": "heap buffer overflow in parse_url function",
                "severity": "HIGH",
            },
            {
                "snippet_id": "b",
                "desc": "function parse_url overflow buffer heap",
                "severity": "MEDIUM",
            },
        ]
        result = deduplicate_semantic(findings, threshold=0.99)
        self.assertEqual(len(result), 1, "same tokens reordered should collapse")

    def test_word_order_only_different(self):
        from ai_vuln_harness.stages.shield import cosine_similarity as cs

        sim = cs([1.0] * 4, [1.0] * 4)
        self.assertAlmostEqual(sim, 1.0)


class CosineLengthDilutionTests(unittest.TestCase):
    """Very long desc vs very short desc describing same bug."""

    def test_long_verbose_vs_short_same_bug(self):
        findings = [
            {
                "snippet_id": "a",
                "desc": (
                    "heap buffer overflow in parse_url function processing "
                    "oversized input causes memory corruption"
                ),
                "severity": "HIGH",
            },
            {
                "snippet_id": "b",
                "desc": "parse_url heap buffer overflow memory input",
                "severity": "LOW",
            },
        ]
        result = deduplicate_semantic(findings, threshold=0.5)
        self.assertEqual(len(result), 1, "long+short same bug should collapse")
        self.assertEqual(result[0]["severity"], "HIGH")

    def test_extremely_verbose_vs_minimal(self):
        findings = [
            {"snippet_id": "a", "desc": "x", "severity": "HIGH"},
            {
                "snippet_id": "b",
                "desc": (
                    "heap buffer overflow vulnerability in parse_url_extended "
                    "function when attacker controlled input length exceeds "
                    "allocated buffer size causing memory safety violation"
                ),
                "severity": "MEDIUM",
            },
        ]
        result = deduplicate_semantic(findings, threshold=0.8)
        self.assertEqual(
            len(result), 2, "minimal vs verbose different vocab should not merge"
        )


class CosineCollisionTests(unittest.TestCase):
    """Different bugs sharing common security vocabulary."""

    def test_different_bugs_common_vocab_not_merged(self):
        findings = [
            {
                "snippet_id": "a",
                "desc": "buffer overflow in http_parser",
                "severity": "HIGH",
            },
            {
                "snippet_id": "b",
                "desc": "buffer overflow in ftp_handler",
                "severity": "HIGH",
            },
        ]
        result = deduplicate_semantic(findings, threshold=0.95)
        self.assertEqual(
            len(result),
            2,
            "different functions should not collapse despite shared vocab",
        )

    def test_different_classes_same_function_not_merged(self):
        findings = [
            {
                "snippet_id": "a",
                "desc": "integer overflow in parse_input length field",
                "severity": "HIGH",
            },
            {
                "snippet_id": "b",
                "desc": "buffer overflow in parse_input data buffer",
                "severity": "HIGH",
            },
        ]
        result = deduplicate_semantic(findings, threshold=0.8)
        self.assertEqual(
            len(result), 2, "different classes same function should not merge"
        )


class CosineThresholdBoundaryTests(unittest.TestCase):
    """Exact threshold boundary conditions."""

    def test_identical_at_threshold_collapses(self):
        findings = [
            {
                "snippet_id": "a",
                "desc": "use after free in cleanup",
                "severity": "MEDIUM",
            },
            {
                "snippet_id": "b",
                "desc": "use after free in cleanup",
                "severity": "HIGH",
            },
        ]
        result = deduplicate_semantic(findings, threshold=1.0)
        self.assertEqual(len(result), 1, "identical descs should collapse even at 1.0")

    def test_single_word_difference(self):
        findings = [
            {
                "snippet_id": "a",
                "desc": "heap buffer overflow in parse_url",
                "severity": "HIGH",
            },
            {
                "snippet_id": "b",
                "desc": "stack buffer overflow in parse_url",
                "severity": "MEDIUM",
            },
        ]
        result = deduplicate_semantic(findings, threshold=0.9)
        self.assertEqual(len(result), 2, "heap vs stack different with high threshold")

    def test_single_word_difference_low_threshold(self):
        findings = [
            {
                "snippet_id": "a",
                "desc": "heap buffer overflow in parse_url",
                "severity": "HIGH",
            },
            {
                "snippet_id": "b",
                "desc": "stack buffer overflow in parse_url",
                "severity": "MEDIUM",
            },
        ]
        result = deduplicate_semantic(findings, threshold=0.5)
        self.assertEqual(
            len(result), 1, "heap vs stack should collapse at low threshold"
        )


class CosineEdgeCaseTests(unittest.TestCase):
    """Boundary and edge cases for dedup."""

    def test_empty_descs_kept_separate(self):
        findings = [
            {"snippet_id": "a", "desc": "", "severity": "HIGH"},
            {"snippet_id": "b", "desc": "", "severity": "MEDIUM"},
        ]
        result = deduplicate_semantic(findings, threshold=0.85)
        self.assertEqual(len(result), 2, "empty descs should be kept separate")

    def test_single_finding_unchanged(self):
        findings = [{"snippet_id": "a", "desc": "buffer overflow", "severity": "HIGH"}]
        result = deduplicate_semantic(findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["snippet_id"], "a")

    def test_no_desc_key(self):
        findings = [
            {"snippet_id": "a", "severity": "HIGH"},
            {"snippet_id": "b", "severity": "MEDIUM"},
        ]
        result = deduplicate_semantic(findings)
        self.assertEqual(
            len(result), 2, "missing desc key should be handled gracefully"
        )

    def test_all_severities_kept_when_different(self):
        findings = [
            {"snippet_id": "a", "desc": "vuln in func_a", "severity": "CRITICAL"},
            {
                "snippet_id": "b",
                "desc": "vuln in func_b completely different",
                "severity": "INFORMATIONAL",
            },
        ]
        result = deduplicate_semantic(findings, threshold=0.1)
        self.assertEqual(
            len(result), 1, "even very different descs collapse at very low threshold"
        )
        self.assertEqual(result[0]["severity"], "CRITICAL")

    def test_critical_severity_preferred_over_high(self):
        findings = [
            {"snippet_id": "a", "desc": "heap overflow in parser", "severity": "HIGH"},
            {
                "snippet_id": "b",
                "desc": "heap overflow in parser function",
                "severity": "CRITICAL",
            },
        ]
        result = deduplicate_semantic(findings, threshold=0.5)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["severity"], "CRITICAL")


# ===================================================================
# Adversarial: Cross-run regression
# ===================================================================


class RegressionAdversarialTests(unittest.TestCase):
    """Edge cases for cross-run regression drift detection."""

    def setUp(self):
        import tempfile
        from pathlib import Path

        self.tmp = Path(tempfile.mktemp(suffix=".jsonl"))

    def tearDown(self):
        if self.tmp.exists():
            self.tmp.unlink()

    def _reg(self):
        from ai_vuln_harness.stages.runtime import CrossRunRegression

        return CrossRunRegression(self.tmp)

    def test_single_run_no_drift_possible(self):
        r = self._reg()
        r.record_run("t1", [{"class": "buffer-overflow"}])
        self.assertEqual(r.detect_drift(), [])

    def test_two_identical_runs_no_drift(self):
        r = self._reg()
        r.record_run("t1", [{"class": "x"}] * 100)
        r.record_run("t2", [{"class": "x"}] * 100)
        self.assertEqual(r.detect_drift(window=5, threshold=0.15), [])

    def test_many_runs_identical_no_drift(self):
        r = self._reg()
        for i in range(20):
            r.record_run(f"t{i}", [{"class": "a"}, {"class": "b"}])
        self.assertEqual(r.detect_drift(window=5, threshold=0.15), [])

    def test_seesaw_distribution_alarms(self):
        r = self._reg()
        r.record_run("t1", [{"class": "overflow"}] * 100)
        r.record_run("t2", [{"class": "uaf"}] * 100)
        r.record_run("t3", [{"class": "overflow"}] * 100)
        r.record_run("t4", [{"class": "uaf"}] * 100)
        signals = r.detect_drift(window=5, threshold=0.01)
        self.assertGreater(len(signals), 0, "seesaw should trigger drift")

    def test_new_class_appearing(self):
        r = self._reg()
        r.record_run(
            "t1", [{"class": "buffer-overflow"}] * 50 + [{"class": "uaf"}] * 50
        )
        r.record_run(
            "t2",
            [{"class": "buffer-overflow"}] * 50 + [{"class": "format-string"}] * 50,
        )
        signals = r.detect_drift(window=5, threshold=0.01)
        self.assertGreater(len(signals), 0)
        changed = {c["class"] for s in signals for c in s["changed_classes"]}
        self.assertIn(
            "format-string", changed, "new class should appear in changed_classes"
        )
        self.assertIn("uaf", changed, "vanished class should appear in changed_classes")

    def test_empty_findings_handled(self):
        r = self._reg()
        r.record_run("t1", [{"class": "overflow"}])
        r.record_run("t2", [])
        signals = r.detect_drift(window=5, threshold=0.01)
        self.assertGreater(len(signals), 0, "shift to empty should be drift")

    def test_history_file_interrupted_line_skipped(self):
        r = self._reg()
        r.record_run("t1", [{"class": "a"}])
        self.tmp.write_text(self.tmp.read_text() + "garbage line\n")
        r.record_run("t2", [{"class": "b"}])
        signals = r.detect_drift(window=5, threshold=0.01)
        self.assertGreater(len(signals), 0, "should skip corrupted lines gracefully")


if __name__ == "__main__":
    unittest.main()
