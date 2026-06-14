"""Tests for the CVE corpus loader and domain filter."""

import json
import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.cve_corpus import (
    _class_to_domain,
    filter_cves_by_domain,
    format_cve_entries,
    load_cve_corpus,
    suppress_known_cves,
)


class LoadCveCorpusTests(unittest.TestCase):
    def test_load_empty_corpus(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as f:
            json.dump([], f)
            f.flush()
            result = load_cve_corpus(Path(f.name))
        self.assertEqual(result, [])

    def test_load_single_entry(self):
        entry = {
            "cve_id": "CVE-2024-1234",
            "description": "Buffer overflow in foo()",
            "class": "buffer-overflow",
            "file": "src/foo.c",
            "function": "foo",
            "severity": "HIGH",
        }
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as f:
            json.dump([entry], f)
            f.flush()
            result = load_cve_corpus(Path(f.name))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cve_id"], "CVE-2024-1234")
        self.assertEqual(result[0]["class"], "buffer-overflow")

    def test_load_missing_cve_id_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as f:
            json.dump([{"class": "buffer-overflow"}], f)
            f.flush()
            with self.assertRaises(ValueError):
                load_cve_corpus(Path(f.name))

    def test_load_not_a_list_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as f:
            json.dump({"cve_id": "CVE-2024-1234"}, f)
            f.flush()
            with self.assertRaises(ValueError):
                load_cve_corpus(Path(f.name))

    def test_load_entry_not_a_dict_raises(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json") as f:
            json.dump(["not-a-dict"], f)
            f.flush()
            with self.assertRaises(ValueError):
                load_cve_corpus(Path(f.name))

    def test_default_file_format(self):
        pkg_dir = Path(__file__).resolve().parent.parent
        default_path = pkg_dir / "src/ai_vuln_harness/config/cve_corpus.json"
        self.assertTrue(default_path.exists())
        result = load_cve_corpus(default_path)
        self.assertEqual(result, [])


class ClassToDomainTests(unittest.TestCase):
    def test_buffer_overflow_maps_to_mem_safety(self):
        self.assertEqual(_class_to_domain("buffer-overflow"), "mem-safety")

    def test_use_after_free_maps_to_mem_safety(self):
        self.assertEqual(_class_to_domain("use-after-free"), "mem-safety")

    def test_format_string_maps_to_format_str(self):
        self.assertEqual(_class_to_domain("format-string"), "format-str")

    def test_weak_crypto_maps_to_crypto(self):
        self.assertEqual(_class_to_domain("weak-crypto"), "crypto")

    def test_unknown_class_returns_none(self):
        self.assertIsNone(_class_to_domain("unknown-class"))

    def test_normalizes_underscores(self):
        self.assertEqual(_class_to_domain("buffer_overflow"), "mem-safety")

    def test_normalizes_spaces(self):
        self.assertEqual(_class_to_domain("use after free"), "mem-safety")

    def test_case_insensitive(self):
        self.assertEqual(_class_to_domain("Buffer-Overflow"), "mem-safety")


class FilterCvesByDomainTests(unittest.TestCase):
    def setUp(self):
        self.corpus = [
            {"cve_id": "CVE-2024-0001", "class": "buffer-overflow"},
            {"cve_id": "CVE-2024-0002", "class": "use-after-free"},
            {"cve_id": "CVE-2024-0003", "class": "weak-crypto"},
            {"cve_id": "CVE-2024-0004", "class": "format-string"},
            {"cve_id": "CVE-2024-0005", "class": ""},
        ]

    def test_filters_mem_safety(self):
        result = filter_cves_by_domain(self.corpus, "mem-safety")
        cve_ids = {e["cve_id"] for e in result}
        self.assertEqual(cve_ids, {"CVE-2024-0001", "CVE-2024-0002"})

    def test_filters_crypto(self):
        result = filter_cves_by_domain(self.corpus, "crypto")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cve_id"], "CVE-2024-0003")

    def test_filters_format_str(self):
        result = filter_cves_by_domain(self.corpus, "format-str")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["cve_id"], "CVE-2024-0004")

    def test_domain_with_no_matches_returns_empty(self):
        result = filter_cves_by_domain(self.corpus, "secrets")
        self.assertEqual(result, [])

    def test_domain_all_returns_full_corpus(self):
        result = filter_cves_by_domain(self.corpus, "all")
        self.assertEqual(len(result), 5)

    def test_empty_class_is_excluded(self):
        result = filter_cves_by_domain(self.corpus, "mem-safety")
        for e in result:
            self.assertTrue(e["class"])


class FormatCveEntriesTests(unittest.TestCase):
    def test_empty_entries(self):
        result = format_cve_entries([])
        self.assertIn("(none)", result)

    def test_single_entry(self):
        entries = [
            {
                "cve_id": "CVE-2024-0001",
                "class": "buffer-overflow",
                "description": "test",
            }
        ]
        result = format_cve_entries(entries)
        self.assertIn("CVE-2024-0001", result)
        self.assertIn("buffer-overflow", result)
        self.assertIn("test", result)

    def test_multiple_entries(self):
        entries = [
            {
                "cve_id": "CVE-2024-0001",
                "class": "buffer-overflow",
                "description": "foo",
            },
            {
                "cve_id": "CVE-2024-0002",
                "class": "use-after-free",
                "description": "bar",
            },
        ]
        result = format_cve_entries(entries)
        self.assertIn("CVE-2024-0001", result)
        self.assertIn("CVE-2024-0002", result)


class SuppressKnownCvesTests(unittest.TestCase):
    """Tests for suppress_known_cves() — all 6 refinement layers."""

    def test_empty_corpus_no_suppression(self):
        findings = [{"desc": "SQL injection", "class": "sql-injection"}]
        novel, known = suppress_known_cves(findings, [])
        self.assertEqual(len(novel), 1)
        self.assertEqual(len(known), 0)

    def test_exact_cve_id_match(self):
        """Layer 1: exact CVE ID mention (fast path)."""
        findings = [
            {"desc": "Buffer overflow related to CVE-2024-12345 in parser", "class": "buffer-overflow"},
            {"desc": "Novel integer overflow", "class": "integer-overflow"},
        ]
        corpus = [
            {"cve_id": "CVE-2024-12345", "class": "buffer-overflow", "description": "Buffer overflow in parser"},
        ]
        novel, known = suppress_known_cves(findings, corpus)
        self.assertEqual(len(novel), 1)
        self.assertEqual(len(known), 1)
        self.assertIn("CVE-2024-12345", known[0]["suppression_reason"])
        self.assertEqual(known[0]["suppression_confidence"], 1.0)

    def test_hard_negative_different_file(self):
        """Layer 5: different file → no suppression."""
        findings = [
            {"desc": "Buffer overflow", "class": "buffer-overflow", "file": "src/parser.c"},
        ]
        corpus = [
            {"cve_id": "CVE-2024-0001", "class": "buffer-overflow", "description": "Buffer overflow in parser", "file": "src/network.c"},
        ]
        novel, known = suppress_known_cves(findings, corpus, threshold=0.3)
        self.assertEqual(len(novel), 1)
        self.assertEqual(len(known), 0)

    def test_same_file_allows_suppression(self):
        """Layer 5: same file allows suppression."""
        findings = [
            {"desc": "Buffer overflow in parsing", "class": "buffer-overflow", "file": "src/parser.c"},
        ]
        corpus = [
            {"cve_id": "CVE-2024-0001", "class": "buffer-overflow", "description": "Buffer overflow in parser module", "file": "src/parser.c"},
        ]
        novel, known = suppress_known_cves(findings, corpus, threshold=0.3)
        self.assertEqual(len(known), 1)

    def test_confidence_score_in_result(self):
        """Layer 6: suppression_confidence should be set."""
        findings = [
            {"desc": "Matches CVE-2024-33333", "class": "xss"},
        ]
        corpus = [
            {"cve_id": "CVE-2024-33333", "class": "xss", "description": "XSS in template"},
        ]
        _, known = suppress_known_cves(findings, corpus)
        self.assertIn("suppression_confidence", known[0])
        self.assertGreater(known[0]["suppression_confidence"], 0)

    def test_multiple_findings_mixed(self):
        """Mix of exact, semantic, and novel findings."""
        findings = [
            {"desc": "Matches CVE-2024-0001 exactly", "class": "buffer-overflow"},
            {"desc": "Novel SSRF via redirect", "class": "ssrf"},
            {"desc": "Also matches CVE-2024-0002", "class": "sql-injection"},
        ]
        corpus = [
            {"cve_id": "CVE-2024-0001", "class": "buffer-overflow", "description": "Buffer overflow"},
            {"cve_id": "CVE-2024-0002", "class": "sql-injection", "description": "SQL injection in login"},
        ]
        novel, known = suppress_known_cves(findings, corpus)
        self.assertEqual(len(novel), 1)
        self.assertEqual(len(known), 2)
        self.assertEqual(novel[0]["class"], "ssrf")

    def test_rich_text_encoding_includes_cwe(self):
        """Layer 4: CWE should be part of the text encoding."""
        from ai_vuln_harness.stages.cve_corpus import _build_finding_text
        f = {"class": "buffer-overflow", "cwe": "CWE-120", "desc": "Stack overflow", "file": "src/main.c", "function": "parse"}
        text = _build_finding_text(f)
        self.assertIn("CWE-120", text)
        self.assertIn("src/main.c", text)
        self.assertIn("parse", text)

    def test_no_match_without_embeddings(self):
        """Without embeddings, only exact CVE ID matches work."""
        findings = [
            {"desc": "SQL injection in login", "class": "sql-injection"},
        ]
        corpus = [
            {"cve_id": "CVE-2024-11111", "class": "buffer-overflow", "description": "Buffer overflow in parser"},
        ]
        novel, known = suppress_known_cves(findings, corpus)
        self.assertEqual(len(novel), 1)
        self.assertEqual(len(known), 0)
