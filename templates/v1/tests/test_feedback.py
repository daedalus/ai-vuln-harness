"""Tests for stages/feedback.py — trace-seeded Hunt task generation."""

import unittest

from stages.feedback import _sibling_files, build_feedback_tasks


# ---------------------------------------------------------------------------
# _sibling_files
# ---------------------------------------------------------------------------


class SiblingFilesTests(unittest.TestCase):
    def test_same_dir_siblings_returned(self):
        result = _sibling_files(
            "src/parser.c", {"src/parser.c", "src/lexer.c", "src/token.c"}
        )
        self.assertIn("src/lexer.c", result)
        self.assertIn("src/token.c", result)

    def test_source_file_excluded_from_siblings(self):
        result = _sibling_files("src/parser.c", {"src/parser.c", "src/lexer.c"})
        self.assertNotIn("src/parser.c", result)

    def test_different_dir_excluded(self):
        result = _sibling_files("src/parser.c", {"src/parser.c", "lib/other.c"})
        self.assertNotIn("lib/other.c", result)

    def test_empty_all_files(self):
        self.assertEqual(_sibling_files("src/a.c", set()), [])

    def test_only_source_in_dir(self):
        self.assertEqual(_sibling_files("src/a.c", {"src/a.c"}), [])

    def test_exclude_already_covered(self):
        all_files = {"src/a.c", "src/b.c", "src/c.c"}
        result = _sibling_files("src/a.c", all_files, exclude={"src/b.c"})
        self.assertNotIn("src/b.c", result)
        self.assertIn("src/c.c", result)

    def test_result_is_sorted(self):
        all_files = {"dir/z.c", "dir/a.c", "dir/m.c"}
        result = _sibling_files("dir/z.c", all_files)
        self.assertEqual(result, sorted(result))

    def test_nested_dir_match(self):
        all_files = {"src/parser/lexer.c", "src/parser/token.c", "src/other/foo.c"}
        result = _sibling_files("src/parser/lexer.c", all_files)
        self.assertIn("src/parser/token.c", result)
        self.assertNotIn("src/other/foo.c", result)


# ---------------------------------------------------------------------------
# build_feedback_tasks
# ---------------------------------------------------------------------------


class BuildFeedbackTasksTests(unittest.TestCase):
    def _finding(self, file: str, attack_class: str) -> dict:
        return {
            "file": file,
            "class": attack_class,
            "trace_status": "confirmed",
            "status": "confirmed",
        }

    def _snippet(self, file: str) -> dict:
        return {"file": file, "id": file}

    # --- No siblings / empty inputs ---

    def test_empty_findings_returns_empty(self):
        result = build_feedback_tasks([], [self._snippet("src/a.c")])
        self.assertEqual(result, [])

    def test_empty_snippets_returns_empty(self):
        findings = [self._finding("src/a.c", "mem-safety")]
        result = build_feedback_tasks(findings, [])
        self.assertEqual(result, [])

    def test_no_siblings_returns_empty(self):
        findings = [self._finding("src/a.c", "mem-safety")]
        snippets = [self._snippet("src/a.c")]  # source file only
        result = build_feedback_tasks(findings, snippets)
        self.assertEqual(result, [])

    # --- Basic sibling generation ---

    def test_sibling_file_becomes_target(self):
        findings = [self._finding("src/parser.c", "mem-safety")]
        snippets = [self._snippet("src/parser.c"), self._snippet("src/lexer.c")]
        result = build_feedback_tasks(findings, snippets)
        self.assertEqual(len(result), 1)
        self.assertIn("src/lexer.c", result[0]["target_files"])

    def test_task_has_correct_attack_class(self):
        findings = [self._finding("src/a.c", "auth")]
        snippets = [self._snippet("src/a.c"), self._snippet("src/b.c")]
        result = build_feedback_tasks(findings, snippets)
        self.assertEqual(result[0]["attack_class"], "auth")
        self.assertEqual(result[0]["domain"], "auth")

    def test_task_source_is_feedback(self):
        findings = [self._finding("src/a.c", "auth")]
        snippets = [self._snippet("src/a.c"), self._snippet("src/b.c")]
        result = build_feedback_tasks(findings, snippets)
        self.assertEqual(result[0]["source"], "feedback")

    def test_seeded_by_field_set(self):
        findings = [self._finding("src/a.c", "auth")]
        snippets = [self._snippet("src/a.c"), self._snippet("src/b.c")]
        result = build_feedback_tasks(findings, snippets)
        self.assertEqual(result[0]["seeded_by"], "src/a.c")

    def test_priority_is_high(self):
        findings = [self._finding("src/a.c", "auth")]
        snippets = [self._snippet("src/a.c"), self._snippet("src/b.c")]
        result = build_feedback_tasks(findings, snippets)
        self.assertEqual(result[0]["priority"], "high")

    # --- already_covered exclusion ---

    def test_already_covered_sibling_excluded(self):
        findings = [self._finding("src/a.c", "auth")]
        snippets = [
            self._snippet("src/a.c"),
            self._snippet("src/b.c"),
            self._snippet("src/c.c"),
        ]
        result = build_feedback_tasks(findings, snippets, already_covered={"src/b.c"})
        self.assertNotIn("src/b.c", result[0]["target_files"])
        self.assertIn("src/c.c", result[0]["target_files"])

    def test_all_siblings_covered_returns_empty(self):
        findings = [self._finding("src/a.c", "auth")]
        snippets = [self._snippet("src/a.c"), self._snippet("src/b.c")]
        result = build_feedback_tasks(findings, snippets, already_covered={"src/b.c"})
        self.assertEqual(result, [])

    # --- Deduplication on (parent_dir, attack_class) ---

    def test_same_dir_same_class_emits_one_task(self):
        findings = [
            self._finding("src/a.c", "auth"),
            self._finding("src/b.c", "auth"),
        ]
        snippets = [
            self._snippet("src/a.c"),
            self._snippet("src/b.c"),
            self._snippet("src/c.c"),
        ]
        result = build_feedback_tasks(findings, snippets)
        self.assertEqual(len(result), 1)

    def test_different_class_same_dir_emits_separate_tasks(self):
        findings = [
            self._finding("src/a.c", "auth"),
            self._finding("src/a.c", "crypto"),
        ]
        snippets = [self._snippet("src/a.c"), self._snippet("src/b.c")]
        result = build_feedback_tasks(findings, snippets)
        classes = {t["attack_class"] for t in result}
        self.assertEqual(classes, {"auth", "crypto"})

    # --- max_tasks cap ---

    def test_max_tasks_respected(self):
        snippets = [self._snippet(f"dir{i}/a.c") for i in range(15)] + [
            self._snippet(f"dir{i}/b.c") for i in range(15)
        ]
        findings = [self._finding(f"dir{i}/a.c", "auth") for i in range(15)]
        result = build_feedback_tasks(findings, snippets, max_tasks=5)
        self.assertLessEqual(len(result), 5)

    def test_default_max_tasks_is_ten(self):
        snippets = [self._snippet(f"dir{i}/a.c") for i in range(15)] + [
            self._snippet(f"dir{i}/b.c") for i in range(15)
        ]
        findings = [self._finding(f"dir{i}/a.c", "auth") for i in range(15)]
        result = build_feedback_tasks(findings, snippets)
        self.assertLessEqual(len(result), 10)

    # --- scope_notes forwarding ---

    def test_scope_notes_forwarded(self):
        findings = [self._finding("src/a.c", "auth")]
        snippets = [self._snippet("src/a.c"), self._snippet("src/b.c")]
        result = build_feedback_tasks(
            findings, snippets, scope_notes="Exclude test harness"
        )
        self.assertEqual(result[0]["scope_notes"], "Exclude test harness")

    def test_no_scope_notes_key_when_absent(self):
        findings = [self._finding("src/a.c", "auth")]
        snippets = [self._snippet("src/a.c"), self._snippet("src/b.c")]
        result = build_feedback_tasks(findings, snippets)
        self.assertNotIn("scope_notes", result[0])

    # --- Finding with missing fields ---

    def test_finding_with_no_file_skipped(self):
        findings = [{"class": "auth", "status": "confirmed"}]
        snippets = [self._snippet("src/a.c"), self._snippet("src/b.c")]
        result = build_feedback_tasks(findings, snippets)
        self.assertEqual(result, [])

    def test_finding_with_no_attack_class_skipped(self):
        findings = [{"file": "src/a.c", "status": "confirmed"}]
        snippets = [self._snippet("src/a.c"), self._snippet("src/b.c")]
        result = build_feedback_tasks(findings, snippets)
        self.assertEqual(result, [])

    # --- rationale ---

    def test_rationale_mentions_feedback_and_source_file(self):
        findings = [self._finding("src/a.c", "auth")]
        snippets = [self._snippet("src/a.c"), self._snippet("src/b.c")]
        result = build_feedback_tasks(findings, snippets)
        self.assertIn("Feedback", result[0]["rationale"])
        self.assertIn("src/a.c", result[0]["rationale"])


if __name__ == "__main__":
    unittest.main()
