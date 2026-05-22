"""Tests for stages/gapfill.py — gap detection and task re-queueing."""

import unittest

from ai_vuln_harness.stages.gapfill import (
    _covered_domains,
    _domain_files,
    _hunted_domains,
    build_gapfill_tasks,
)


# ---------------------------------------------------------------------------
# _hunted_domains
# ---------------------------------------------------------------------------


class HuntedDomainsTests(unittest.TestCase):
    def test_empty_tasks(self):
        self.assertEqual(_hunted_domains([]), set())

    def test_single_domain(self):
        tasks = [{"domain": "mem-safety", "target_files": []}]
        self.assertEqual(_hunted_domains(tasks), {"mem-safety"})

    def test_multiple_domains(self):
        tasks = [
            {"domain": "mem-safety"},
            {"domain": "auth"},
            {"domain": "crypto"},
        ]
        self.assertEqual(_hunted_domains(tasks), {"mem-safety", "auth", "crypto"})

    def test_deduplicates_repeated_domains(self):
        tasks = [{"domain": "auth"}, {"domain": "auth"}]
        self.assertEqual(_hunted_domains(tasks), {"auth"})

    def test_tasks_without_domain_key_ignored(self):
        tasks = [{"attack_class": "mem-safety"}]
        self.assertEqual(_hunted_domains(tasks), set())

    def test_none_domain_ignored(self):
        tasks = [{"domain": None}, {"domain": "auth"}]
        self.assertEqual(_hunted_domains(tasks), {"auth"})


# ---------------------------------------------------------------------------
# _covered_domains
# ---------------------------------------------------------------------------


class CoveredDomainsTests(unittest.TestCase):
    def test_empty_findings(self):
        self.assertEqual(_covered_domains([]), set())

    def test_confirmed_finding_covers_domain(self):
        findings = [{"class": "mem-safety", "status": "confirmed"}]
        self.assertEqual(_covered_domains(findings), {"mem-safety"})

    def test_rejected_finding_does_not_cover(self):
        findings = [{"class": "auth", "status": "rejected"}]
        self.assertEqual(_covered_domains(findings), set())

    def test_raw_finding_does_not_cover(self):
        findings = [{"class": "crypto", "status": "raw"}]
        self.assertEqual(_covered_domains(findings), set())

    def test_domain_field_used_when_class_absent(self):
        findings = [{"domain": "ipc", "status": "confirmed"}]
        self.assertEqual(_covered_domains(findings), {"ipc"})

    def test_attack_class_field_fallback(self):
        findings = [{"attack_class": "data-flow", "status": "confirmed"}]
        self.assertEqual(_covered_domains(findings), {"data-flow"})

    def test_mixed_statuses(self):
        findings = [
            {"class": "mem-safety", "status": "confirmed"},
            {"class": "auth", "status": "rejected"},
            {"class": "crypto", "status": "raw"},
        ]
        self.assertEqual(_covered_domains(findings), {"mem-safety"})

    def test_multiple_confirmed(self):
        findings = [
            {"class": "auth", "status": "confirmed"},
            {"class": "crypto", "status": "confirmed"},
        ]
        self.assertEqual(_covered_domains(findings), {"auth", "crypto"})


# ---------------------------------------------------------------------------
# _domain_files
# ---------------------------------------------------------------------------


class DomainFilesTests(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(_domain_files([]), {})

    def test_single_task(self):
        tasks = [{"domain": "auth", "target_files": ["src/login.c", "src/session.c"]}]
        result = _domain_files(tasks)
        self.assertIn("auth", result)
        self.assertEqual(result["auth"], {"src/login.c", "src/session.c"})

    def test_multiple_tasks_same_domain(self):
        tasks = [
            {"domain": "auth", "target_files": ["src/login.c"]},
            {"domain": "auth", "target_files": ["src/session.c"]},
        ]
        result = _domain_files(tasks)
        self.assertEqual(result["auth"], {"src/login.c", "src/session.c"})

    def test_multiple_domains(self):
        tasks = [
            {"domain": "auth", "target_files": ["src/auth.c"]},
            {"domain": "crypto", "target_files": ["src/crypto.c"]},
        ]
        result = _domain_files(tasks)
        self.assertIn("auth", result)
        self.assertIn("crypto", result)

    def test_task_missing_target_files(self):
        tasks = [{"domain": "auth"}]
        result = _domain_files(tasks)
        # No files to iterate → domain may be absent; fall back to empty set
        self.assertEqual(result.get("auth", set()), set())


# ---------------------------------------------------------------------------
# build_gapfill_tasks
# ---------------------------------------------------------------------------


class BuildGapfillTasksTests(unittest.TestCase):
    def _task(self, domain: str, files: list[str] | None = None) -> dict:
        return {"domain": domain, "target_files": files or [f"src/{domain}.c"]}

    def _finding(self, domain: str, status: str = "rejected") -> dict:
        return {"class": domain, "status": status}

    # --- No gaps ---

    def test_all_domains_confirmed_returns_empty(self):
        tasks = [self._task("auth"), self._task("crypto")]
        findings = [
            self._finding("auth", "confirmed"),
            self._finding("crypto", "confirmed"),
        ]
        result = build_gapfill_tasks(tasks, findings)
        self.assertEqual(result, [])

    def test_empty_existing_tasks_returns_empty(self):
        result = build_gapfill_tasks([], [])
        self.assertEqual(result, [])

    # --- Gap detected ---

    def test_domain_with_no_confirmed_finding_creates_task(self):
        tasks = [self._task("auth", ["src/auth.c"])]
        findings = [self._finding("auth", "rejected")]
        result = build_gapfill_tasks(tasks, findings)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["domain"], "auth")
        self.assertEqual(result[0]["source"], "gapfill")

    def test_gapfill_task_inherits_target_files(self):
        tasks = [self._task("crypto", ["src/cipher.c", "src/rng.c"])]
        findings = []
        result = build_gapfill_tasks(tasks, findings)
        self.assertEqual(
            result[0]["target_files"], sorted(["src/cipher.c", "src/rng.c"])
        )

    def test_confirmed_domain_not_gapfilled(self):
        tasks = [self._task("auth"), self._task("crypto")]
        findings = [self._finding("auth", "confirmed")]
        result = build_gapfill_tasks(tasks, findings)
        domains = {t["domain"] for t in result}
        self.assertNotIn("auth", domains)
        self.assertIn("crypto", domains)

    # --- max_tasks cap ---

    def test_max_tasks_respected(self):
        tasks = [
            self._task(d)
            for d in ("auth", "crypto", "ipc", "data-flow", "mem-safety", "format-str")
        ]
        result = build_gapfill_tasks(tasks, [], max_tasks=3)
        self.assertEqual(len(result), 3)

    def test_default_max_tasks_is_five(self):
        tasks = [self._task(d) for d in ("a", "b", "c", "d", "e", "f", "g")]
        result = build_gapfill_tasks(tasks, [])
        self.assertLessEqual(len(result), 5)

    # --- Task structure ---

    def test_task_has_required_keys(self):
        tasks = [self._task("auth")]
        result = build_gapfill_tasks(tasks, [])
        t = result[0]
        for key in (
            "task_id",
            "domain",
            "attack_class",
            "target_files",
            "rationale",
            "priority",
            "source",
        ):
            self.assertIn(key, t)

    def test_task_id_contains_domain(self):
        tasks = [self._task("auth")]
        result = build_gapfill_tasks(tasks, [])
        self.assertIn("auth", result[0]["task_id"])

    def test_priority_is_medium(self):
        tasks = [self._task("auth")]
        result = build_gapfill_tasks(tasks, [])
        self.assertEqual(result[0]["priority"], "medium")

    def test_rationale_mentions_gapfill(self):
        tasks = [self._task("auth")]
        result = build_gapfill_tasks(tasks, [])
        self.assertIn("Gapfill", result[0]["rationale"])

    # --- scope_notes forwarding ---

    def test_scope_notes_forwarded(self):
        tasks = [self._task("auth")]
        result = build_gapfill_tasks(tasks, [], scope_notes="Ignore port 1025")
        self.assertEqual(result[0]["scope_notes"], "Ignore port 1025")

    def test_no_scope_notes_key_when_absent(self):
        tasks = [self._task("auth")]
        result = build_gapfill_tasks(tasks, [])
        self.assertNotIn("scope_notes", result[0])

    # --- Multiple domains in one run ---

    def test_multiple_gap_domains_all_emitted(self):
        tasks = [self._task("auth"), self._task("crypto")]
        result = build_gapfill_tasks(tasks, [])
        domains = {t["domain"] for t in result}
        self.assertEqual(domains, {"auth", "crypto"})

    def test_result_is_deterministically_ordered(self):
        tasks = [self._task("crypto"), self._task("auth"), self._task("ipc")]
        r1 = build_gapfill_tasks(tasks, [])
        r2 = build_gapfill_tasks(tasks, [])
        self.assertEqual([t["domain"] for t in r1], [t["domain"] for t in r2])


if __name__ == "__main__":
    unittest.main()
