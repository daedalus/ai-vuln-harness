"""Tests for stages/recon.py — recon task building from snippet tags and git history."""

import unittest
from unittest.mock import patch, MagicMock

from ai_vuln_harness.stages.recon import (
    build_recon_tasks,
    _scan_git_security_patches,
    _find_sibling_files,
    _COMMIT_LINE_PREFIX,
)


class BuildReconTasksTests(unittest.TestCase):
    def test_empty_snippets(self):
        tasks = build_recon_tasks([])
        self.assertEqual(tasks, [])

    def test_memory_tag_creates_mem_safety_domain(self):
        snippets = [{"file": "src/buffer.c", "tags": ["memory", "external-input"]}]
        tasks = build_recon_tasks(snippets)
        domains = {t["domain"] for t in tasks}
        self.assertIn("mem-safety", domains)

    def test_auth_tag_creates_auth_domain(self):
        snippets = [{"file": "src/login.c", "tags": ["auth"]}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks[0]["domain"], "auth")

    def test_crypto_tag_creates_crypto_domain(self):
        snippets = [{"file": "src/cipher.c", "tags": ["crypto"]}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks[0]["domain"], "crypto")

    def test_ipc_tag_creates_ipc_domain(self):
        snippets = [{"file": "src/shm.c", "tags": ["ipc"]}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks[0]["domain"], "ipc")

    def test_external_input_creates_data_flow_domain(self):
        snippets = [{"file": "src/http.c", "tags": ["external-input"]}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks[0]["domain"], "data-flow")

    def test_format_string_creates_format_str_domain(self):
        snippets = [{"file": "src/print.c", "tags": ["format-string"]}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks[0]["domain"], "format-str")

    def test_single_snippet_multiple_tags(self):
        snippets = [{"file": "src/all.c", "tags": ["memory", "auth", "crypto", "ipc"]}]
        tasks = build_recon_tasks(snippets)
        domains = {t["domain"] for t in tasks}
        # memory→mem-safety, auth→auth, crypto→crypto, ipc→ipc
        # memory+auth also triggers logic-chain
        for expected in ("mem-safety", "auth", "crypto", "ipc", "logic-chain"):
            self.assertIn(expected, domains)

    def task_has_correct_structure(self):
        snippets = [{"file": "src/buffer.c", "tags": ["memory"]}]
        tasks = build_recon_tasks(snippets)
        task = tasks[0]
        self.assertIn("task_id", task)
        self.assertIn("domain", task)
        self.assertIn("attack_class", task)
        self.assertIn("target_files", task)
        self.assertIn("rationale", task)
        self.assertIn("priority", task)

    def test_target_files_are_sorted(self):
        snippets = [
            {"file": "z.c", "tags": ["memory"]},
            {"file": "a.c", "tags": ["memory"]},
        ]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks[0]["target_files"], ["a.c", "z.c"])

    def test_no_matching_tags_returns_empty(self):
        snippets = [{"file": "src/nothing.c", "tags": ["irrelevant"]}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks, [])

    def test_missing_tags_key(self):
        snippets = [{"file": "src/main.c"}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks, [])

    def test_priority_high_for_mem_safety_data_flow_crypto(self):
        snippets = [
            {"file": "a.c", "tags": ["memory"]},
            {"file": "b.c", "tags": ["external-input"]},
            {"file": "c.c", "tags": ["crypto"]},
        ]
        tasks = build_recon_tasks(snippets)
        for t in tasks:
            self.assertEqual(t["priority"], "high")

    def test_priority_medium_for_auth_ipc_format_str(self):
        snippets = [
            {"file": "a.c", "tags": ["auth"]},
            {"file": "b.c", "tags": ["ipc"]},
            {"file": "c.c", "tags": ["format-string"]},
        ]
        tasks = build_recon_tasks(snippets)
        for t in tasks:
            self.assertEqual(t["priority"], "medium")

    def test_duplicate_files_deduplicated(self):
        snippets = [
            {"file": "shared.c", "tags": ["memory"]},
            {"file": "shared.c", "tags": ["memory"]},
        ]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(len(tasks[0]["target_files"]), 1)


# ===================================================================
# Git-history patch-gap discovery
# ===================================================================


class GitSecurityPatchScanTests(unittest.TestCase):
    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_phase2_oerror_returns_empty(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="abc123 fix overflow\n"),
            FileNotFoundError(),
        ]
        result = _scan_git_security_patches("/fake/repo")
        self.assertEqual(result, set())

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_phase2_nonzero_return_empty(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="abc123 fix overflow\n"),
            MagicMock(returncode=128, stdout="fatal\n"),
        ]
        result = _scan_git_security_patches("/fake/repo")
        self.assertEqual(result, set())

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_no_security_commits_returns_empty(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0, stdout="abc123 feat: add widget\n"
        )
        result = _scan_git_security_patches("/fake/repo")
        self.assertEqual(result, set())

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_security_commit_finds_patched_files(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="abc123 fix overflow in parser\n"),
            MagicMock(
                returncode=0,
                stdout=f"{_COMMIT_LINE_PREFIX}fix overflow in parser\nsrc/parser.c\n",
            ),
        ]
        result = _scan_git_security_patches("/fake/repo")
        self.assertEqual(result, {"src/parser.c"})

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_multiple_patched_files_across_commits(self, mock_run):
        mock_run.side_effect = [
            MagicMock(
                returncode=0, stdout="abc123 CVE-2024-0001\ndef456 sec: auth fix\n"
            ),
            MagicMock(
                returncode=0,
                stdout=(
                    f"{_COMMIT_LINE_PREFIX}CVE-2024-0001\nsrc/parser.c\nsrc/lexer.c\n"
                    f"{_COMMIT_LINE_PREFIX}sec: auth fix\nsrc/login.c\n"
                ),
            ),
        ]
        result = _scan_git_security_patches("/fake/repo")
        self.assertEqual(result, {"src/parser.c", "src/lexer.c", "src/login.c"})

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_non_security_commits_skipped(self, mock_run):
        mock_run.side_effect = [
            MagicMock(
                returncode=0, stdout="abc123 fix overflow\ndef456 refactor: tidy up\n"
            ),
            MagicMock(
                returncode=0,
                stdout=(
                    f"{_COMMIT_LINE_PREFIX}fix overflow\nsrc/parser.c\n"
                    f"{_COMMIT_LINE_PREFIX}refactor: tidy up\nsrc/util.c\n"
                ),
            ),
        ]
        result = _scan_git_security_patches("/fake/repo")
        self.assertEqual(result, {"src/parser.c"})

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_git_not_available_returns_empty(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        result = _scan_git_security_patches("/fake/repo")
        self.assertEqual(result, set())

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_git_non_zero_return_empty(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=128, stdout="fatal: not a git repo\n"
        )
        result = _scan_git_security_patches("/fake/repo")
        self.assertEqual(result, set())

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_empty_history_returns_empty(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="")
        result = _scan_git_security_patches("/fake/repo")
        self.assertEqual(result, set())


class FindSiblingFilesTests(unittest.TestCase):
    def test_empty_patched_returns_empty(self):
        self.assertEqual(_find_sibling_files(set(), {"a.c"}), set())

    def test_same_dir_sibling_found(self):
        patched = {"src/buffer.c"}
        all_files = {"src/buffer.c", "src/lexer.c"}
        self.assertEqual(_find_sibling_files(patched, all_files), {"src/lexer.c"})

    def test_patched_file_excluded(self):
        patched = {"src/a.c", "src/b.c"}
        all_files = {"src/a.c", "src/b.c", "src/c.c"}
        self.assertEqual(_find_sibling_files(patched, all_files), {"src/c.c"})

    def test_different_dir_not_included(self):
        patched = {"src/a.c"}
        all_files = {"src/a.c", "lib/b.c", "other/d.c"}
        self.assertEqual(_find_sibling_files(patched, all_files), set())

    def test_multiple_patched_dirs(self):
        patched = {"src/a.c", "lib/x.c"}
        all_files = {"src/a.c", "src/b.c", "lib/x.c", "lib/y.c", "other/z.c"}
        self.assertEqual(
            _find_sibling_files(patched, all_files), {"src/b.c", "lib/y.c"}
        )

    def test_no_siblings_returns_empty(self):
        patched = {"src/only.c"}
        all_files = {"src/only.c"}
        self.assertEqual(_find_sibling_files(patched, all_files), set())


class GitHistoryIntegrationInBuildReconTasksTests(unittest.TestCase):
    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_no_repo_path_never_calls_git(self, mock_run):
        tasks = build_recon_tasks([{"file": "a.c", "tags": ["memory"]}])
        mock_run.assert_not_called()
        self.assertEqual(len(tasks), 1)

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_no_security_commits_no_patch_gap(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout="abc123 feat: add\n")
        tasks = build_recon_tasks(
            [{"file": "a.c", "tags": ["memory"]}],
            repo_path="/repo",
        )
        domains = [t["domain"] for t in tasks]
        self.assertNotIn("patch-gap", domains)

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_security_commit_creates_patch_gap_domain(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="abc123 fix overflow\n"),
            MagicMock(
                returncode=0,
                stdout=f"{_COMMIT_LINE_PREFIX}fix overflow\nsrc/buffer.c\n",
            ),
        ]
        snippets = [
            {"file": "src/buffer.c", "tags": []},
            {"file": "src/lexer.c", "tags": []},
        ]
        tasks = build_recon_tasks(snippets, repo_path="/repo")
        patch_gap = [t for t in tasks if t["domain"] == "patch-gap"]
        self.assertEqual(len(patch_gap), 1)
        self.assertEqual(patch_gap[0]["target_files"], ["src/lexer.c"])
        self.assertEqual(patch_gap[0]["priority"], "high")
        self.assertIn("git history", patch_gap[0]["rationale"])

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_patched_file_is_not_its_own_sibling(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="abc123 CVE-2024-1234\n"),
            MagicMock(
                returncode=0,
                stdout=f"{_COMMIT_LINE_PREFIX}CVE-2024-1234\nsrc/login.c\n",
            ),
        ]
        snippets = [
            {"file": "src/login.c", "tags": ["auth"]},
            {"file": "src/logout.c", "tags": ["auth"]},
        ]
        tasks = build_recon_tasks(snippets, repo_path="/repo")
        patch_gap = [t for t in tasks if t["domain"] == "patch-gap"]
        self.assertEqual(patch_gap[0]["target_files"], ["src/logout.c"])

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_sibling_only_if_exists_in_snippets(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="abc123 fix format string\n"),
            MagicMock(
                returncode=0,
                stdout=f"{_COMMIT_LINE_PREFIX}fix format string\nsrc/print.c\n",
            ),
        ]
        snippets = [{"file": "src/print.c", "tags": []}]
        tasks = build_recon_tasks(snippets, repo_path="/repo")
        patch_gap = [t for t in tasks if t["domain"] == "patch-gap"]
        self.assertEqual(len(patch_gap), 0)

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_sibling_with_tags_appears_in_both_domains(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="abc123 fix memory corruption\n"),
            MagicMock(
                returncode=0,
                stdout=f"{_COMMIT_LINE_PREFIX}fix memory corruption\nsrc/vuln.c\n",
            ),
        ]
        snippets = [
            {"file": "src/vuln.c", "tags": ["memory"]},
            {"file": "src/vuln2.c", "tags": ["memory", "auth"]},
        ]
        tasks = build_recon_tasks(snippets, repo_path="/repo")
        domains = {t["domain"]: t["target_files"] for t in tasks}
        self.assertIn("mem-safety", domains)
        self.assertIn("auth", domains)
        self.assertIn("patch-gap", domains)
        self.assertIn("src/vuln2.c", domains["patch-gap"])

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_git_error_graceful_tag_tasks_still_returned(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        tasks = build_recon_tasks(
            [{"file": "a.c", "tags": ["memory"]}],
            repo_path="/repo",
        )
        self.assertEqual(len(tasks), 1)
        self.assertEqual(tasks[0]["domain"], "mem-safety")

    @patch("ai_vuln_harness.stages.recon.subprocess.run")
    def test_multiple_patched_dirs_find_siblings_in_each(self, mock_run):
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout="abc123 CVE-2024-0001\n"),
            MagicMock(
                returncode=0,
                stdout=(
                    f"{_COMMIT_LINE_PREFIX}CVE-2024-0001\nsrc/foo/a.c\nlib/bar/x.c\n"
                ),
            ),
        ]
        snippets = [
            {"file": "src/foo/a.c", "tags": []},
            {"file": "src/foo/b.c", "tags": []},
            {"file": "lib/bar/x.c", "tags": []},
            {"file": "lib/bar/y.c", "tags": []},
            {"file": "other/z.c", "tags": []},
        ]
        tasks = build_recon_tasks(snippets, repo_path="/repo")
        patch_gap = [t for t in tasks if t["domain"] == "patch-gap"]
        self.assertEqual(len(patch_gap), 1)
        self.assertIn("src/foo/b.c", patch_gap[0]["target_files"])
        self.assertIn("lib/bar/y.c", patch_gap[0]["target_files"])
        self.assertNotIn("other/z.c", patch_gap[0]["target_files"])


if __name__ == "__main__":
    unittest.main()
