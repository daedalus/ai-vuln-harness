"""Tests for stages/recon.py — recon task building from snippet tags."""

import unittest

from stages.recon import build_recon_tasks


class BuildReconTasksTests(unittest.TestCase):
    def test_empty_snippets(self):
        tasks = build_recon_tasks([])
        self.assertEqual(tasks, [])

    def test_memory_tag_creates_mem_safety_domain(self):
        snippets = [{'file': 'src/buffer.c', 'tags': ['memory', 'external-input']}]
        tasks = build_recon_tasks(snippets)
        domains = {t['domain'] for t in tasks}
        self.assertIn('mem-safety', domains)

    def test_auth_tag_creates_auth_domain(self):
        snippets = [{'file': 'src/login.c', 'tags': ['auth']}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks[0]['domain'], 'auth')

    def test_crypto_tag_creates_crypto_domain(self):
        snippets = [{'file': 'src/cipher.c', 'tags': ['crypto']}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks[0]['domain'], 'crypto')

    def test_ipc_tag_creates_ipc_domain(self):
        snippets = [{'file': 'src/shm.c', 'tags': ['ipc']}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks[0]['domain'], 'ipc')

    def test_external_input_creates_data_flow_domain(self):
        snippets = [{'file': 'src/http.c', 'tags': ['external-input']}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks[0]['domain'], 'data-flow')

    def test_format_string_creates_format_str_domain(self):
        snippets = [{'file': 'src/print.c', 'tags': ['format-string']}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks[0]['domain'], 'format-str')

    def test_single_snippet_multiple_tags(self):
        snippets = [{'file': 'src/all.c', 'tags': ['memory', 'auth', 'crypto', 'ipc']}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(len(tasks), 4)

    def task_has_correct_structure(self):
        snippets = [{'file': 'src/buffer.c', 'tags': ['memory']}]
        tasks = build_recon_tasks(snippets)
        task = tasks[0]
        self.assertIn('task_id', task)
        self.assertIn('domain', task)
        self.assertIn('attack_class', task)
        self.assertIn('target_files', task)
        self.assertIn('rationale', task)
        self.assertIn('priority', task)

    def test_target_files_are_sorted(self):
        snippets = [
            {'file': 'z.c', 'tags': ['memory']},
            {'file': 'a.c', 'tags': ['memory']},
        ]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks[0]['target_files'], ['a.c', 'z.c'])

    def test_no_matching_tags_returns_empty(self):
        snippets = [{'file': 'src/nothing.c', 'tags': ['irrelevant']}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks, [])

    def test_missing_tags_key(self):
        snippets = [{'file': 'src/main.c'}]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(tasks, [])

    def test_priority_high_for_mem_safety_data_flow_crypto(self):
        snippets = [
            {'file': 'a.c', 'tags': ['memory']},
            {'file': 'b.c', 'tags': ['external-input']},
            {'file': 'c.c', 'tags': ['crypto']},
        ]
        tasks = build_recon_tasks(snippets)
        for t in tasks:
            self.assertEqual(t['priority'], 'high')

    def test_priority_medium_for_auth_ipc_format_str(self):
        snippets = [
            {'file': 'a.c', 'tags': ['auth']},
            {'file': 'b.c', 'tags': ['ipc']},
            {'file': 'c.c', 'tags': ['format-string']},
        ]
        tasks = build_recon_tasks(snippets)
        for t in tasks:
            self.assertEqual(t['priority'], 'medium')

    def test_duplicate_files_deduplicated(self):
        snippets = [
            {'file': 'shared.c', 'tags': ['memory']},
            {'file': 'shared.c', 'tags': ['memory']},
        ]
        tasks = build_recon_tasks(snippets)
        self.assertEqual(len(tasks[0]['target_files']), 1)


if __name__ == '__main__':
    unittest.main()
