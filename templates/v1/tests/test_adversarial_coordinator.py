"""Adversarial tests for stages/coordinator.py — context pack building.

Covers budget boundary conditions, empty/missing fields, duplicate
file entries, overlapping domains, and token accounting edge cases.
"""

import unittest

from stages.coordinator import build_context_packs


class CoordinatorBudgetBoundaryTests(unittest.TestCase):
    """Token budget edge cases."""

    def test_exact_budget_fit(self):
        snippets = [
            {'file': 'a.c', 'token_count': 100},
            {'file': 'b.c', 'token_count': 80},
        ]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow', 'target_files': ['a.c', 'b.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs(snippets, tasks, budget_tokens=90)
        self.assertEqual(len(packs), 1)
        self.assertEqual(len(packs[0]['snippets']), 2)

    def test_budget_split_across_domains(self):
        snippets = [
            {'file': 'a.c', 'token_count': 100},
            {'file': 'b.c', 'token_count': 100},
        ]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow', 'target_files': ['a.c', 'b.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs(snippets, tasks, budget_tokens=70)
        self.assertEqual(len(packs), 2)

    def test_zero_budget_creates_separate_packs(self):
        snippets = [
            {'file': 'a.c', 'token_count': 1},
            {'file': 'b.c', 'token_count': 1},
        ]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow', 'target_files': ['a.c', 'b.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs(snippets, tasks, budget_tokens=0)
        self.assertEqual(len(packs), 2)


class CoordinatorMissingFieldTests(unittest.TestCase):
    """Missing or malformed fields."""

    def test_empty_snippets_list(self):
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow', 'target_files': ['a.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs([], tasks)
        self.assertEqual(len(packs), 0)

    def test_target_file_not_in_snippets(self):
        snippets = [{'file': 'a.c', 'token_count': 100}]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow', 'target_files': ['missing.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs(snippets, tasks)
        self.assertEqual(len(packs), 0)

    def test_missing_token_count_defaults_to_zero(self):
        snippets = [
            {'file': 'a.c'},
            {'file': 'b.c'},
        ]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow', 'target_files': ['a.c', 'b.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs(snippets, tasks)
        self.assertEqual(len(packs), 1)

    def test_negative_token_count(self):
        snippets = [
            {'file': 'a.c', 'token_count': -100},
        ]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow', 'target_files': ['a.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs(snippets, tasks)
        self.assertEqual(len(packs), 1)


class CoordinatorDuplicateFileTests(unittest.TestCase):
    """Duplicate file entries across snippets."""

    def test_duplicate_file_keeps_all_matching_snippets(self):
        snippets = [
            {'file': 'a.c', 'name': 'first', 'token_count': 10},
            {'file': 'a.c', 'name': 'second', 'token_count': 999},
        ]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow', 'target_files': ['a.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs(snippets, tasks)
        self.assertEqual([s['name'] for s in packs[0]['snippets']], ['first', 'second'])


class CoordinatorOverlappingDomainTests(unittest.TestCase):
    """Recon domains with overlapping target files."""

    def test_overlapping_domains_pack_separately(self):
        snippets = [
            {'file': 'shared.c', 'token_count': 50},
            {'file': 'mem_only.c', 'token_count': 50},
        ]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow', 'target_files': ['shared.c', 'mem_only.c'], 'rationale': 'r', 'priority': 'high'},
            {'task_id': 't2', 'domain': 'auth', 'attack_class': 'bypass', 'target_files': ['shared.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs(snippets, tasks)
        domains = {p['agent'] for p in packs}
        self.assertEqual(domains, {'mem', 'auth'})

    def test_missing_task_domain(self):
        snippets = [{'file': 'a.c', 'token_count': 10}]
        tasks = [
            {'task_id': 't1', 'attack_class': 'overflow', 'target_files': ['a.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        with self.assertRaises(KeyError):
            build_context_packs(snippets, tasks)


class CoordinatorNoReconTests(unittest.TestCase):
    """Recon not provided."""

    def test_recon_none_without_fallback_raises(self):
        with self.assertRaises(ValueError):
            build_context_packs([], recon_tasks=None, allow_full_db_fallback=False)

    def test_recon_none_with_fallback(self):
        snippets = [{'file': 'a.c', 'token_count': 10}]
        packs = build_context_packs(snippets, recon_tasks=None, allow_full_db_fallback=True)
        self.assertGreater(len(packs), 0)
        self.assertEqual(packs[0]['agent'], 'all')


class CoordinatorReconTasksVariantsTests(unittest.TestCase):
    """Variant recon task structures."""

    def test_recon_with_empty_target_files(self):
        snippets = [{'file': 'a.c', 'token_count': 10}]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow', 'target_files': [], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs(snippets, tasks)
        self.assertEqual(len(packs), 0)

    def test_recon_target_files_not_in_snippets(self):
        snippets = [{'file': 'a.c', 'token_count': 10}]
        tasks = [
            {'task_id': 't1', 'domain': 'mem', 'attack_class': 'overflow', 'target_files': ['b.c', 'c.c'], 'rationale': 'r', 'priority': 'high'},
        ]
        packs = build_context_packs(snippets, tasks)
        self.assertEqual(len(packs), 0)


if __name__ == '__main__':
    unittest.main()
