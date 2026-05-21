import unittest

from stages.recon import build_dependency_graph, build_recon_tasks


class ReconSupplyChainTests(unittest.TestCase):
    def test_build_dependency_graph_collects_external_deps(self):
        snippets = [
            {'file': 'src/a.py', 'imports': ['requests', 'local.module']},
            {'file': 'src/b.ts', 'imports': ['@scope/pkg/submodule', './local']},
        ]
        graph = build_dependency_graph(snippets)
        self.assertIn('requests', graph['external_dependencies'])
        self.assertIn('@scope/pkg', graph['external_dependencies'])
        self.assertNotIn('./local', graph['external_dependencies'])

    def test_build_recon_tasks_adds_supply_chain_domain(self):
        snippets = [
            {'file': 'src/a.py', 'tags': [], 'imports': ['requests']},
            {'file': 'src/b.py', 'tags': ['auth'], 'imports': []},
        ]
        tasks = build_recon_tasks(snippets)
        by_domain = {t['domain']: t for t in tasks}
        self.assertIn('supply-chain', by_domain)
        self.assertEqual(by_domain['supply-chain']['task_type'], 'supply_chain')
        self.assertIn('requests', by_domain['supply-chain']['cross_repo_targets'])
        self.assertIn('src/a.py', by_domain['supply-chain']['target_files'])


if __name__ == '__main__':
    unittest.main()
