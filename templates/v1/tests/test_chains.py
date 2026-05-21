import unittest

from stages.chains import synthesize_exploit_chains


class ChainSynthesisTests(unittest.TestCase):
    def test_synthesizes_cross_component_chain(self):
        findings = [
            {
                'snippet_id': 's1',
                'file': 'frontend/parser.ts',
                'class': 'auth-bypass',
                'severity': 'HIGH',
                'status': 'confirmed',
                'call_path_verified': True,
            },
            {
                'snippet_id': 's2',
                'file': 'backend/db.py',
                'class': 'sql-injection',
                'severity': 'CRITICAL',
                'status': 'confirmed',
                'call_path_verified': True,
            },
        ]
        chains = synthesize_exploit_chains(findings, snippets=[])
        self.assertEqual(len(chains), 1)
        self.assertTrue(chains[0]['feasible'])
        self.assertIn('cvss', chains[0])
        self.assertIn('mitigations', chains[0])
        self.assertIn('CWE-', chains[0]['steps'][0]['cwe'])

    def test_ignores_unconfirmed_findings(self):
        findings = [
            {'snippet_id': 's1', 'file': 'a.py', 'class': 'xss', 'severity': 'HIGH', 'status': 'raw'},
            {'snippet_id': 's2', 'file': 'b.py', 'class': 'auth', 'severity': 'HIGH', 'status': 'confirmed'},
        ]
        self.assertEqual(synthesize_exploit_chains(findings, snippets=[]), [])


if __name__ == '__main__':
    unittest.main()
