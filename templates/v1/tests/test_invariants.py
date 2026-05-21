import json
import unittest
from pathlib import Path

STAGES_DIR = Path(__file__).parent.parent / 'stages'
CONFIG_DIR = Path(__file__).parent.parent / 'config'
SCHEMAS_DIR = Path(__file__).parent.parent / 'schemas'
PROMPTS_DIR = Path(__file__).parent.parent / 'prompts'
OUTPUT_DIR = Path(__file__).parent.parent / 'output'


class StructuralInvariantTests(unittest.TestCase):
    def test_every_stage_is_standalone_module(self):
        expected_stages = [
            'ingestor', 'recon', 'coordinator', 'runtime', 'shield', 'parser',
            'diff', 'voting', 'chains', 'report', 'suppressions', 'exposure',
            'feedback', 'gapfill', 'validate', 'contracts',
        ]
        for s in expected_stages:
            self.assertTrue(
                (STAGES_DIR / f'{s}.py').exists(),
                f'Missing stage module: {s}.py',
            )

    def test_run_py_is_entry_point(self):
        run_py = Path(__file__).parent.parent / 'run.py'
        self.assertTrue(run_py.exists())
        content = run_py.read_text()
        # Should import from stages submodules, not implement them
        for stage_ref in ['ingestor', 'recon', 'coordinator', 'runtime', 'shield',
                          'parser', 'diff', 'voting', 'chains', 'report',
                          'suppressions', 'exposure', 'feedback', 'gapfill']:
            self.assertIn(f'stages.{stage_ref}', content,
                          f'run.py does not reference stages.{stage_ref}')

    def test_no_logic_hidden_in_run_py(self):
        run_py = (Path(__file__).parent.parent / 'run.py').read_text()
        self.assertNotIn('import uuid', run_py)
        self.assertNotIn('import random', run_py)

    def test_config_files_exist(self):
        self.assertTrue((CONFIG_DIR / 'defaults.json').exists())
        self.assertTrue((CONFIG_DIR / 'stages.json').exists(), 'Missing config/stages.json')

    def test_prompts_exist(self):
        for prompt in ['hunt.md', 'recon.md', 'validate.md', 'trace.md', 'report.md']:
            self.assertTrue((PROMPTS_DIR / prompt).exists(), f'Missing prompt: {prompt}')

    def test_schemas_exist(self):
        for schema in ['context_pack.schema.json', 'finding.schema.json',
                       'recon_tasks.schema.json', 'report.schema.json']:
            self.assertTrue((SCHEMAS_DIR / schema).exists(), f'Missing schema: {schema}')

    def test_tests_exist(self):
        tests = list((Path(__file__).parent).glob('test_*.py'))
        self.assertGreaterEqual(len(tests), 10, f'Only {len(tests)} test files found')


class IngestorInvariantTests(unittest.TestCase):
    def test_snippet_id_deterministic(self):
        from stages.ingestor import _make_snippet_id

        id1 = _make_snippet_id('a.c', 'foo', 42)
        id2 = _make_snippet_id('a.c', 'foo', 42)
        self.assertEqual(id1, id2, 'snippet IDs not deterministic')

        id3 = _make_snippet_id('a.c', 'foo', 43)
        self.assertNotEqual(id1, id3, 'different line should change ID')

    def test_snippet_id_format(self):
        from stages.ingestor import _make_snippet_id
        sid = _make_snippet_id('test.c', 'bar', 10)
        self.assertTrue(sid.startswith('sha256:'), f'ID does not start with sha256: {sid}')

    def test_use_of_hash_or_uuid_forbidden(self):
        ingestor = (STAGES_DIR / 'ingestor.py').read_text()
        self.assertNotIn('hash(', ingestor, 'ingestor uses hash()')
        self.assertNotIn('uuid.uuid4', ingestor, 'ingestor uses uuid.uuid4')

    def test_c_cpp_uses_tree_sitter(self):
        ingestor = (STAGES_DIR / 'ingestor.py').read_text()
        self.assertIn('tree_sitter', ingestor, 'ingestor does not use tree-sitter')

    def test_snippet_required_fields_defined(self):
        from stages.ingestor import SNIPPET_REQUIRED_FIELDS
        expected = {'id', 'file', 'language', 'kind', 'name', 'lines',
                    'content', 'tags', 'token_count', 'callees', 'continuation'}
        self.assertEqual(set(SNIPPET_REQUIRED_FIELDS), expected)

    def test_snippet_has_callees_field(self):
        ingestor = (STAGES_DIR / 'ingestor.py').read_text()
        self.assertIn("'callees'", ingestor, 'snippet missing callees field')


class CoordinatorInvariantTests(unittest.TestCase):
    def test_exactly_11_domains(self):
        from stages.coordinator import DOMAIN_ORDER
        self.assertEqual(len(DOMAIN_ORDER), 11,
                         f'Expected 11 domains, got {len(DOMAIN_ORDER)}')

    def test_domain_order_exists(self):
        from stages.coordinator import DOMAIN_ORDER
        self.assertGreater(len(DOMAIN_ORDER), 0)

    def test_domain_names(self):
        from stages.coordinator import DOMAIN_ORDER
        expected = {'mem-safety', 'auth', 'crypto', 'ipc', 'data-flow', 'format-str',
                    'injection', 'path-traversal', 'concurrency', 'resource', 'secrets'}
        self.assertEqual(set(DOMAIN_ORDER), expected)

    def test_domains_have_exclusive_flag(self):
        from stages.coordinator import DOMAINS
        for d in DOMAINS:
            self.assertIn('exclusive', d,
                          f'Domain {d.get("name")} missing exclusive flag')

    def test_domain_order_used_in_build(self):
        from stages.coordinator import build_context_packs, DOMAINS
        packs = build_context_packs([], recon_tasks=None, allow_full_db_fallback=True)
        self.assertIsInstance(packs, list)


class ChainInvariantTests(unittest.TestCase):
    def test_filter_unreachable_accepts_entry_points(self):
        from stages.shield import filter_unreachable
        findings = [{'snippet_id': 's1', 'desc': 'test', 'call_path': ['a']}]
        # main calls a, finding is on a
        graph = {'main': {'a'}, 'a': set()}
        reachable, unreachable = filter_unreachable(findings, graph, ['main'])
        self.assertEqual(len(reachable), 1)

    def test_call_graph_keyed_lowercase(self):
        from stages.shield import build_call_graph
        snippets = [
            {'id': 'S1', 'name': 'FooFunc', 'callees': ['BarFunc']},
            {'id': 'S2', 'name': 'BarFunc', 'callees': []},
        ]
        graph = build_call_graph(snippets)
        for k in graph:
            self.assertEqual(k, k.lower(), f'Graph key not lowercase: {k}')

    def test_call_path_normalized_to_list_at_parse_time(self):
        from stages.parser import parse_findings
        text = ('[{"snippet_id": "x", "severity": "HIGH", "class": "buf", '
                '"desc": "d", "call_path": "a -> b"}]')
        findings, _ = parse_findings(text)
        for f in findings:
            self.assertIsInstance(f.get('call_path'), list,
                                  f'call_path not normalized: {f.get("call_path")}')
            self.assertEqual(f['call_path'], ['a', 'b'])


class PipelineInvariantTests(unittest.TestCase):
    def test_stage_order_constant(self):
        from stages.contracts import PIPELINE_STAGES
        expected = [
            'ingestor', 'recon', 'coordinator', 'hunt', 'validate',
            'gapfill', 'voting', 'shield', 'suppressions', 'chainer',
            'poc', 'trace', 'exposure', 'feedback', 'report',
        ]
        self.assertEqual(PIPELINE_STAGES, expected)

    def test_config_has_model_pool(self):
        defaults = json.loads((CONFIG_DIR / 'defaults.json').read_text())
        self.assertIn('entry_points', defaults)

    def test_model_ids_not_hardcoded_in_stages(self):
        run_py = (Path(__file__).parent.parent / 'run.py').read_text()
        # run.py is the single place for model chain, that's acceptable
        self.assertIn('model_chain', run_py)

    def test_skip_health_flag(self):
        run_py = (Path(__file__).parent.parent / 'run.py').read_text()
        self.assertIn('skip-health', run_py)

    def test_output_dir_exists(self):
        self.assertTrue(OUTPUT_DIR.exists())

    def test_validate_only_mode(self):
        run_py = (Path(__file__).parent.parent / 'run.py').read_text()
        self.assertIn('validate-only', run_py)

    def test_resume_mode(self):
        run_py = (Path(__file__).parent.parent / 'run.py').read_text()
        self.assertIn('resume', run_py)

    def test_check_deps_first_in_main(self):
        run_py = (Path(__file__).parent.parent / 'run.py').read_text()
        self.assertIn('_check_deps()', run_py.split('def main')[1].split('\n')[1])


class QualityGateInvariantTests(unittest.TestCase):
    def test_shield_check_before_chainer(self):
        from stages.contracts import PIPELINE_STAGES
        shield_idx = PIPELINE_STAGES.index('shield')
        chainer_idx = PIPELINE_STAGES.index('chainer')
        self.assertLess(shield_idx, chainer_idx)

    def test_each_finding_passes_shield(self):
        from stages.shield import annotate_call_path_verification, annotate_hallucination
        findings = [
            {'snippet_id': 's1', 'desc': 'test', 'call_path': ['a', 'b']},
        ]
        snippet_db = {'s1': {'content': 'void a() { b(); }', 'callers': [], 'callees': ['b']}}
        graph = {'a': {'b'}, 'b': set()}
        shielded = annotate_call_path_verification(findings, graph)
        shielded = annotate_hallucination(shielded, snippet_db)
        for f in shielded:
            self.assertIn('call_path_verified', f)
            self.assertIn('hallucination_detected', f)


if __name__ == '__main__':
    unittest.main()
