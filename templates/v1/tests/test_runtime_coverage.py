"""Coverage gap tests for stages/runtime.py — model pool splitting, caching,
state DB, and remaining uncovered code paths.
"""

import json
import os
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from stages.runtime import (
    HUNT_SYSTEM_PROMPT,
    JsonCache,
    StateDB,
    cache_key,
    call_llm,
    fetch_model_limits,
    load_auth_config,
    repair_json_output,
    split_model_pools,
)
from run import (
    _run_one_hunt_pack as run_hunt_pack,
    _run_hunt_packs as run_hunt_all,
    _run_validate_finding as run_validate_finding,
    _run_validate_findings as run_validate_all,
)


class SplitModelPoolsTests(unittest.TestCase):
    def test_hunt_preferred_models(self):
        models = ['deepseek-v2', 'qwen-72b', 'gemma-7b', 'gpt-4']
        hunt, validate = split_model_pools(models)
        self.assertIn('deepseek-v2', hunt)
        self.assertIn('qwen-72b', hunt)
        self.assertIn('gemma-7b', hunt)

    def test_validate_preferred_models(self):
        models = ['nemotron-4', 'trinity-x', 'z-ai-v2', 'gpt-4']
        hunt, validate = split_model_pools(models)
        self.assertIn('nemotron-4', validate)
        self.assertIn('trinity-x', validate)
        self.assertIn('z-ai-v2', validate)

    def test_remaining_models_distributed(self):
        models = ['gpt-4', 'claude-3', 'llama-3', 'mixtral']
        hunt, validate = split_model_pools(models)
        self.assertEqual(len(hunt) + len(validate), len(models))

    def test_no_validate_if_hunt_takes_all_with_preferred(self):
        models = ['deepseek-v2', 'gpt-4']
        hunt, validate = split_model_pools(models)
        self.assertIn('deepseek-v2', hunt)
        self.assertEqual(len(validate), 1)

    def test_overflow_to_hunt(self):
        models = ['deepseek-a', 'deepseek-b', 'deepseek-c', 'gpt-4', 'gpt-5', 'gpt-6']
        hunt, validate = split_model_pools(models)
        self.assertGreater(len(hunt), 0)
        self.assertGreater(len(validate), 0)

    def test_empty_list(self):
        hunt, validate = split_model_pools([])
        self.assertEqual(hunt, [])
        self.assertEqual(validate, [])

    def test_hunt_and_validate_no_overlap(self):
        models = ['deepseek-v2', 'nemotron-4']
        hunt, validate = split_model_pools(models)
        for m in hunt:
            self.assertNotIn(m, validate)
        for m in validate:
            self.assertNotIn(m, hunt)

    def test_all_models_in_both_preferred_categories(self):
        models = ['deepseek-v2', 'qwen-72b', 'nemotron-4', 'trinity-x']
        hunt, validate = split_model_pools(models)
        self.assertEqual(len(hunt), 2)
        self.assertEqual(len(validate), 2)


class CacheKeyTests(unittest.TestCase):
    def test_consistent_key(self):
        k1 = cache_key('hunt', 'deepseek', 'hello world')
        k2 = cache_key('hunt', 'deepseek', 'hello world')
        self.assertEqual(k1, k2)

    def test_different_stage_different_key(self):
        k1 = cache_key('hunt', 'deepseek', 'same text')
        k2 = cache_key('validate', 'deepseek', 'same text')
        self.assertNotEqual(k1, k2)

    def test_different_text_different_key(self):
        k1 = cache_key('hunt', 'deepseek', 'text a')
        k2 = cache_key('hunt', 'deepseek', 'text b')
        self.assertNotEqual(k1, k2)

    def test_key_format(self):
        k = cache_key('hunt', 'deepseek', 'test')
        parts = k.split(':')
        self.assertEqual(parts[0], 'hunt')
        self.assertEqual(parts[1], 'deepseek')
        self.assertEqual(len(parts), 3)

    def test_empty_text(self):
        k = cache_key('hunt', 'deepseek', '')
        self.assertIsInstance(k, str)
        self.assertGreater(len(k), 4)


class JsonCacheTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / 'cache.json'

    def tearDown(self):
        self._tmp.cleanup()

    def test_init_new_cache(self):
        cache = JsonCache(self.path)
        self.assertEqual(cache.data, {})

    def test_get_missing(self):
        cache = JsonCache(self.path)
        self.assertIsNone(cache.get('nonexistent'))

    def test_put_then_get(self):
        cache = JsonCache(self.path)
        cache.put('key1', {'value': 42})
        self.assertEqual(cache.get('key1'), {'value': 42})

    def test_persistence(self):
        cache1 = JsonCache(self.path)
        cache1.put('k', 'v')
        cache2 = JsonCache(self.path)
        self.assertEqual(cache2.get('k'), 'v')

    def test_put_overwrites(self):
        cache = JsonCache(self.path)
        cache.put('k', 'v1')
        cache.put('k', 'v2')
        self.assertEqual(cache.get('k'), 'v2')

    def test_init_from_existing_file(self):
        self.path.write_text(json.dumps({'existing': 'data'}))
        cache = JsonCache(self.path)
        self.assertEqual(cache.get('existing'), 'data')

    def test_init_from_empty_file(self):
        self.path.write_text('')
        cache = JsonCache(self.path)
        self.assertEqual(cache.data, {})

    def test_put_none_value(self):
        cache = JsonCache(self.path)
        cache.put('k', None)
        self.assertIsNone(cache.get('k'))


class StateDBTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name) / 'state.db'

    def tearDown(self):
        self._tmp.cleanup()

    def test_init_creates_db(self):
        db = StateDB(self.path)
        db.close()
        self.assertTrue(self.path.exists())

    def test_put_and_get_meta(self):
        db = StateDB(self.path)
        db.put_meta('scan_id', 'abc-123')
        self.assertEqual(db.get_meta('scan_id'), 'abc-123')
        db.close()

    def test_get_missing_meta(self):
        db = StateDB(self.path)
        self.assertIsNone(db.get_meta('nonexistent'))
        db.close()

    def test_meta_overwrite(self):
        db = StateDB(self.path)
        db.put_meta('status', 'running')
        db.put_meta('status', 'done')
        self.assertEqual(db.get_meta('status'), 'done')
        db.close()

    def test_multiple_meta_keys(self):
        db = StateDB(self.path)
        db.put_meta('k1', 'v1')
        db.put_meta('k2', 'v2')
        self.assertEqual(db.get_meta('k1'), 'v1')
        self.assertEqual(db.get_meta('k2'), 'v2')
        db.close()

    def test_reuse_existing_db(self):
        db1 = StateDB(self.path)
        db1.put_meta('key', 'val')
        db1.close()
        db2 = StateDB(self.path)
        self.assertEqual(db2.get_meta('key'), 'val')
        db2.close()


class FetchModelLimitsTests(unittest.TestCase):
    def _models_dev(self, tmp: str) -> Path:
        p = Path(tmp) / 'config'
        p.mkdir(parents=True, exist_ok=True)
        return p / 'models.dev'

    def test_uses_models_dev_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            models_dev = self._models_dev(tmp)
            models_dev.write_text(json.dumps({
                'fake-model-v1:free': {
                    'context_window': 65536,
                    'max_output_tokens': 65536,
                    'last_updated': time.time(),
                },
            }))
            result = fetch_model_limits(
                ['fake-model-v1:free'],
                Path(tmp),
            )
            self.assertEqual(result, {'fake-model-v1:free': 65536})

    def test_fallback_to_128k_on_empty_cache_and_no_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = fetch_model_limits(
                ['non-existent-model-xyz'],
                Path(tmp),
            )
            self.assertEqual(result.get('non-existent-model-xyz'), 128_000)

    def test_creates_models_dev_after_live_fetch(self):
        mock_response = {
            'data': [
                {'id': 'deepseek/deepseek-v4-flash:free', 'context_length': 131072},
            ],
        }

        class FakeResponse:
            def read(self):
                return json.dumps(mock_response).encode()
            def __exit__(self, *a):
                pass
            def __enter__(self):
                return self
            def __init__(self):
                self.status = 200

        with patch('stages.runtime.urllib.request.urlopen', return_value=FakeResponse()):
            with tempfile.TemporaryDirectory() as tmp:
                result = fetch_model_limits(
                    ['deepseek/deepseek-v4-flash:free'],
                    Path(tmp),
                )
                dev_path = Path(tmp) / 'config/models.dev'
                self.assertTrue(dev_path.exists())
                cache = json.loads(dev_path.read_text())
                for m, cw in result.items():
                    self.assertIn(m, cache)
                    self.assertEqual(cache[m]['context_window'], cw)

    def test_multiple_models(self):
        with tempfile.TemporaryDirectory() as tmp:
            models_dev = self._models_dev(tmp)
            models_dev.write_text(json.dumps({
                'model-a:free': {
                    'context_window': 32768,
                    'max_output_tokens': 32768,
                    'last_updated': time.time(),
                },
                'model-b:free': {
                    'context_window': 65536,
                    'max_output_tokens': 65536,
                    'last_updated': time.time(),
                },
            }))
            result = fetch_model_limits(
                ['model-a:free', 'model-b:free'],
                Path(tmp),
            )
            self.assertEqual(result['model-a:free'], 32768)
            self.assertEqual(result['model-b:free'], 65536)

    def test_stale_cache_falls_back_when_no_network(self):
        with tempfile.TemporaryDirectory() as tmp:
            models_dev = self._models_dev(tmp)
            stale_ts = time.time() - 86400 * 8
            models_dev.write_text(json.dumps({
                'stale-model:free': {
                    'context_window': 999,
                    'max_output_tokens': 999,
                    'last_updated': stale_ts,
                },
            }))
            result = fetch_model_limits(
                ['stale-model:free'],
                Path(tmp),
            )
            self.assertEqual(result.get('stale-model:free'), 999)


class _MockedCallTests(unittest.TestCase):
    def setUp(self):
        patcher = patch('stages.runtime.time.sleep')
        self.addCleanup(patcher.stop)
        self._sleep_mock = patcher.start()


class CallLlmTests(_MockedCallTests):
    def test_call_llm_returns_content(self):
        mock_response = {
            'choices': [{'message': {'content': 'Hello, world!'}}],
        }

        class FakeResponse:
            def read(self):
                return json.dumps(mock_response).encode()
            def __init__(self):
                self.status = 200

        with patch('stages.runtime.urllib.request.urlopen', return_value=FakeResponse()):
            result = call_llm('openrouter:test-model:free', 'Hello', auth={'openrouter': 'sk-test'})
            self.assertEqual(result, 'Hello, world!')

    def test_call_llm_uses_reasoning_fallback(self):
        mock_response = {
            'choices': [{'message': {'content': '', 'reasoning': 'step by step...'}}],
        }

        class FakeResponse:
            def read(self):
                return json.dumps(mock_response).encode()
            def __init__(self):
                self.status = 200

        with patch('stages.runtime.urllib.request.urlopen', return_value=FakeResponse()):
            result = call_llm('openrouter:reasoning-model:free', 'Think', auth={'openrouter': 'sk-test'})
            self.assertEqual(result, 'step by step...')

    def test_call_llm_raises_without_auth(self):
        with self.assertRaises(ValueError):
            call_llm('openrouter:test:free', 'test', auth={})


class RunHuntPackTests(_MockedCallTests):
    def test_run_hunt_pack_parses_findings(self):
        hunt_output = (
            '{"snippet_id": "s1", "class": "buffer-overflow", "severity": "HIGH", '
            '"desc": "buffer overflow", "call_path": ["a", "b"], "status": "raw", "poc_confirmed": false}\n'
            '{"done": true}'
        )

        mock_response = {
            'choices': [{'message': {'content': hunt_output}}],
        }

        class FakeResponse:
            def read(self):
                return json.dumps(mock_response).encode()
            def __init__(self):
                self.status = 200

        pack = {
            'agent': 'mem-safety',
            'snippets': [{'id': 's1', 'content': 'void main() { char buf[10]; gets(buf); }'}],
        }

        with patch('stages.runtime.urllib.request.urlopen', return_value=FakeResponse()):
            findings, gaps = run_hunt_pack(pack, 'openrouter:test:free', auth={'openrouter': 'sk-test'}, cache=None)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['class'], 'buffer-overflow')

    def test_run_hunt_pack_no_auth_returns_gap(self):
        pack = {'agent': 'test', 'snippets': []}
        findings, gaps = run_hunt_pack(pack, 'openrouter:test:free', auth=None, cache=None)
        self.assertEqual(len(findings), 0)
        self.assertEqual(len(gaps), 1)
        self.assertIn('coverage_gap', gaps[0])


class RunHuntAllTests(unittest.TestCase):
    def test_run_hunt_all_empty_packs(self):
        result = run_hunt_all([], ['test:free'], auth={'openrouter': 'sk-test'}, cache=None)
        self.assertEqual(result, ([], []))

    def test_run_hunt_all_empty_models(self):
        result = run_hunt_all([{'agent': 'test', 'snippets': []}], [], auth={'openrouter': 'sk-test'}, cache=None)
        self.assertEqual(len(result[0]), 0)
        self.assertEqual(len(result[1]), 1)


class RunValidateFindingTests(_MockedCallTests):
    def test_run_validate_finding_extracts_status(self):
        validate_output = '{"status": "confirmed", "reason": "reachable via user input"}'

        mock_response = {
            'choices': [{'message': {'content': validate_output}}],
        }

        class FakeResponse:
            def read(self):
                return json.dumps(mock_response).encode()
            def __init__(self):
                self.status = 200

        finding = {'snippet_id': 's1', 'class': 'buffer-overflow'}
        snippet = {'content': 'void main() { gets(buf); }', 'file': 'test.c', 'name': 'test'}

        with patch('stages.runtime.urllib.request.urlopen', return_value=FakeResponse()):
            result = run_validate_finding(
                finding, snippet, 'openrouter:test:free',
                auth={'openrouter': 'sk-test'}, cache=None,
            )

        self.assertEqual(result['validate_status'], 'confirmed')
        self.assertEqual(result['validate_reason'], 'reachable via user input')

    def test_run_validate_finding_unparseable(self):
        mock_response = {
            'choices': [{'message': {'content': 'not json at all'}}],
        }

        class FakeResponse:
            def read(self):
                return json.dumps(mock_response).encode()
            def __init__(self):
                self.status = 200

        finding = {'snippet_id': 's1', 'class': 'buffer-overflow'}
        snippet = {'content': 'int x = 1;', 'file': 'test.c', 'name': 'test'}

        with patch('stages.runtime.urllib.request.urlopen', return_value=FakeResponse()):
            result = run_validate_finding(
                finding, snippet, 'openrouter:test:free',
                auth={'openrouter': 'sk-test'}, cache=None,
            )

        self.assertEqual(result['validate_status'], 'needs-more-info')
        self.assertIn('unparseable', result.get('validate_reason', ''))


class RunValidateAllTests(unittest.TestCase):
    def test_run_validate_all_empty(self):
        result = run_validate_all([], {}, ['test:free'], auth={'openrouter': 'sk-test'}, cache=None)
        self.assertEqual(result, [])

    def test_run_validate_all_no_models(self):
        result = run_validate_all([{'snippet_id': 's1'}], {}, [], auth={'openrouter': 'sk-test'}, cache=None)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['snippet_id'], 's1')
        self.assertEqual(result[0].get('validate_status'), 'needs-more-info')

    def test_run_validate_all_no_findings(self):
        result = run_validate_all([], {'s1': {}}, ['test:free'], auth={'openrouter': 'sk-test'}, cache=None)
        self.assertEqual(result, [])


class RunHuntPackCacheTests(_MockedCallTests):
    def test_run_hunt_pack_uses_cache(self):
        cache = JsonCache.__new__(JsonCache)
        cache.data = {}
        cache.path = None

        pack = {'agent': 'test', 'snippets': [{'id': 's1', 'content': 'int x = 1;'}]}
        prompt = json.dumps(pack, indent=2)
        import hashlib
        ck = f"llm:openrouter:test:free:{hashlib.sha256((prompt + HUNT_SYSTEM_PROMPT).encode()).hexdigest()[:12]}"
        cache.data[ck] = '{"snippet_id": "s1", "class": "uaf"}\n{"done": true}'

        findings, gaps = run_hunt_pack(pack, 'openrouter:test:free', auth={'openrouter': 'sk-test'}, cache=cache)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['class'], 'uaf')


class RepairJsonOutputTests(unittest.TestCase):
    def test_direct_json(self):
        parsed, repaired = repair_json_output('{"a": 1}')
        self.assertEqual(parsed, {'a': 1})
        self.assertFalse(repaired)

    def test_fenced_code_block(self):
        raw = '```json\n{"a": 1}\n```'
        parsed, repaired = repair_json_output(raw)
        self.assertEqual(parsed, {'a': 1})
        self.assertTrue(repaired)

    def test_extract_balanced_brace(self):
        raw = 'some text {"a": 1} trailing'
        parsed, repaired = repair_json_output(raw)
        self.assertEqual(parsed, {'a': 1})
        self.assertTrue(repaired)

    def test_invalid_input(self):
        parsed, repaired = repair_json_output('not json at all')
        self.assertIsNone(parsed)
        self.assertFalse(repaired)

    def test_empty_string(self):
        parsed, repaired = repair_json_output('')
        self.assertIsNone(parsed)
        self.assertFalse(repaired)


if __name__ == '__main__':
    unittest.main()
