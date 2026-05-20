"""Coverage gap tests for stages/runtime.py — model pool splitting, caching,
state DB, and remaining uncovered code paths.
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

from stages.runtime import (
    JsonCache,
    StateDB,
    cache_key,
    load_auth_config,
    split_model_pools,
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


if __name__ == '__main__':
    unittest.main()
