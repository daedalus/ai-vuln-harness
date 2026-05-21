"""Tests for sanitized pickle cache of context packs."""

import io
import pickle
import tempfile
import unittest
from pathlib import Path

from stages.runtime import _SafeUnpickler, load_packs_pickle, save_packs_pickle


class _EvilEval:
    def __reduce__(self):
        return (eval, ('1+1',))


class _EvilOs:
    def __reduce__(self):
        return (eval, ('__import__("os").system("id")',))


class _EvilSubprocess:
    def __reduce__(self):
        return (eval, ('__import__("subprocess").check_call(["ls"])',))


class _EvilCustom:
    def __init__(self):
        self.x = 1


class PickleRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mktemp(suffix='.pkl'))

    def tearDown(self):
        self.tmp.unlink(missing_ok=True)

    def test_round_trip_empty_list(self):
        save_packs_pickle([], self.tmp)
        loaded = load_packs_pickle(self.tmp)
        self.assertEqual(loaded, [])

    def test_round_trip_basic_packs(self):
        packs = [
            {'agent': 'mem-safety', 'snippets': [{'id': 's1', 'content': 'int x;'}], 'guidance': 'test'},
            {'agent': 'auth', 'snippets': [{'id': 's2', 'content': 'if (x) {}'}]},
        ]
        save_packs_pickle(packs, self.tmp)
        loaded = load_packs_pickle(self.tmp)
        self.assertEqual(loaded, packs)

    def test_round_trip_nested_types(self):
        packs = [
            {
                'agent': 'crypto',
                'snippets': [],
                'cross_refs': {},
                'score': 3.14,
                'active': True,
                'tags': ('a', 'b'),
                'unique_ids': {'x', 'y'},
                'raw': b'\x00\x01',
            }
        ]
        save_packs_pickle(packs, self.tmp)
        loaded = load_packs_pickle(self.tmp)
        self.assertEqual(loaded, packs)

    def test_file_created(self):
        self.assertFalse(self.tmp.exists())
        save_packs_pickle([{'a': 1}], self.tmp)
        self.assertTrue(self.tmp.exists())
        self.assertGreater(self.tmp.stat().st_size, 0)

    def test_save_creates_parent_dirs(self):
        nested = self.tmp.parent / 'sub' / 'packs.pkl'
        try:
            save_packs_pickle([], nested)
            self.assertTrue(nested.exists())
        finally:
            nested.unlink(missing_ok=True)
            nested.parent.rmdir()


class SafeUnpicklerTests(unittest.TestCase):
    def _unpickle(self, data: bytes):
        return _SafeUnpickler(io.BytesIO(data)).load()

    def _pickle_obj(self, obj):
        return pickle.dumps(obj)

    def test_rejects_eval(self):
        with self.assertRaises(pickle.UnpicklingError):
            self._unpickle(self._pickle_obj(_EvilEval()))

    def test_rejects_os_system(self):
        with self.assertRaises(pickle.UnpicklingError):
            self._unpickle(self._pickle_obj(_EvilOs()))

    def test_rejects_subprocess(self):
        with self.assertRaises(pickle.UnpicklingError):
            self._unpickle(self._pickle_obj(_EvilSubprocess()))

    def test_rejects_custom_class(self):
        with self.assertRaises(pickle.UnpicklingError):
            self._unpickle(self._pickle_obj(_EvilCustom()))

    def test_allows_dict(self):
        self.assertEqual(self._unpickle(self._pickle_obj({'k': 'v'})), {'k': 'v'})

    def test_allows_list(self):
        self.assertEqual(self._unpickle(self._pickle_obj([1, 2, 3])), [1, 2, 3])

    def test_allows_tuple(self):
        self.assertEqual(self._unpickle(self._pickle_obj((1, 'a'))), (1, 'a'))

    def test_allows_set(self):
        self.assertEqual(self._unpickle(self._pickle_obj({1, 2})), {1, 2})

    def test_allows_str_int_float_bool_none_bytes(self):
        for val in ['hello', 42, 3.14, True, False, None, b'\x00']:
            self.assertEqual(self._unpickle(self._pickle_obj(val)), val)

    def test_allows_nested_containers(self):
        data = {'a': [1, {'b': (2, {3})}], 'c': None}
        self.assertEqual(self._unpickle(self._pickle_obj(data)), data)


class LoadErrorsTests(unittest.TestCase):
    def test_load_nonexistent_raises(self):
        p = Path('/tmp/__no_such_pickle_file__')
        with self.assertRaises(FileNotFoundError):
            load_packs_pickle(p)

    def test_load_corrupt_raises(self):
        p = Path(tempfile.mktemp(suffix='.pkl'))
        try:
            p.write_bytes(b'not a pickle file')
            with self.assertRaises((pickle.UnpicklingError, Exception)):
                load_packs_pickle(p)
        finally:
            p.unlink(missing_ok=True)

    def test_load_malicious_rejected(self):
        p = Path(tempfile.mktemp(suffix='.pkl'))
        try:
            p.write_bytes(pickle.dumps(_EvilEval()))
            with self.assertRaises(pickle.UnpicklingError):
                load_packs_pickle(p)
        finally:
            p.unlink(missing_ok=True)
