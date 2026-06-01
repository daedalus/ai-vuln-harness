"""Tests for JSON cache of context packs (replaced pickle)."""

import json
import tempfile
import unittest
from pathlib import Path

from ai_vuln_harness.stages.runtime import (
    load_packs_json,
    save_packs_json,
)


class JsonRoundTripTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mktemp(suffix=".json"))

    def tearDown(self):
        self.tmp.unlink(missing_ok=True)

    def test_round_trip_empty_list(self):
        save_packs_json([], self.tmp)
        loaded = load_packs_json(self.tmp)
        self.assertEqual(loaded, [])

    def test_round_trip_basic_packs(self):
        packs = [
            {
                "agent": "mem-safety",
                "snippets": [{"id": "s1", "content": "int x;"}],
                "guidance": "test",
            },
            {"agent": "auth", "snippets": [{"id": "s2", "content": "if (x) {}"}]},
        ]
        save_packs_json(packs, self.tmp)
        loaded = load_packs_json(self.tmp)
        self.assertEqual(loaded, packs)

    def test_round_trip_nested_types(self):
        packs = [
            {
                "agent": "crypto",
                "snippets": [],
                "cross_refs": {},
                "score": 3.14,
                "active": True,
                "tags": ["a", "b"],
            }
        ]
        save_packs_json(packs, self.tmp)
        loaded = load_packs_json(self.tmp)
        self.assertEqual(loaded, packs)

    def test_file_created(self):
        self.assertFalse(self.tmp.exists())
        save_packs_json([{"a": 1}], self.tmp)
        self.assertTrue(self.tmp.exists())
        self.assertGreater(self.tmp.stat().st_size, 0)

    def test_save_creates_parent_dirs(self):
        nested = self.tmp.parent / "sub" / "packs.json"
        try:
            save_packs_json([], nested)
            self.assertTrue(nested.exists())
        finally:
            nested.unlink(missing_ok=True)
            nested.parent.rmdir()


class LoadErrorsTests(unittest.TestCase):
    def test_load_nonexistent_raises(self):
        p = Path("/tmp/__no_such_json_file__")
        with self.assertRaises((FileNotFoundError, OSError)):
            load_packs_json(p)

    def test_load_corrupt_raises(self):
        p = Path(tempfile.mktemp(suffix=".json"))
        try:
            p.write_text("not valid json{{{")
            with self.assertRaises(json.JSONDecodeError):
                load_packs_json(p)
        finally:
            p.unlink(missing_ok=True)
