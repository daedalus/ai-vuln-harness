"""Tests for stages/runtime.py — cross-run regression analysis with
KL-divergence/Jensen-Shannon divergence, and auth config loading."""

import json
import math
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from stages.runtime import (
    CrossRunRegression,
    class_distribution,
    js_divergence,
    load_auth_config,
)

# ---------------------------------------------------------------------------
# Auth config tests
# ---------------------------------------------------------------------------


class LoadAuthConfigTests(unittest.TestCase):
    def test_no_files_returns_empty(self):
        auth = load_auth_config(script_dir=Path(tempfile.mkdtemp()), skip_global_fallback=True)
        self.assertEqual(auth, {})

    def test_explicit_path_loaded(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'openrouter': 'sk-or-v1-explicit'}, f)
            tmp = Path(f.name)
        try:
            auth = load_auth_config(explicit_path=tmp)
            self.assertEqual(auth.get('openrouter'), 'sk-or-v1-explicit')
        finally:
            tmp.unlink()

    def test_explicit_path_overrides_default(self):
        with (
            tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as explicit,
            tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as default,
        ):
            json.dump({'openrouter': 'explicit-key'}, explicit)
            json.dump({'openrouter': 'default-key'}, default)
            exp = Path(explicit.name)
            default_path = Path(default.name)
        try:
            auth = load_auth_config(explicit_path=exp, script_dir=default_path.parent)
            self.assertEqual(auth.get('openrouter'), 'explicit-key')
        finally:
            exp.unlink()
            default_path.unlink()

    def test_env_var_overrides_file(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'openrouter': 'from-file'}, f)
            tmp = Path(f.name)
        try:
            with patch.dict(os.environ, {'OPENROUTER_API_KEY': 'from-env'}):
                auth = load_auth_config(explicit_path=tmp)
                self.assertEqual(auth.get('openrouter'), 'from-env')
        finally:
            tmp.unlink()

    def test_multiple_providers(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'openrouter': 'or-key', 'groq': 'gsk-key', 'zen': 'zen-key'}, f)
            tmp = Path(f.name)
        try:
            auth = load_auth_config(explicit_path=tmp)
            self.assertEqual(auth.get('openrouter'), 'or-key')
            self.assertEqual(auth.get('groq'), 'gsk-key')
            self.assertEqual(auth.get('zen'), 'zen-key')
        finally:
            tmp.unlink()

    def test_alternative_key_names(self):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({'openrouter_api_key': 'underscore-key'}, f)
            tmp = Path(f.name)
        try:
            auth = load_auth_config(explicit_path=tmp)
            self.assertEqual(auth.get('openrouter'), 'underscore-key')
        finally:
            tmp.unlink()

    def test_nonexistent_path_skipped(self):
        auth = load_auth_config(explicit_path=Path('/nonexistent/auth.json'))
        self.assertEqual(auth, {})


# ---------------------------------------------------------------------------
# Cross-run regression tests
# ---------------------------------------------------------------------------


class ClassDistributionTests(unittest.TestCase):
    def test_empty_findings(self):
        counts = class_distribution([])
        self.assertEqual(sum(counts.values()), 0)

    def test_counts_by_class(self):
        findings = [
            {'class': 'buffer-overflow'},
            {'class': 'buffer-overflow'},
            {'class': 'format-string'},
        ]
        counts = class_distribution(findings)
        self.assertEqual(counts['buffer-overflow'], 2)
        self.assertEqual(counts['format-string'], 1)

    def test_falls_back_to_attack_class(self):
        findings = [{'attack_class': 'uaf'}, {'attack_class': 'uaf'}]
        counts = class_distribution(findings)
        self.assertEqual(counts['uaf'], 2)

    def test_falls_back_to_cwe_id(self):
        findings = [{'cwe_id': 'CWE-476'}]
        counts = class_distribution(findings)
        self.assertEqual(counts['cwe-476'], 1)

    def test_unknown_fallback(self):
        findings = [{}]
        counts = class_distribution(findings)
        self.assertEqual(counts['unknown'], 1)


class JSDivergenceTests(unittest.TestCase):
    def test_identical_distributions(self):
        p = {'a': 0.5, 'b': 0.5}
        q = {'a': 0.5, 'b': 0.5}
        self.assertAlmostEqual(js_divergence(p, q), 0.0, places=6)

    def test_disjoint_distributions(self):
        p = {'a': 1.0}
        q = {'b': 1.0}
        js = js_divergence(p, q)
        self.assertGreater(js, 0.0)
        self.assertLessEqual(js, math.log(2))

    def test_symmetric(self):
        p = {'a': 0.9, 'b': 0.1}
        q = {'a': 0.2, 'b': 0.8}
        self.assertAlmostEqual(js_divergence(p, q), js_divergence(q, p), places=6)


class CrossRunRegressionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mktemp(suffix='.jsonl'))

    def tearDown(self):
        if self.tmp.exists():
            self.tmp.unlink()

    def test_record_and_detect_no_history(self):
        reg = CrossRunRegression(self.tmp)
        reg.record_run('t1', [{'class': 'buffer-overflow'}])
        self.assertEqual(reg.detect_drift(), [])

    def test_detect_drift_threshold(self):
        reg = CrossRunRegression(self.tmp)
        reg.record_run('t1', [{'class': 'buffer-overflow'}] * 90 + [{'class': 'format-string'}] * 10)
        reg.record_run('t2', [{'class': 'buffer-overflow'}] * 10 + [{'class': 'format-string'}] * 90)
        signals = reg.detect_drift(window=5, threshold=0.01)
        self.assertGreater(len(signals), 0)
        for s in signals:
            self.assertIn('js_divergence', s)
            self.assertIn('changed_classes', s)

    def test_stable_distribution_no_drift(self):
        reg = CrossRunRegression(self.tmp)
        reg.record_run('t1', [{'class': 'buffer-overflow'}] * 50 + [{'class': 'uaf'}] * 50)
        reg.record_run('t2', [{'class': 'buffer-overflow'}] * 50 + [{'class': 'uaf'}] * 50)
        signals = reg.detect_drift(window=5, threshold=0.15)
        self.assertEqual(signals, [])

    def test_changed_classes_reported(self):
        reg = CrossRunRegression(self.tmp)
        reg.record_run('t1', [{'class': 'buffer-overflow'}] * 100)
        reg.record_run('t2', [{'class': 'format-string'}] * 100)
        signals = reg.detect_drift(window=5, threshold=0.01)
        self.assertGreater(len(signals), 0)
        changed = signals[0]['changed_classes']
        class_names = {c['class'] for c in changed}
        self.assertIn('buffer-overflow', class_names)
        self.assertIn('format-string', class_names)

    def test_record_metadata_stored(self):
        reg = CrossRunRegression(self.tmp)
        record = reg.record_run('t1', [{'class': 'x'}], metadata={'repo': 'test'})
        self.assertEqual(record['metadata']['repo'], 'test')
        self.assertEqual(record['total_findings'], 1)

    def test_history_persistence(self):
        reg = CrossRunRegression(self.tmp)
        reg.record_run('t1', [{'class': 'x'}])
        reg.record_run('t2', [{'class': 'y'}])

        reg2 = CrossRunRegression(self.tmp)
        signals = reg2.detect_drift(window=5, threshold=0.01)
        self.assertGreater(len(signals), 0)


if __name__ == '__main__':
    unittest.main()
