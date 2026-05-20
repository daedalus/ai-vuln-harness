"""Adversarial tests for stages/contracts.py — schema validation and repair.

Covers non-dict inputs, recursive schemas, enum boundaries, and
non-repairing repair functions.
"""

import unittest

from stages.contracts import (
    apply_repair_turns,
    standardize_finding,
    validate_subset_schema,
)


class StandardizeFindingAdversarialTests(unittest.TestCase):
    """Edge cases in finding standardization."""

    def test_empty_dict(self):
        result = standardize_finding({})
        self.assertEqual(result['status'], 'raw')
        self.assertFalse(result['poc_confirmed'])

    def test_none_values_preserved(self):
        result = standardize_finding({'snippet_id': None, 'class': None})
        self.assertIsNone(result['snippet_id'])
        self.assertIsNone(result['class'])

    def test_extra_keys_preserved(self):
        result = standardize_finding({'snippet_id': 's1', 'claude_extra': 'xyz'})
        self.assertIn('claude_extra', result)

    def test_bool_values_for_numeric_fields(self):
        result = standardize_finding({'snippet_id': 's1', 'poc_confirmed': 'yes'})
        self.assertEqual(result['poc_confirmed'], 'yes')


class ValidateSubsetSchemaAdversarialTests(unittest.TestCase):
    """Edge cases in subset schema validation."""

    def test_recursive_schema(self):
        schema = {
            'type': 'object',
            'properties': {
                'child': {'type': 'object', 'properties': {'child': {'type': 'object'}}},
            },
        }
        data = {'child': {'child': {}}}
        errors = validate_subset_schema(data, schema)
        self.assertEqual(errors, [])

    def test_enum_with_empty_string(self):
        schema = {'type': 'string', 'enum': ['a', 'b', '']}
        self.assertEqual(validate_subset_schema('', schema), [])
        self.assertNotEqual(validate_subset_schema('c', schema), [])

    def test_required_fields_with_none(self):
        schema = {'type': 'object', 'required': ['a', 'b'], 'properties': {'a': {}, 'b': {}}}
        data = {'a': None}
        errors = validate_subset_schema(data, schema)
        has_missing = any('missing required' in e for e in errors)
        self.assertTrue(has_missing)

    def test_type_mismatch_nested(self):
        schema = {
            'type': 'object',
            'properties': {
                'metadata': {'type': 'object', 'properties': {'count': {'type': 'string'}}},
            },
        }
        data = {'metadata': {'count': 42}}
        errors = validate_subset_schema(data, schema)
        self.assertGreater(len(errors), 0)

    def test_array_items_schema(self):
        schema = {'type': 'array', 'items': {'type': 'string'}}
        self.assertEqual(validate_subset_schema(['a', 'b'], schema), [])
        self.assertNotEqual(validate_subset_schema([1, 2], schema), [])

    def test_unknown_type_skips_validation(self):
        schema = {'type': 'widget'}
        errors = validate_subset_schema(42, schema)
        self.assertEqual(errors, [])

    def test_deeply_nested_required(self):
        schema = {
            'type': 'object',
            'properties': {
                'level1': {
                    'type': 'object',
                    'required': ['level2'],
                    'properties': {'level2': {'type': 'object', 'required': ['key']}},
                },
            },
        }
        data = {'level1': {'level2': {}}}
        errors = validate_subset_schema(data, schema)
        self.assertGreater(len(errors), 0)


class ApplyRepairTurnsAdversarialTests(unittest.TestCase):
    """Edge cases in repair turns."""

    def test_non_repairing_function(self):
        def noop(_data, _errors):
            return _data

        schema = {'type': 'object', 'required': ['x'], 'properties': {'x': {'type': 'string'}}}
        result, errors = apply_repair_turns({'y': 1}, schema, repair_fn=noop, max_attempts=2)
        self.assertGreater(len(errors), 0)
        self.assertEqual(result, {'y': 1})

    def test_repair_that_makes_things_worse(self):
        def worse(_data, _errors):
            return {'y': 1}

        schema = {'type': 'object', 'required': ['x'], 'properties': {'x': {'type': 'string'}}}
        result, errors = apply_repair_turns({'y': 1}, schema, repair_fn=worse, max_attempts=1)
        self.assertGreaterEqual(len(errors), 1)

    def test_zero_max_attempts(self):
        schema = {'type': 'object', 'required': ['x']}
        data = {'y': 1}
        result, errors = apply_repair_turns(data, schema, max_attempts=0)
        self.assertGreater(len(errors), 0)

    def test_repair_succeeds_on_third_attempt(self):
        attempt = [0]

        def lazy_repair(_data, _errors):
            attempt[0] += 1
            _data['x'] = 'ok'
            return _data

        schema = {'type': 'object', 'required': ['x'], 'properties': {'x': {'type': 'string'}}}
        data = {'y': 1}
        result, errors = apply_repair_turns(data, schema, repair_fn=lazy_repair, max_attempts=5)
        self.assertEqual(errors, [])
        self.assertEqual(result['x'], 'ok')


if __name__ == '__main__':
    unittest.main()
