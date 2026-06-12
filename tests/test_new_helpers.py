"""Tests for new helper functions added in contracts.py, voting.py, and run.py."""

import unittest

from ai_vuln_harness.stages.contracts import _finding_id, standardize_finding
from ai_vuln_harness.stages.voting import (
    TIER_CONFIRMED,
    TIER_PLAUSIBLE,
    TIER_THEORETICAL,
    _aggregate_finding_data,
    _annotate_best_variants,
    _determine_validation_tier,
    _validate_severity_tier,
)


class FindingIdTests(unittest.TestCase):
    """Tests for _finding_id() in contracts.py."""

    def test_deterministic_same_input(self):
        f1 = {"file": "a.py", "class": "sqli", "lines": [10, 15]}
        f2 = {"file": "a.py", "class": "sqli", "lines": [10, 15]}
        self.assertEqual(_finding_id(f1), _finding_id(f2))

    def test_different_file_different_id(self):
        f1 = {"file": "a.py", "class": "sqli", "lines": [10]}
        f2 = {"file": "b.py", "class": "sqli", "lines": [10]}
        self.assertNotEqual(_finding_id(f1), _finding_id(f2))

    def test_different_class_different_id(self):
        f1 = {"file": "a.py", "class": "sqli", "lines": [10]}
        f2 = {"file": "a.py", "class": "xss", "lines": [10]}
        self.assertNotEqual(_finding_id(f1), _finding_id(f2))

    def test_different_lines_different_id(self):
        f1 = {"file": "a.py", "class": "sqli", "lines": [10]}
        f2 = {"file": "a.py", "class": "sqli", "lines": [20]}
        self.assertNotEqual(_finding_id(f1), _finding_id(f2))

    def test_fallback_to_snippet_id(self):
        f = {"snippet_id": "abc123", "class": "xss"}
        fid = _finding_id(f)
        self.assertEqual(len(fid), 16)
        self.assertEqual(fid, _finding_id(f))

    def test_empty_when_no_key(self):
        f = {"class": "xss"}
        fid = _finding_id(f)
        self.assertEqual(len(fid), 16)

    def test_line_range_format(self):
        f1 = {"file": "a.py", "class": "sqli", "lines": [10, 20]}
        f2 = {"file": "a.py", "class": "sqli", "lines": [10, 15]}
        self.assertNotEqual(_finding_id(f1), _finding_id(f2))

    def test_standardize_adds_finding_id(self):
        f = {"snippet_id": "s1", "class": "sqli", "file": "a.py", "lines": [10]}
        result = standardize_finding(f)
        self.assertIn("finding_id", result)
        self.assertEqual(len(result["finding_id"]), 16)


class DetermineValidationTierTests(unittest.TestCase):
    """Tests for _determine_validation_tier() in voting.py."""

    def test_poc_confirmed_is_tier1(self):
        f = {"poc_confirmed": True}
        self.assertEqual(_determine_validation_tier(f), TIER_CONFIRMED)

    def test_high_confidence_is_tier1(self):
        f = {"confidence": 0.95}
        self.assertEqual(_determine_validation_tier(f), TIER_CONFIRMED)

    def test_medium_confidence_is_tier2(self):
        f = {"confidence": 0.7}
        self.assertEqual(_determine_validation_tier(f), TIER_PLAUSIBLE)

    def test_has_suspicious_points_is_tier2(self):
        f = {"suspicious_points": [{"function": "foo"}]}
        self.assertEqual(_determine_validation_tier(f), TIER_PLAUSIBLE)

    def test_low_confidence_is_tier3(self):
        f = {"confidence": 0.3}
        self.assertEqual(_determine_validation_tier(f), TIER_THEORETICAL)

    def test_no_evidence_is_tier3(self):
        f = {}
        self.assertEqual(_determine_validation_tier(f), TIER_THEORETICAL)

    def test_validate_confidence_fallback(self):
        f = {"validate_confidence": 0.95}
        self.assertEqual(_determine_validation_tier(f), TIER_CONFIRMED)


class ValidateSeverityTierTests(unittest.TestCase):
    """Tests for _validate_severity_tier() in voting.py."""

    def test_no_enforcement_no_change(self):
        f = {"severity": "HIGH", "validation_tier": TIER_THEORETICAL}
        result = _validate_severity_tier(f, enforce=False)
        self.assertEqual(result["severity"], "HIGH")
        self.assertNotIn("severity_downgraded", result)

    def test_enforcement_downgrades_high_tier3(self):
        f = {"severity": "HIGH", "validation_tier": TIER_THEORETICAL}
        result = _validate_severity_tier(f, enforce=True)
        self.assertEqual(result["severity"], "MEDIUM")
        self.assertTrue(result["severity_downgraded"])

    def test_enforcement_downgrades_critical_tier3(self):
        f = {"severity": "CRITICAL", "validation_tier": TIER_THEORETICAL}
        result = _validate_severity_tier(f, enforce=True)
        self.assertEqual(result["severity"], "MEDIUM")

    def test_enforcement_keeps_high_tier1(self):
        f = {"severity": "HIGH", "validation_tier": TIER_CONFIRMED}
        result = _validate_severity_tier(f, enforce=True)
        self.assertEqual(result["severity"], "HIGH")

    def test_enforcement_keeps_medium_tier3(self):
        f = {"severity": "MEDIUM", "validation_tier": TIER_THEORETICAL}
        result = _validate_severity_tier(f, enforce=True)
        self.assertEqual(result["severity"], "MEDIUM")

    def test_enforcement_keeps_low_tier3(self):
        f = {"severity": "LOW", "validation_tier": TIER_THEORETICAL}
        result = _validate_severity_tier(f, enforce=True)
        self.assertEqual(result["severity"], "LOW")


class AggregateFindingDataTests(unittest.TestCase):
    """Tests for _aggregate_finding_data() in voting.py."""

    def _make_accumulators(self):
        from collections import defaultdict
        return (
            defaultdict(float),
            defaultdict(int),
            defaultdict(list),
            defaultdict(list),
        )

    def test_aggregates_confidence(self):
        sums, counts, evidence, hunters = self._make_accumulators()
        f = {"confidence": 0.8, "hunt_model": "opus"}
        _aggregate_finding_data("k1", f, sums, counts, evidence, hunters)
        self.assertEqual(sums["k1"], 0.8)
        self.assertEqual(counts["k1"], 1)

    def test_aggregates_evidence(self):
        sums, counts, evidence, hunters = self._make_accumulators()
        f = {"suspicious_points": [{"function": "foo"}]}
        _aggregate_finding_data("k1", f, sums, counts, evidence, hunters)
        self.assertEqual(len(evidence["k1"]), 1)

    def test_aggregates_hunters(self):
        sums, counts, evidence, hunters = self._make_accumulators()
        f = {"hunt_model": "opus"}
        _aggregate_finding_data("k1", f, sums, counts, evidence, hunters)
        self.assertEqual(hunters["k1"], ["opus"])

    def test_no_duplicate_hunters(self):
        sums, counts, evidence, hunters = self._make_accumulators()
        f = {"hunt_model": "opus"}
        _aggregate_finding_data("k1", f, sums, counts, evidence, hunters)
        _aggregate_finding_data("k1", f, sums, counts, evidence, hunters)
        self.assertEqual(hunters["k1"], ["opus"])

    def test_zero_confidence_not_aggregated(self):
        sums, counts, evidence, hunters = self._make_accumulators()
        f = {"confidence": 0.0}
        _aggregate_finding_data("k1", f, sums, counts, evidence, hunters)
        self.assertEqual(counts["k1"], 0)


class AnnotateBestVariantsTests(unittest.TestCase):
    """Tests for _annotate_best_variants() in voting.py."""

    def _make_accumulators(self):
        from collections import defaultdict
        return (
            defaultdict(float),
            defaultdict(int),
            defaultdict(list),
            defaultdict(list),
        )

    def test_annotates_confidence(self):
        sums, counts, evidence, hunters = self._make_accumulators()
        sums["k1"] = 1.6
        counts["k1"] = 2
        best = {"k1": {"severity": "HIGH"}}
        _annotate_best_variants(best, sums, counts, evidence, hunters)
        self.assertEqual(best["k1"]["aggregated_confidence"], 0.8)

    def test_annotates_evidence(self):
        sums, counts, evidence, hunters = self._make_accumulators()
        evidence["k1"] = [{"function": "foo"}]
        best = {"k1": {"severity": "HIGH"}}
        _annotate_best_variants(best, sums, counts, evidence, hunters)
        self.assertEqual(len(best["k1"]["accumulated_evidence"]), 1)

    def test_annotates_hunters(self):
        sums, counts, evidence, hunters = self._make_accumulators()
        hunters["k1"] = ["opus", "gpt"]
        best = {"k1": {"severity": "HIGH"}}
        _annotate_best_variants(best, sums, counts, evidence, hunters)
        self.assertEqual(best["k1"]["hunter_models"], ["opus", "gpt"])

    def test_skips_when_no_data(self):
        sums, counts, evidence, hunters = self._make_accumulators()
        best = {"k1": {"severity": "HIGH"}}
        _annotate_best_variants(best, sums, counts, evidence, hunters)
        self.assertNotIn("aggregated_confidence", best["k1"])
        self.assertNotIn("accumulated_evidence", best["k1"])
        self.assertNotIn("hunter_models", best["k1"])


class LoadYamlAuthTests(unittest.TestCase):
    """Tests for _load_yaml_auth() in run.py."""

    def test_loads_single_connector(self):
        from ai_vuln_harness.run import _load_yaml_auth
        auth = {}
        yaml_cfg = {"llm": {"connectors": {"openrouter": {"name": "or", "api_key": "sk-123"}}}}
        _load_yaml_auth(yaml_cfg, auth)
        self.assertEqual(auth["or"], "sk-123")

    def test_loads_list_connector(self):
        from ai_vuln_harness.run import _load_yaml_auth
        auth = {}
        yaml_cfg = {"llm": {"connectors": {"providers": [{"name": "p1", "api_key": "key1"}]}}}
        _load_yaml_auth(yaml_cfg, auth)
        self.assertEqual(auth["p1"], "key1")

    def test_does_not_overwrite_existing(self):
        from ai_vuln_harness.run import _load_yaml_auth
        auth = {"existing": "old_key"}
        yaml_cfg = {"llm": {"connectors": {"x": {"name": "existing", "api_key": "new_key"}}}}
        _load_yaml_auth(yaml_cfg, auth)
        self.assertEqual(auth["existing"], "old_key")

    def test_skips_empty_api_key(self):
        from ai_vuln_harness.run import _load_yaml_auth
        auth = {}
        yaml_cfg = {"llm": {"connectors": {"x": {"name": "or", "api_key": ""}}}}
        _load_yaml_auth(yaml_cfg, auth)
        self.assertEqual(auth, {})

    def test_empty_config(self):
        from ai_vuln_harness.run import _load_yaml_auth
        auth = {}
        _load_yaml_auth({}, auth)
        self.assertEqual(auth, {})


class BuildHuntTasksTests(unittest.TestCase):
    """Tests for _build_hunt_tasks() in run.py."""

    def test_pooled_mode(self):
        from ai_vuln_harness.run import _build_hunt_tasks
        packs = [{"agent": "a"}, {"agent": "b"}]
        tasks = _build_hunt_tasks(packs, ["m1"], model_pool="pool")
        self.assertEqual(len(tasks), 2)
        self.assertEqual(tasks[0]["pack"]["agent"], "a")

    def test_non_pooled_with_preferred(self):
        from ai_vuln_harness.run import _build_hunt_tasks
        packs = [{"agent": "mem-safety"}]
        tasks = _build_hunt_tasks(packs, ["model-a", "model-b"], model_pool=None)
        self.assertEqual(len(tasks), 1)
        self.assertIn("models", tasks[0])


if __name__ == "__main__":
    unittest.main()
