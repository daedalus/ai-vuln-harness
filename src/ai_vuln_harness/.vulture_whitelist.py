# pylint: disable=pointless-statement
from __future__ import annotations


def _suppress_vulture_false_positives() -> None:
    from ai_vuln_harness.stages.runtime import StateDB

    # StateDB methods are called indirectly via state instances
    StateDB.get_run
    StateDB.record_cost
