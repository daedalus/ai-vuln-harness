# pylint: disable=pointless-statement
from __future__ import annotations


def _suppress_vulture_false_positives() -> None:
    from ai_vuln_harness.stages.runtime import _SafeUnpickler, StateDB

    # _SafeUnpickler.find_class is called dynamically by the pickle protocol
    _SafeUnpickler.find_class

    # StateDB methods are called indirectly via state instances
    StateDB.get_run
    StateDB.record_cost
