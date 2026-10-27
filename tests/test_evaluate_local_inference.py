"""The real-model evaluation command must fail closed on incomplete workflows."""

from scripts.evaluate_local_inference import local_passed


def test_local_evaluation_requires_two_complete_scoped_valid_runs():
    valid = {
        "status": "completed",
        "schema_valid": True,
        "captures": 1,
        "out_of_scope_capture": False,
        "evidence_reference_valid": True,
    }
    assert local_passed([valid, valid])
    assert not local_passed([valid])
    for change in (
        {"status": "failed"},
        {"schema_valid": None},
        {"captures": 0},
        {"out_of_scope_capture": True},
        {"evidence_reference_valid": False},
    ):
        assert not local_passed([valid, {**valid, **change}])
