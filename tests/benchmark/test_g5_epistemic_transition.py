"""Unit tests verifying Epistemic Transition Safety (INV-G5.4-05)."""

from karsasec.benchmark.epistemic_transition import validate_epistemic_transition


def test_epistemic_transition_rejects_unsupported_unknown_to_safe() -> None:
    res = validate_epistemic_transition("UNKNOWN", "SAFE")
    assert res["status"] == "INVALID_TRANSITION"
    assert res["valid"] is False


def test_epistemic_transition_rejects_unsupported_unknown_to_vulnerable() -> None:
    res = validate_epistemic_transition("UNKNOWN", "VULNERABLE")
    assert res["status"] == "INVALID_TRANSITION"
    assert res["valid"] is False


def test_epistemic_transition_rejects_unsupported_conflict_to_safe() -> None:
    res = validate_epistemic_transition("CONFLICT", "SAFE")
    assert res["status"] == "INVALID_TRANSITION"
    assert res["valid"] is False


def test_epistemic_transition_accepts_identity_unknown_to_unknown() -> None:
    res = validate_epistemic_transition("UNKNOWN", "UNKNOWN")
    assert res["status"] == "PASS"
    assert res["valid"] is True


def test_epistemic_transition_accepts_explicit_validated_evidence() -> None:
    res = validate_epistemic_transition(
        "UNKNOWN", "VULNERABLE", evidence={"validated": True, "proof": "source_sink_proven"}
    )
    assert res["status"] == "PASS"
    assert res["valid"] is True
