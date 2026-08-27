"""Unit tests for E16 Policy-as-Code Engine."""

from types import SimpleNamespace
from karsasec.analysis.e16_models import AdmissionStatus, EnforcementPolicy, ReleaseArtifact
from karsasec.analysis.e16_policy import PolicyEngine


def test_policy_engine_allow_on_valid_inputs():
    pol = EnforcementPolicy.create(allow_on=("ALLOW",), minimum_confidence=0.80)
    engine = PolicyEngine(pol)

    art = ReleaseArtifact.create(
        version="1.0.0",
        commit_sha="sha123",
        decision_id="dec123",
        evaluation_id="eval123",
        content_hash="hash123",
    )
    decision = SimpleNamespace(
        decision_id="dec123",
        decision=SimpleNamespace(value="ALLOW"),
        confidence=0.90,
        evidence_valid=True,
        exploitability_valid=True,
        regression_status="PASS",
    )

    status, reasons = engine.evaluate(art, decision)
    assert status == AdmissionStatus.APPROVED
    assert any("RELEASE APPROVED" in r for r in reasons)


def test_policy_engine_block_on_nan_confidence():
    pol = EnforcementPolicy.create()
    engine = PolicyEngine(pol)

    art = ReleaseArtifact.create("1.0", "sha", "dec", "eval", "hash")
    decision = SimpleNamespace(
        decision_id="dec",
        decision=SimpleNamespace(value="ALLOW"),
        confidence=float("nan"),
        evidence_valid=True,
        exploitability_valid=True,
        regression_status="PASS",
    )

    status, reasons = engine.evaluate(art, decision)
    assert status == AdmissionStatus.UNKNOWN
    assert any("Invalid confidence score" in r for r in reasons)


def test_policy_engine_block_on_regression_failure():
    pol = EnforcementPolicy.create()
    engine = PolicyEngine(pol)

    art = ReleaseArtifact.create("1.0", "sha", "dec", "eval", "hash")
    decision = SimpleNamespace(
        decision_id="dec",
        decision=SimpleNamespace(value="ALLOW"),
        confidence=0.95,
        evidence_valid=True,
        exploitability_valid=True,
        regression_status="FAIL",
    )

    status, reasons = engine.evaluate(art, decision)
    assert status == AdmissionStatus.BLOCKED
    assert any("Security regression detected" in r for r in reasons)
