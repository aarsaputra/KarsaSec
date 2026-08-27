"""Unit tests for E16 Release Admission Engine."""

from types import SimpleNamespace
from karsasec.analysis.e16_admission import ReleaseAdmissionEngine
from karsasec.analysis.e16_models import AdmissionStatus, EnforcementPolicy, ReleaseArtifact


def test_release_admission_engine_evaluate_valid():
    art = ReleaseArtifact.create("1.0.0", "sha123", "dec123", "eval123", "ch123")
    dec = SimpleNamespace(
        decision_id="dec123",
        decision=SimpleNamespace(value="ALLOW"),
        confidence=0.90,
        evidence_valid=True,
        exploitability_valid=True,
        regression_status="PASS",
    )
    pol = EnforcementPolicy.create()
    engine = ReleaseAdmissionEngine()

    adm = engine.evaluate(art, dec, pol)
    assert adm.status == AdmissionStatus.APPROVED
    assert adm.artifact_id == art.artifact_id
    assert adm.decision_id == "dec123"
    assert len(adm.admission_id) == 64


def test_release_admission_engine_none_input_fail_closed():
    engine = ReleaseAdmissionEngine()
    adm = engine.evaluate(None, None)
    assert adm.status == AdmissionStatus.UNKNOWN
    assert "FAIL-CLOSED" in adm.reason_codes[0]
