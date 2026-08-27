"""Unit tests for Anti-Confused-Deputy Enforcement Engine."""

from karsasec.analysis.e16_enforcement import EnforcementEngine
from karsasec.analysis.e16_models import AdmissionStatus, ReleaseAdmission


def test_enforcement_engine_approved():
    adm = ReleaseAdmission.create(
        status=AdmissionStatus.APPROVED,
        artifact_id="art1",
        artifact_content_hash="ch1",
        decision_id="dec1",
        policy_id="pol1",
        evaluation_id="eval1",
        reason_codes=("RELEASE APPROVED",),
    )
    engine = EnforcementEngine()
    perm = engine.authorize_permission(adm)

    assert perm.is_permitted is True
    assert perm.permission_status == "PERMITTED"
    assert perm.admission_id == "art1" or len(perm.permission_id) == 64


def test_enforcement_engine_rejects_none_input():
    engine = EnforcementEngine()
    perm = engine.authorize_permission(None)
    assert perm.is_permitted is False
    assert perm.permission_status == "PROHIBITED_INVALID_INPUT"


def test_enforcement_engine_prohibits_blocked_and_unknown():
    adm_b = ReleaseAdmission.create(
        status=AdmissionStatus.BLOCKED,
        artifact_id="art1",
        artifact_content_hash="ch1",
        decision_id="dec1",
        policy_id="pol1",
        evaluation_id="eval1",
        reason_codes=("BLOCKED",),
    )
    engine = EnforcementEngine()
    perm_b = engine.authorize_permission(adm_b)
    assert perm_b.is_permitted is False
    assert perm_b.permission_status == "PROHIBITED_BLOCKED"

    adm_u = ReleaseAdmission.create(
        status=AdmissionStatus.UNKNOWN,
        artifact_id="art1",
        artifact_content_hash="ch1",
        decision_id="dec1",
        policy_id="pol1",
        evaluation_id="eval1",
        reason_codes=("UNKNOWN",),
    )
    perm_u = engine.authorize_permission(adm_u)
    assert perm_u.is_permitted is False
    assert perm_u.permission_status == "PROHIBITED_UNKNOWN"
