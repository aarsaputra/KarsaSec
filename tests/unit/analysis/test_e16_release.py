"""Unit tests for Monotonic Release State Machine."""

import pytest
from karsasec.analysis.e16_models import AdmissionStatus, ReleaseAdmission, ReleaseState
from karsasec.analysis.e16_release import IllegalStateTransitionError, ReleaseStateMachine


def test_release_state_machine_valid_flow():
    sm = ReleaseStateMachine(artifact_id="art123")
    assert sm.current_state == ReleaseState.CREATED

    adm = ReleaseAdmission.create(
        status=AdmissionStatus.APPROVED,
        artifact_id="art123",
        artifact_content_hash="ch123",
        decision_id="dec123",
        policy_id="pol123",
        evaluation_id="eval123",
        reason_codes=("APPROVED",),
    )

    sm.transition(ReleaseState.SECURITY_EVALUATED, adm)
    assert sm.current_state == ReleaseState.SECURITY_EVALUATED

    sm.transition(ReleaseState.APPROVED, adm)
    assert sm.current_state == ReleaseState.APPROVED


def test_release_state_machine_blocks_illegal_transition():
    sm = ReleaseStateMachine(artifact_id="art123")
    adm_b = ReleaseAdmission.create(
        status=AdmissionStatus.BLOCKED,
        artifact_id="art123",
        artifact_content_hash="ch123",
        decision_id="dec123",
        policy_id="pol123",
        evaluation_id="eval123",
        reason_codes=("BLOCKED",),
    )
    sm.transition(ReleaseState.SECURITY_EVALUATED, adm_b)
    sm.transition(ReleaseState.BLOCKED, adm_b)
    assert sm.current_state == ReleaseState.BLOCKED

    with pytest.raises(IllegalStateTransitionError):
        sm.transition(ReleaseState.APPROVED, adm_b)
