"""Unit tests for E16 Domain Models and SHA-256 identity computation."""

import pytest
from karsasec.analysis.e16_models import (
    AdmissionStatus,
    EnforcementPolicy,
    ReleaseAdmission,
    ReleaseArtifact,
    deterministic_id,
)


def test_admission_status_enum():
    assert AdmissionStatus.APPROVED.value == "APPROVED"
    assert AdmissionStatus.BLOCKED.value == "BLOCKED"
    assert AdmissionStatus.REVIEW_REQUIRED.value == "REVIEW_REQUIRED"
    assert AdmissionStatus.UNKNOWN.value == "UNKNOWN"


def test_deterministic_id_properties():
    h1 = deterministic_id("E16-TEST:v1:", {"b": 2, "a": 1})
    h2 = deterministic_id("E16-TEST:v1:", {"a": 1, "b": 2})
    assert len(h1) == 64
    assert h1 == h2


def test_release_artifact_immutability():
    art = ReleaseArtifact.create(
        version="1.0.0",
        commit_sha="abc1234",
        decision_id="dec001",
        evaluation_id="eval001",
        content_hash="hash001",
    )
    assert art.artifact_id.startswith("") and len(art.artifact_id) == 64
    with pytest.raises(AttributeError):
        art.version = "2.0.0"


def test_enforcement_policy_creation():
    pol = EnforcementPolicy.create(
        allow_on=("ALLOW",),
        minimum_confidence=0.85,
    )
    assert pol.policy_id is not None
    assert pol.minimum_confidence == 0.85


def test_release_admission_to_dict():
    adm = ReleaseAdmission.create(
        status=AdmissionStatus.APPROVED,
        artifact_id="art123",
        artifact_content_hash="ch123",
        decision_id="dec123",
        policy_id="pol123",
        evaluation_id="eval123",
        reason_codes=("RELEASE APPROVED",),
    )
    d = adm.to_dict()
    assert d["status"] == "APPROVED"
    assert d["artifact_id"] == "art123"
