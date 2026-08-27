"""Unit and Invariant test suite for Sprint E18: Continuous Security Verification."""

from karsasec.continuous.drift_evaluator import SecurityDriftEvaluator
from karsasec.continuous.engine import ContinuousVerificationEngine
from karsasec.continuous.models import VerificationSnapshot


def test_verification_snapshot_creation():
    snap = VerificationSnapshot.create(
        target_id="APP-001",
        cluster_count=5,
        critical_count=1,
        high_count=2,
        policy_hash="p-hash-1",
    )
    assert len(snap.snapshot_id) == 64
    assert snap.target_id == "APP-001"


def test_drift_evaluator_no_drift():
    evaluator = SecurityDriftEvaluator()
    base = VerificationSnapshot.create("APP-1", 5, 0, 1, "p-hash-1")
    curr = VerificationSnapshot.create("APP-1", 5, 0, 1, "p-hash-1")

    rep = evaluator.compare(base, curr)
    assert rep.has_drift is False
    assert rep.drift_type == "NO_DRIFT"


def test_drift_evaluator_detects_critical_drift():
    evaluator = SecurityDriftEvaluator()
    base = VerificationSnapshot.create("APP-1", 5, 0, 1, "p-hash-1")
    curr = VerificationSnapshot.create("APP-1", 6, 2, 1, "p-hash-1")

    rep = evaluator.compare(base, curr)
    assert rep.has_drift is True
    assert "CRITICAL_DRIFT" in rep.drift_type


def test_continuous_verification_engine_missing_baseline():
    engine = ContinuousVerificationEngine()
    curr = VerificationSnapshot.create("APP-UNKNOWN", 1, 0, 0, "p-hash")

    rep = engine.verify_target(curr)
    assert rep.has_drift is True
    assert rep.drift_type == "MISSING_BASELINE"
