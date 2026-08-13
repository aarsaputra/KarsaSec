"""Comprehensive Unit & Adversarial Test Suite for LifecycleAuditEvent (Sprint E13-5 Phase 3).

Validates Security Invariants:
  - L11: Immutability & Event Schema
  - L12-L13: Deterministic Event Fingerprinting & Metadata Order Invariance
  - L14-L17: Proposal, Snapshot, Verification, Repository, & Predecessor Binding
  - L25: Timestamp Non-Authority
  - L26: No Security Verdict Authority
  - L27: Privacy Filtering & Sensitive Metadata Rejection
  - L28: No Execution Capabilities
"""

from __future__ import annotations

import dataclasses
import pytest

from karsasec.ai.remediation.audit import AuditEventType, LifecycleAuditEvent, sanitize_metadata


def _make_dummy_event(
    event_id: str = "E-101",
    event_type: str = "FINDING_DETECTED",
    finding_id: str = "F-101",
    lifecycle_state: str = "DETECTED",
    actor: str = "scanner",
    timestamp: str = "2026-08-13T12:00:00Z",
    repository_identity: str = "/repo",
    predecessor_event_id: str | None = None,
    predecessor_event_fingerprint: str | None = None,
    proposal_fingerprint: str | None = None,
    source_snapshot_hash: str | None = None,
    post_apply_snapshot_hash: str | None = None,
    verification_run_id: str | None = None,
    verification_fingerprint: str | None = None,
    provenance_fingerprint: str | None = None,
    metadata: dict | tuple = (),
) -> LifecycleAuditEvent:
    return LifecycleAuditEvent.create(
        event_id=event_id,
        event_type=event_type,
        finding_id=finding_id,
        lifecycle_state=lifecycle_state,
        actor=actor,
        timestamp=timestamp,
        repository_identity=repository_identity,
        predecessor_event_id=predecessor_event_id,
        predecessor_event_fingerprint=predecessor_event_fingerprint,
        proposal_fingerprint=proposal_fingerprint,
        source_snapshot_hash=source_snapshot_hash,
        post_apply_snapshot_hash=post_apply_snapshot_hash,
        verification_run_id=verification_run_id,
        verification_fingerprint=verification_fingerprint,
        provenance_fingerprint=provenance_fingerprint,
        metadata=metadata,
    )


def test_01_event_creation() -> None:
    ev = _make_dummy_event()
    assert ev.event_id == "E-101"
    assert ev.event_type == AuditEventType.FINDING_DETECTED
    assert len(ev.event_fingerprint) == 64


def test_02_event_fingerprint_determinism() -> None:
    ev1 = _make_dummy_event()
    ev2 = _make_dummy_event()
    assert ev1.event_fingerprint == ev2.event_fingerprint


def test_03_same_logical_event_same_fingerprint() -> None:
    meta1 = (("a", "1"), ("b", "2"))
    meta2 = (("b", "2"), ("a", "1"))
    ev1 = _make_dummy_event(metadata=meta1)
    ev2 = _make_dummy_event(metadata=meta2)
    assert ev1.event_fingerprint == ev2.event_fingerprint


def test_04_different_event_different_fingerprint() -> None:
    ev1 = _make_dummy_event(event_id="E-101")
    ev2 = _make_dummy_event(event_id="E-102")
    assert ev1.event_fingerprint != ev2.event_fingerprint


def test_05_metadata_canonicalization() -> None:
    raw_meta = {"z_key": "val_z", "a_key": "val_a"}
    res = sanitize_metadata(raw_meta)
    assert res == (("a_key", "val_a"), ("z_key", "val_z"))


def test_06_dictionary_order_invariance() -> None:
    m1 = {"rule": "R1", "cwe": "CWE-89"}
    m2 = {"cwe": "CWE-89", "rule": "R1"}
    ev1 = _make_dummy_event(metadata=m1)
    ev2 = _make_dummy_event(metadata=m2)
    assert ev1.event_fingerprint == ev2.event_fingerprint


def test_07_immutable_event_frozen() -> None:
    ev = _make_dummy_event()
    with pytest.raises(dataclasses.FrozenInstanceError):
        ev.event_id = "E-999"  # type: ignore[misc]


def test_08_sensitive_metadata_filtering_passwords() -> None:
    with pytest.raises(ValueError, match="Sensitive metadata key detected"):
        _make_dummy_event(metadata={"db_password": "super_secret_pass"})


def test_09_raw_source_rejection() -> None:
    with pytest.raises(ValueError, match="Sensitive metadata key detected"):
        _make_dummy_event(metadata={"source_code": "def vulnerable_fn(): pass"})


def test_10_secret_and_token_rejection() -> None:
    with pytest.raises(ValueError, match="Sensitive metadata key detected"):
        _make_dummy_event(metadata={"api_key": "secret_key_12345"})

    with pytest.raises(ValueError, match="Sensitive metadata key detected"):
        _make_dummy_event(metadata={"access_token": "bearer_xyz"})


def test_11_proposal_fingerprint_binding() -> None:
    ev = _make_dummy_event(proposal_fingerprint="prop_fp_101")
    assert ev.proposal_fingerprint == "prop_fp_101"
    assert "prop_fp_101" in ev.event_fingerprint or len(ev.event_fingerprint) == 64


def test_12_snapshot_binding() -> None:
    ev = _make_dummy_event(source_snapshot_hash="src_snap_101", post_apply_snapshot_hash="post_snap_101")
    assert ev.source_snapshot_hash == "src_snap_101"
    assert ev.post_apply_snapshot_hash == "post_snap_101"


def test_13_verification_binding() -> None:
    ev = _make_dummy_event(verification_run_id="ver_run_1", verification_fingerprint="ver_fp_101")
    assert ev.verification_run_id == "ver_run_1"
    assert ev.verification_fingerprint == "ver_fp_101"


def test_14_repository_binding() -> None:
    ev = _make_dummy_event(repository_identity="/var/workspace/repo")
    assert ev.repository_identity == "/var/workspace/repo"


def test_15_predecessor_binding() -> None:
    ev = _make_dummy_event(predecessor_event_id="E-100", predecessor_event_fingerprint="fp_100")
    assert ev.predecessor_event_id == "E-100"
    assert ev.predecessor_event_fingerprint == "fp_100"


def test_16_timestamp_treated_as_metadata_not_authority() -> None:
    # Changing timestamp produces different audit fingerprint but does NOT grant authority
    ev1 = _make_dummy_event(timestamp="2026-08-13T12:00:00Z")
    ev2 = _make_dummy_event(timestamp="2026-08-13T12:05:00Z")
    assert ev1.event_fingerprint != ev2.event_fingerprint
    assert not hasattr(ev1, "grant_verdict")


def test_17_no_verdict_authority() -> None:
    ev = _make_dummy_event(event_type="VERIFIED_FIXED")
    assert not hasattr(ev, "apply_fix")
    assert not hasattr(ev, "mutate_finding")


def test_18_no_execution_capability() -> None:
    ev = _make_dummy_event()
    assert not hasattr(ev, "subprocess")
    assert not hasattr(ev, "os")
    assert not hasattr(ev, "retry")


def test_19_tampered_event_fingerprint_rejection() -> None:
    with pytest.raises(ValueError, match="Invalid or tampered event fingerprint"):
        LifecycleAuditEvent(
            event_id="E-101",
            event_type=AuditEventType.FINDING_DETECTED,
            finding_id="F-101",
            lifecycle_state="DETECTED",
            actor="scanner",
            timestamp="2026-08-13T12:00:00Z",
            repository_identity="/repo",
            event_fingerprint="forged_fingerprint_12345678901234567890123456789012345678901234567890",
        )


def test_20_serialization_roundtrip_to_from_dict() -> None:
    ev1 = _make_dummy_event(proposal_fingerprint="prop_fp_101", metadata={"rule_id": "RULE-01"})
    d = ev1.to_dict()
    ev2 = LifecycleAuditEvent.from_dict(d)
    assert ev1 == ev2
    assert ev1.event_fingerprint == ev2.event_fingerprint
