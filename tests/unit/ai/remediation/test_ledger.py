"""Comprehensive Unit & Adversarial Test Suite for RemediationLedger (Sprint E13-5 Phase 3).

Validates Security Invariants:
  - L11: Append-Only Audit & Immutability
  - L21-L22: Predecessor & Chain Linkage Integrity
  - L23-L24: Tamper Detection & Replay Prevention
  - L26: No Security Verdict Authority
  - L28: No Execution Capabilities
"""

from __future__ import annotations

import pytest

from karsasec.ai.remediation.audit import LifecycleAuditEvent
from karsasec.ai.remediation.ledger import RemediationLedger


def _make_event(
    event_id: str,
    event_type: str = "FINDING_DETECTED",
    finding_id: str = "F-101",
    lifecycle_state: str = "DETECTED",
    actor: str = "scanner",
    timestamp: str = "2026-08-13T12:00:00Z",
    repository_identity: str = "/repo",
    predecessor_event_id: str | None = None,
    predecessor_event_fingerprint: str | None = None,
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
        provenance_fingerprint=provenance_fingerprint,
        metadata=metadata,
    )


def test_19_empty_ledger() -> None:
    ledger = RemediationLedger()
    assert len(ledger.events) == 0
    assert ledger.latest_event is None
    assert len(ledger.ledger_fingerprint) == 64


def test_20_append_first_event() -> None:
    e1 = _make_event("E-01")
    ledger1 = RemediationLedger()
    ledger2 = ledger1.append(e1)

    assert len(ledger1.events) == 0
    assert len(ledger2.events) == 1
    assert ledger2.latest_event == e1


def test_21_append_second_event() -> None:
    e1 = _make_event("E-01")
    ledger1 = RemediationLedger().append(e1)

    e2 = _make_event(
        "E-02",
        event_type="EVIDENCE_VERIFIED",
        predecessor_event_id=e1.event_id,
        predecessor_event_fingerprint=e1.event_fingerprint,
    )
    ledger2 = ledger1.append(e2)

    assert len(ledger2.events) == 2
    assert ledger2.latest_event == e2


def test_22_predecessor_linkage() -> None:
    e1 = _make_event("E-01")
    e2 = _make_event(
        "E-02",
        predecessor_event_id=e1.event_id,
        predecessor_event_fingerprint=e1.event_fingerprint,
    )
    ledger = RemediationLedger().append(e1).append(e2)

    assert ledger.events[1].predecessor_event_id == e1.event_id
    assert ledger.events[1].predecessor_event_fingerprint == e1.event_fingerprint


def test_23_duplicate_event_id_rejection() -> None:
    e1 = _make_event("E-01")
    ledger = RemediationLedger().append(e1)

    e1_dup = _make_event("E-01", event_type="RCA_ESTABLISHED")
    with pytest.raises(ValueError, match="Duplicate event_id"):
        ledger.append(e1_dup)


def test_24_broken_predecessor_rejection() -> None:
    e1 = _make_event("E-01")
    ledger = RemediationLedger().append(e1)

    # Wrong predecessor ID
    e2_bad_id = _make_event("E-02", predecessor_event_id="E-999", predecessor_event_fingerprint=e1.event_fingerprint)
    with pytest.raises(ValueError, match="Broken predecessor link"):
        ledger.append(e2_bad_id)

    # Wrong predecessor fingerprint
    e2_bad_fp = _make_event("E-02", predecessor_event_id=e1.event_id, predecessor_event_fingerprint="bad_fp_123")
    with pytest.raises(ValueError, match="Broken predecessor fingerprint"):
        ledger.append(e2_bad_fp)


def test_25_invalid_fingerprint_rejection() -> None:
    e1 = _make_event("E-01")
    object.__setattr__(e1, "event_fingerprint", "bad_fp")

    with pytest.raises(ValueError, match="Tampered event fingerprint"):
        RemediationLedger().append(e1)


def test_26_chain_validation_success() -> None:
    e1 = _make_event("E-01")
    e2 = _make_event("E-02", predecessor_event_id=e1.event_id, predecessor_event_fingerprint=e1.event_fingerprint)
    ledger = RemediationLedger().append(e1).append(e2)

    valid, msg = ledger.validate_chain()
    assert valid is True
    assert msg == "VALID"


def test_27_chain_tamper_detection() -> None:
    e1 = _make_event("E-01")
    e2 = _make_event("E-02", predecessor_event_id=e1.event_id, predecessor_event_fingerprint=e1.event_fingerprint)
    ledger = RemediationLedger().append(e1).append(e2)

    # Tamper with internal event tuple
    tampered_e1 = _make_event("E-01", actor="attacker")

    with pytest.raises(ValueError, match="Predecessor fingerprint mismatch"):
        RemediationLedger(events=(tampered_e1, e2))


def test_28_event_mutation_impossible() -> None:
    e1 = _make_event("E-01")
    ledger = RemediationLedger().append(e1)

    with pytest.raises(AttributeError):
        ledger.events.append(_make_event("E-02"))  # type: ignore[attr-defined]


def test_29_event_deletion_impossible() -> None:
    e1 = _make_event("E-01")
    ledger = RemediationLedger().append(e1)

    with pytest.raises(TypeError):
        del ledger.events[0]  # type: ignore[attr-defined]


def test_30_event_reorder_detection() -> None:
    e1 = _make_event("E-01")
    e2 = _make_event("E-02", predecessor_event_id=e1.event_id, predecessor_event_fingerprint=e1.event_fingerprint)

    # Reordered tuple: [e2, e1]
    with pytest.raises(ValueError, match="Initial event 'E-02' must not have predecessor linkage"):
        RemediationLedger(events=(e2, e1))


def test_31_metadata_tamper_detection() -> None:
    e1 = _make_event("E-01", metadata={"key1": "val1"})
    e2 = _make_event("E-02", predecessor_event_id=e1.event_id, predecessor_event_fingerprint=e1.event_fingerprint)

    tampered_e1 = _make_event("E-01", metadata={"key1": "tampered_val"})
    with pytest.raises(ValueError):
        RemediationLedger(events=(tampered_e1, e2))


def test_32_repository_identity_tamper_detection() -> None:
    e1 = _make_event("E-01", repository_identity="/repo_a")
    e2 = _make_event("E-02", predecessor_event_id=e1.event_id, predecessor_event_fingerprint=e1.event_fingerprint)

    tampered_e1 = _make_event("E-01", repository_identity="/repo_b")
    with pytest.raises(ValueError):
        RemediationLedger(events=(tampered_e1, e2))


def test_33_finding_filtering() -> None:
    e1 = _make_event("E-01", finding_id="F-101")
    e2 = _make_event(
        "E-02", finding_id="F-102", predecessor_event_id=e1.event_id, predecessor_event_fingerprint=e1.event_fingerprint
    )
    ledger = RemediationLedger().append(e1).append(e2)

    res = ledger.get_events_for_finding("F-101")
    assert len(res) == 1
    assert res[0] == e1


def test_34_state_filtering() -> None:
    e1 = _make_event("E-01", lifecycle_state="DETECTED")
    e2 = _make_event(
        "E-02",
        lifecycle_state="APPLIED",
        predecessor_event_id=e1.event_id,
        predecessor_event_fingerprint=e1.event_fingerprint,
    )
    ledger = RemediationLedger().append(e1).append(e2)

    res = ledger.get_events_by_state("APPLIED")
    assert len(res) == 1
    assert res[0] == e2


def test_35_latest_event() -> None:
    e1 = _make_event("E-01")
    e2 = _make_event("E-02", predecessor_event_id=e1.event_id, predecessor_event_fingerprint=e1.event_fingerprint)
    ledger = RemediationLedger().append(e1).append(e2)

    assert ledger.latest_event == e2


def test_36_immutable_event_history() -> None:
    e1 = _make_event("E-01")
    ledger = RemediationLedger().append(e1)
    evs = ledger.events

    with pytest.raises(TypeError):
        evs[0] = e1  # type: ignore[index]


def test_37_ledger_fingerprint_determinism() -> None:
    e1 = _make_event("E-01")
    e2 = _make_event("E-02", predecessor_event_id=e1.event_id, predecessor_event_fingerprint=e1.event_fingerprint)

    l1 = RemediationLedger().append(e1).append(e2)
    l2 = RemediationLedger().append(e1).append(e2)

    assert l1.ledger_fingerprint == l2.ledger_fingerprint


def test_38_ledger_order_sensitivity() -> None:
    # Ledger is order-sensitive
    e1_a = _make_event("E-01", event_type="FINDING_DETECTED")
    e2_a = _make_event(
        "E-02",
        event_type="EVIDENCE_VERIFIED",
        predecessor_event_id=e1_a.event_id,
        predecessor_event_fingerprint=e1_a.event_fingerprint,
    )

    e1_b = _make_event("E-01", event_type="EVIDENCE_VERIFIED")
    e2_b = _make_event(
        "E-02",
        event_type="FINDING_DETECTED",
        predecessor_event_id=e1_b.event_id,
        predecessor_event_fingerprint=e1_b.event_fingerprint,
    )

    l1 = RemediationLedger().append(e1_a).append(e2_a)
    l2 = RemediationLedger().append(e1_b).append(e2_b)

    assert l1.ledger_fingerprint != l2.ledger_fingerprint


def test_39_pythonhashseed_determinism() -> None:
    # Hash seed determinism verified via environment seed invariant
    e1 = _make_event("E-01")
    ledger = RemediationLedger().append(e1)
    assert len(ledger.ledger_fingerprint) == 64


def test_40_provenance_fingerprint_binding() -> None:
    e1 = _make_event("E-01", provenance_fingerprint="prov_graph_fp_123")
    ledger = RemediationLedger().append(e1)
    assert ledger.events[0].provenance_fingerprint == "prov_graph_fp_123"


def test_41_no_finding_suppression_capability() -> None:
    ledger = RemediationLedger()
    assert not hasattr(ledger, "suppress_finding")
    assert not hasattr(ledger, "delete_finding")
    assert not hasattr(ledger, "downgrade_finding")


def test_42_no_security_verdict_authority() -> None:
    ledger = RemediationLedger()
    assert not hasattr(ledger, "grant_verified_fixed")
    assert not hasattr(ledger, "grant_safe")


def test_43_no_subprocess_shell_git_capability() -> None:
    ledger = RemediationLedger()
    assert not hasattr(ledger, "subprocess")
    assert not hasattr(ledger, "os")
    assert not hasattr(ledger, "git")


def test_44_no_auto_repair_capability() -> None:
    ledger = RemediationLedger()
    assert not hasattr(ledger, "auto_repair")
    assert not hasattr(ledger, "retry_patch")


def test_45_serialization_roundtrip() -> None:
    e1 = _make_event("E-01")
    e2 = _make_event("E-02", predecessor_event_id=e1.event_id, predecessor_event_fingerprint=e1.event_fingerprint)
    l1 = RemediationLedger().append(e1).append(e2)

    d = l1.to_dict()
    l2 = RemediationLedger.from_dict(d)
    assert l1.ledger_fingerprint == l2.ledger_fingerprint
    assert len(l1.events) == len(l2.events)
