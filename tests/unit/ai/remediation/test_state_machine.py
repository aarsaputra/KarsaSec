"""Comprehensive Unit & Adversarial Test Suite for LifecycleStateMachine (Sprint E13-5 Phase 1).

Validates Security Invariants L1, L2, L3, L4, L6, L7, L9, L18:
  - L1: Transition Authority
  - L2: No State Skipping / Explicit Matrix
  - L3: Historical Immutability
  - L4: Verification Evidence Binding
  - L6: Verification Freshness
  - L7: Zero LLM Security Authority
  - L9: No Auto-Repair Loop Capabilities
  - L18: Failure Finality
"""

from __future__ import annotations

import dataclasses

import pytest

from karsasec.ai.remediation.state_machine import (
    InvalidStateTransitionError,
    LifecycleEvent,
    LifecycleStateMachine,
    RemediationLifecycleState,
    VerificationAuthority,
    VerificationEvidenceContract,
)

# =============================================================================
# 1. BASIC STATE TRANSITION BEHAVIOR TESTS (1 - 10)
# =============================================================================


def test_01_initial_state_is_detected() -> None:
    sm = LifecycleStateMachine("F-101")
    assert sm.current_state == RemediationLifecycleState.DETECTED
    assert sm.finding_id == "F-101"
    assert len(sm.history) == 1
    assert sm.history[0].new_state == RemediationLifecycleState.DETECTED


def test_02_valid_detected_to_evidence_verified() -> None:
    sm = LifecycleStateMachine("F-101")
    evt = sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED, actor="sast_engine")
    assert sm.current_state == RemediationLifecycleState.EVIDENCE_VERIFIED
    assert evt.previous_state == RemediationLifecycleState.DETECTED
    assert evt.new_state == RemediationLifecycleState.EVIDENCE_VERIFIED
    assert evt.actor == "sast_engine"


def test_03_valid_evidence_verified_to_rca_established() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    assert sm.current_state == RemediationLifecycleState.RCA_ESTABLISHED


def test_04_valid_rca_established_to_remediation_proposed() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    assert sm.current_state == RemediationLifecycleState.REMEDIATION_PROPOSED


def test_05_valid_remediation_proposed_to_awaiting_approval() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    assert sm.current_state == RemediationLifecycleState.AWAITING_APPROVAL


def test_06_valid_awaiting_approval_to_approved() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED, actor="lead_architect")
    assert sm.current_state == RemediationLifecycleState.APPROVED


def test_07_valid_approved_to_snapshot_verified() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    assert sm.current_state == RemediationLifecycleState.SNAPSHOT_VERIFIED


def test_08_valid_snapshot_verified_to_applying() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    assert sm.current_state == RemediationLifecycleState.APPLYING


def test_09_valid_applying_to_applied_unverified() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLIED_UNVERIFIED)
    assert sm.current_state == RemediationLifecycleState.APPLIED_UNVERIFIED


def test_10_valid_applied_unverified_to_security_rescan() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLIED_UNVERIFIED)
    sm.transition(RemediationLifecycleState.SECURITY_RESCAN)
    assert sm.current_state == RemediationLifecycleState.SECURITY_RESCAN


# =============================================================================
# 2. INVALID STATE TRANSITION REJECTION TESTS (11 - 17)
# =============================================================================


def test_11_detected_to_verified_fixed_rejected() -> None:
    sm = LifecycleStateMachine("F-101")
    with pytest.raises(InvalidStateTransitionError):
        sm.transition(RemediationLifecycleState.VERIFIED_FIXED)


def test_12_remediation_proposed_to_verified_fixed_rejected() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    with pytest.raises(InvalidStateTransitionError):
        sm.transition(RemediationLifecycleState.VERIFIED_FIXED)


def test_13_approved_to_verified_fixed_rejected() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    with pytest.raises(InvalidStateTransitionError):
        sm.transition(RemediationLifecycleState.VERIFIED_FIXED)


def test_14_applying_to_verified_fixed_rejected() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    with pytest.raises(InvalidStateTransitionError):
        sm.transition(RemediationLifecycleState.VERIFIED_FIXED)


def test_15_applied_unverified_to_verified_fixed_without_rescan_rejected() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLIED_UNVERIFIED)
    with pytest.raises(InvalidStateTransitionError):
        sm.transition(RemediationLifecycleState.VERIFIED_FIXED)


def test_16_invalid_backward_transition_rejected() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    with pytest.raises(InvalidStateTransitionError):
        sm.transition(RemediationLifecycleState.DETECTED)


def test_17_rejected_state_cannot_transition_further() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.REJECTED)

    assert sm.current_state == RemediationLifecycleState.REJECTED
    assert not sm.can_transition(RemediationLifecycleState.APPROVED)
    with pytest.raises(InvalidStateTransitionError):
        sm.transition(RemediationLifecycleState.APPROVED)


# =============================================================================
# 3. VERIFICATION AUTHORITY & EVIDENCE CONTRACT TESTS (18 - 25)
# =============================================================================


def _get_valid_evidence(finding_id: str = "F-101") -> VerificationEvidenceContract:
    return VerificationEvidenceContract(
        finding_id=finding_id,
        proposal_fingerprint="prop_fp_123",
        source_snapshot_hash="snap_hash_pre",
        post_apply_snapshot_hash="snap_hash_post",
        verification_run_id="v_run_999",
        verification_fingerprint="v_fp_888",
        authority=VerificationAuthority.DETERMINISTIC_SAST,
    )


def test_18_security_rescan_to_verified_fixed_succeeds_with_complete_evidence() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLIED_UNVERIFIED)
    sm.transition(RemediationLifecycleState.SECURITY_RESCAN)

    ev = _get_valid_evidence("F-101")
    evt = sm.transition_verified_fixed(ev)
    assert sm.current_state == RemediationLifecycleState.VERIFIED_FIXED
    assert evt.new_state == RemediationLifecycleState.VERIFIED_FIXED


def test_19_missing_finding_id_in_evidence_rejected() -> None:
    with pytest.raises(ValueError, match="finding_id cannot be empty"):
        VerificationEvidenceContract(
            finding_id="",
            proposal_fingerprint="prop_fp",
            source_snapshot_hash="src",
            post_apply_snapshot_hash="post",
            verification_run_id="v_run",
            verification_fingerprint="v_fp",
            authority=VerificationAuthority.DETERMINISTIC_SAST,
        )


def test_20_missing_proposal_fingerprint_in_evidence_rejected() -> None:
    with pytest.raises(ValueError, match="proposal_fingerprint cannot be empty"):
        VerificationEvidenceContract(
            finding_id="F-101",
            proposal_fingerprint="",
            source_snapshot_hash="src",
            post_apply_snapshot_hash="post",
            verification_run_id="v_run",
            verification_fingerprint="v_fp",
            authority=VerificationAuthority.DETERMINISTIC_SAST,
        )


def test_21_missing_source_snapshot_hash_in_evidence_rejected() -> None:
    with pytest.raises(ValueError, match="source_snapshot_hash cannot be empty"):
        VerificationEvidenceContract(
            finding_id="F-101",
            proposal_fingerprint="prop_fp",
            source_snapshot_hash="",
            post_apply_snapshot_hash="post",
            verification_run_id="v_run",
            verification_fingerprint="v_fp",
            authority=VerificationAuthority.DETERMINISTIC_SAST,
        )


def test_22_missing_post_apply_snapshot_hash_in_evidence_rejected() -> None:
    with pytest.raises(ValueError, match="post_apply_snapshot_hash cannot be empty"):
        VerificationEvidenceContract(
            finding_id="F-101",
            proposal_fingerprint="prop_fp",
            source_snapshot_hash="src",
            post_apply_snapshot_hash="",
            verification_run_id="v_run",
            verification_fingerprint="v_fp",
            authority=VerificationAuthority.DETERMINISTIC_SAST,
        )


def test_23_missing_verification_run_id_in_evidence_rejected() -> None:
    with pytest.raises(ValueError, match="verification_run_id cannot be empty"):
        VerificationEvidenceContract(
            finding_id="F-101",
            proposal_fingerprint="prop_fp",
            source_snapshot_hash="src",
            post_apply_snapshot_hash="post",
            verification_run_id="",
            verification_fingerprint="v_fp",
            authority=VerificationAuthority.DETERMINISTIC_SAST,
        )


def test_24_missing_verification_fingerprint_in_evidence_rejected() -> None:
    with pytest.raises(ValueError, match="verification_fingerprint cannot be empty"):
        VerificationEvidenceContract(
            finding_id="F-101",
            proposal_fingerprint="prop_fp",
            source_snapshot_hash="src",
            post_apply_snapshot_hash="post",
            verification_run_id="v_run",
            verification_fingerprint="",
            authority=VerificationAuthority.DETERMINISTIC_SAST,
        )


def test_25_llm_advisory_authority_rejected_l7() -> None:
    with pytest.raises(ValueError, match="cannot establish VERIFIED_FIXED state"):
        VerificationEvidenceContract(
            finding_id="F-101",
            proposal_fingerprint="prop_fp",
            source_snapshot_hash="src",
            post_apply_snapshot_hash="post",
            verification_run_id="v_run",
            verification_fingerprint="v_fp",
            authority=VerificationAuthority.LLM_ADVISORY,
        )


# =============================================================================
# 4. FAILURE FINALITY TESTS (26 - 30)
# =============================================================================


def test_26_apply_failed_to_rolled_back_allowed() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLY_FAILED)

    sm.transition(RemediationLifecycleState.ROLLED_BACK)
    assert sm.current_state == RemediationLifecycleState.ROLLED_BACK


def test_27_rolled_back_to_applying_rejected_l18() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLY_FAILED)
    sm.transition(RemediationLifecycleState.ROLLED_BACK)

    with pytest.raises(InvalidStateTransitionError):
        sm.transition(RemediationLifecycleState.APPLYING)


def test_28_rolled_back_to_verified_fixed_rejected_l18() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLY_FAILED)
    sm.transition(RemediationLifecycleState.ROLLED_BACK)

    ev = _get_valid_evidence("F-101")
    with pytest.raises(InvalidStateTransitionError):
        sm.transition_verified_fixed(ev)


def test_29_critical_recovery_failure_is_terminal_l18() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLY_FAILED)
    sm.transition(RemediationLifecycleState.CRITICAL_RECOVERY_FAILURE)

    assert sm.current_state == RemediationLifecycleState.CRITICAL_RECOVERY_FAILURE
    assert not sm.can_transition(RemediationLifecycleState.APPLYING)
    with pytest.raises(InvalidStateTransitionError):
        sm.transition(RemediationLifecycleState.APPLYING)


def test_30_critical_recovery_failure_to_verified_fixed_rejected() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLY_FAILED)
    sm.transition(RemediationLifecycleState.CRITICAL_RECOVERY_FAILURE)

    ev = _get_valid_evidence("F-101")
    with pytest.raises(InvalidStateTransitionError):
        sm.transition_verified_fixed(ev)


# =============================================================================
# 5. IMMUTABILITY & DETERMINISM TESTS (31 - 35)
# =============================================================================


def test_31_lifecycle_event_is_frozen_dataclass_l3() -> None:
    sm = LifecycleStateMachine("F-101")
    evt = sm.history[0]
    with pytest.raises(dataclasses.FrozenInstanceError):
        evt.actor = "malicious_actor"  # type: ignore[misc]


def test_32_returned_history_mutation_does_not_mutate_internal_history() -> None:
    sm = LifecycleStateMachine("F-101")
    hist = sm.history
    assert len(hist) == 1
    # Modifying returned tuple is not allowed directly, but if converted to list:
    hist_list = list(hist)
    hist_list.clear()

    # Internal history remains intact
    assert len(sm.history) == 1


def test_33_direct_state_attribute_bypass_blocked() -> None:
    sm = LifecycleStateMachine("F-101")
    # Verify that current_state is a read-only property
    with pytest.raises(AttributeError):
        sm.current_state = RemediationLifecycleState.VERIFIED_FIXED  # type: ignore[misc]


def test_34_same_transition_sequence_produces_identical_deterministic_fingerprint() -> None:
    ts = "2026-08-13T12:00:00Z"
    sm1 = LifecycleStateMachine("F-101", created_at=ts)
    sm1.transition(RemediationLifecycleState.EVIDENCE_VERIFIED, timestamp=ts)

    sm2 = LifecycleStateMachine("F-101", created_at=ts)
    sm2.transition(RemediationLifecycleState.EVIDENCE_VERIFIED, timestamp=ts)

    assert sm1.history[0].event_fingerprint == sm2.history[0].event_fingerprint
    assert sm1.history[1].event_fingerprint == sm2.history[1].event_fingerprint


def test_35_evidence_references_ordering_is_deterministic() -> None:
    ts = "2026-08-13T12:00:00Z"
    refs1 = ("b.py:10", "a.py:5")
    refs2 = ("a.py:5", "b.py:10")

    fp1 = LifecycleEvent.compute_fingerprint("e1", "F1", RemediationLifecycleState.DETECTED, RemediationLifecycleState.EVIDENCE_VERIFIED, "actor", ts, refs1)
    fp2 = LifecycleEvent.compute_fingerprint("e1", "F1", RemediationLifecycleState.DETECTED, RemediationLifecycleState.EVIDENCE_VERIFIED, "actor", ts, refs2)

    assert fp1 == fp2


# =============================================================================
# 6. ADVERSARIAL SECURITY BYPASS TESTS (36 - 40)
# =============================================================================


def test_36_adversarial_mismatched_finding_id_in_evidence_rejected() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLIED_UNVERIFIED)
    sm.transition(RemediationLifecycleState.SECURITY_RESCAN)

    mismatched_ev = _get_valid_evidence("F-FORGED-999")
    with pytest.raises(InvalidStateTransitionError, match="does not match state machine finding_id"):
        sm.transition_verified_fixed(mismatched_ev)


def test_37_adversarial_ai_model_authority_in_evidence_rejected() -> None:
    with pytest.raises(ValueError, match="cannot establish VERIFIED_FIXED state"):
        VerificationEvidenceContract(
            finding_id="F-101",
            proposal_fingerprint="prop_fp",
            source_snapshot_hash="src",
            post_apply_snapshot_hash="post",
            verification_run_id="v_run",
            verification_fingerprint="v_fp",
            authority=VerificationAuthority.AI_MODEL,
        )


def test_38_adversarial_general_transition_to_verified_fixed_rejected() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLIED_UNVERIFIED)
    sm.transition(RemediationLifecycleState.SECURITY_RESCAN)

    # Calling generic transition() to VERIFIED_FIXED must fail
    with pytest.raises(InvalidStateTransitionError, match="requires explicit transition_verified_fixed"):
        sm.transition(RemediationLifecycleState.VERIFIED_FIXED)


def test_39_still_vulnerable_transitions_to_rolled_back() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLIED_UNVERIFIED)
    sm.transition(RemediationLifecycleState.SECURITY_RESCAN)

    sm.transition(RemediationLifecycleState.STILL_VULNERABLE)
    assert sm.current_state == RemediationLifecycleState.STILL_VULNERABLE

    sm.transition(RemediationLifecycleState.ROLLED_BACK)
    assert sm.current_state == RemediationLifecycleState.ROLLED_BACK


def test_40_unknown_rescan_verdict_transitions_to_rolled_back() -> None:
    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLIED_UNVERIFIED)
    sm.transition(RemediationLifecycleState.SECURITY_RESCAN)

    sm.transition(RemediationLifecycleState.UNKNOWN)
    assert sm.current_state == RemediationLifecycleState.UNKNOWN

    sm.transition(RemediationLifecycleState.ROLLED_BACK)
    assert sm.current_state == RemediationLifecycleState.ROLLED_BACK


# =============================================================================
# 7. E13-4 VERIFICATION RESULT BOUNDARY TESTS (41 - 43)
# =============================================================================

from karsasec.ai.remediation.verification import VerificationContract, VerificationResult, VerificationStatus


def test_41_from_verification_result_factory_creates_valid_contract() -> None:
    contract = VerificationContract(
        finding_id="F-101",
        rule_id="RULE-01",
        cwe_id="CWE-89",
        sink_category="SQL_INJECTION",
        file_path="app.py",
        line_number=10,
        affected_symbol="query",
        evidence_fingerprint="ev_fp_101",
    )
    vr = VerificationResult(
        verification_id="ver_run_555",
        finding_id="F-101",
        pre_apply_verdict_status="VULNERABLE",
        post_apply_verdict_status="SAFE",
        status=VerificationStatus.VERIFIED_FIXED,
        contract=contract,
        matching_findings_count=0,
        details="Eliminated",
    )

    ev_contract = VerificationEvidenceContract.from_verification_result(
        verification_result=vr,
        proposal_fingerprint="prop_fp",
        source_snapshot_hash="src",
        post_apply_snapshot_hash="post",
        verification_fingerprint="v_fp",
    )

    assert ev_contract.finding_id == "F-101"
    assert ev_contract.verification_run_id == "ver_run_555"
    assert ev_contract.verification_result is vr

    sm = LifecycleStateMachine("F-101")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLIED_UNVERIFIED)
    sm.transition(RemediationLifecycleState.SECURITY_RESCAN)

    sm.transition_verified_fixed(ev_contract)
    assert sm.current_state == RemediationLifecycleState.VERIFIED_FIXED


def test_42_verification_result_with_still_vulnerable_status_rejected() -> None:
    contract = VerificationContract(
        finding_id="F-101",
        rule_id="RULE-01",
        cwe_id="CWE-89",
        sink_category="SQL_INJECTION",
        file_path="app.py",
        line_number=10,
        affected_symbol="query",
        evidence_fingerprint="ev_fp_101",
    )
    vr_still_vulnerable = VerificationResult(
        verification_id="ver_run_555",
        finding_id="F-101",
        pre_apply_verdict_status="VULNERABLE",
        post_apply_verdict_status="VULNERABLE",
        status=VerificationStatus.STILL_VULNERABLE,
        contract=contract,
        matching_findings_count=1,
        details="Vulnerability persists",
    )

    with pytest.raises(ValueError, match="status must be VERIFIED_FIXED"):
        VerificationEvidenceContract.from_verification_result(
            verification_result=vr_still_vulnerable,
            proposal_fingerprint="prop_fp",
            source_snapshot_hash="src",
            post_apply_snapshot_hash="post",
            verification_fingerprint="v_fp",
        )


def test_43_verification_result_with_mismatched_finding_id_rejected() -> None:
    contract = VerificationContract(
        finding_id="F-OTHER",
        rule_id="RULE-01",
        cwe_id="CWE-89",
        sink_category="SQL_INJECTION",
        file_path="app.py",
        line_number=10,
        affected_symbol="query",
        evidence_fingerprint="ev_fp_101",
    )
    vr_mismatched = VerificationResult(
        verification_id="ver_run_555",
        finding_id="F-OTHER",
        pre_apply_verdict_status="VULNERABLE",
        post_apply_verdict_status="SAFE",
        status=VerificationStatus.VERIFIED_FIXED,
        contract=contract,
        matching_findings_count=0,
        details="Eliminated",
    )

    with pytest.raises(ValueError, match="does not match contract finding_id"):
        VerificationEvidenceContract(
            finding_id="F-101",
            proposal_fingerprint="prop_fp",
            source_snapshot_hash="src",
            post_apply_snapshot_hash="post",
            verification_run_id="ver_run_555",
            verification_fingerprint="v_fp",
            authority=VerificationAuthority.DETERMINISTIC_SAST,
            verification_result=vr_mismatched,
        )

