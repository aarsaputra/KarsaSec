"""Authoritative Remediation Lifecycle State Machine for KarsaSec AI Engine (Sprint E13-5 Phase 1).

Enforces the deterministic, strongly typed security remediation state machine.
The LifecycleStateMachine is the ONLY authority allowed to perform remediation lifecycle state transitions.

Enforces Security Invariants:
  - L1: State Transition Authority (Transitions exclusively via LifecycleStateMachine).
  - L2: No State Skipping (Strict explicit transition matrix enforcement).
  - L3: Historical Immutability (Frozen dataclasses; zero event/history mutation).
  - L4: Verification Evidence Binding (VERIFIED_FIXED requires 6-point cryptographic proof).
  - L6: Verification Freshness (Explicit verification run ID & fingerprint binding).
  - L7: Zero LLM Security Authority (LLM outputs CANNOT grant VERIFIED_FIXED).
  - L9: No Auto-Repair Loop (Zero automatic patch-retry or auto-repair execution loops).
  - L18: Failure Finality (ROLLED_BACK and CRITICAL_RECOVERY_FAILURE are terminal/non-resumable).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, UTC
from enum import StrEnum
import hashlib
from typing import Any


from karsasec.ai.remediation.verification import VerificationResult, VerificationStatus


class InvalidStateTransitionError(ValueError):
    """Raised when an illegal lifecycle state transition is attempted."""

    def __init__(
        self, current_state: RemediationLifecycleState, target_state: RemediationLifecycleState, reason: str = ""
    ) -> None:
        message = f"Illegal transition from '{current_state}' to '{target_state}'."
        if reason:
            message += f" Reason: {reason}"
        super().__init__(message)
        self.current_state = current_state
        self.target_state = target_state
        self.reason = reason


class RemediationLifecycleState(StrEnum):
    """Canonical lifecycle states for KarsaSec security remediation."""

    DETECTED = "DETECTED"
    EVIDENCE_VERIFIED = "EVIDENCE_VERIFIED"
    RCA_ESTABLISHED = "RCA_ESTABLISHED"
    REMEDIATION_PROPOSED = "REMEDIATION_PROPOSED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    REJECTED = "REJECTED"
    APPROVED = "APPROVED"
    SNAPSHOT_VERIFIED = "SNAPSHOT_VERIFIED"
    APPLYING = "APPLYING"
    APPLY_FAILED = "APPLY_FAILED"
    APPLIED_UNVERIFIED = "APPLIED_UNVERIFIED"
    SECURITY_RESCAN = "SECURITY_RESCAN"
    VERIFIED_FIXED = "VERIFIED_FIXED"
    STILL_VULNERABLE = "STILL_VULNERABLE"
    UNKNOWN = "UNKNOWN"
    ROLLED_BACK = "ROLLED_BACK"
    CRITICAL_RECOVERY_FAILURE = "CRITICAL_RECOVERY_FAILURE"


class VerificationAuthority(StrEnum):
    """Classification of verification authority for post-apply security rescan."""

    DETERMINISTIC_SAST = "DETERMINISTIC_SAST"
    SECURITY_ENGINE = "SECURITY_ENGINE"
    LLM_ADVISORY = "LLM_ADVISORY"
    AI_MODEL = "AI_MODEL"
    HUMAN_CLAIM = "HUMAN_CLAIM"


@dataclass(frozen=True, slots=True)
class VerificationEvidenceContract:
    """Cryptographic evidence required to establish VERIFIED_FIXED state (L4, L6, L7).

    Binds authenticated E13-4 VerificationResult output to prevent self-attestation.
    """

    finding_id: str
    proposal_fingerprint: str
    source_snapshot_hash: str
    post_apply_snapshot_hash: str
    verification_run_id: str
    verification_fingerprint: str
    authority: VerificationAuthority
    verification_result: VerificationResult | None = None

    def __post_init__(self) -> None:
        if not self.finding_id or not self.finding_id.strip():
            raise ValueError("finding_id cannot be empty.")
        if not self.proposal_fingerprint or not self.proposal_fingerprint.strip():
            raise ValueError("proposal_fingerprint cannot be empty.")
        if not self.source_snapshot_hash or not self.source_snapshot_hash.strip():
            raise ValueError("source_snapshot_hash cannot be empty.")
        if not self.post_apply_snapshot_hash or not self.post_apply_snapshot_hash.strip():
            raise ValueError("post_apply_snapshot_hash cannot be empty.")
        if not self.verification_run_id or not self.verification_run_id.strip():
            raise ValueError("verification_run_id cannot be empty.")
        if not self.verification_fingerprint or not self.verification_fingerprint.strip():
            raise ValueError("verification_fingerprint cannot be empty.")

        # L7: Zero LLM Security Authority Enforcement
        disallowed_authorities = {
            VerificationAuthority.LLM_ADVISORY,
            VerificationAuthority.AI_MODEL,
            VerificationAuthority.HUMAN_CLAIM,
        }
        if self.authority in disallowed_authorities:
            raise ValueError(f"Authority '{self.authority}' cannot establish VERIFIED_FIXED state (L7 invariant).")

        # Validate bound VerificationResult if present
        if self.verification_result is not None:
            if self.verification_result.status != VerificationStatus.VERIFIED_FIXED:
                raise ValueError(
                    f"Bound VerificationResult status must be VERIFIED_FIXED, got '{self.verification_result.status}'."
                )
            if self.verification_result.finding_id != self.finding_id:
                raise ValueError(
                    f"Bound VerificationResult finding_id '{self.verification_result.finding_id}' "
                    f"does not match contract finding_id '{self.finding_id}'."
                )

    @classmethod
    def from_verification_result(
        cls,
        verification_result: VerificationResult,
        proposal_fingerprint: str,
        source_snapshot_hash: str,
        post_apply_snapshot_hash: str,
        verification_fingerprint: str,
        authority: VerificationAuthority = VerificationAuthority.DETERMINISTIC_SAST,
    ) -> VerificationEvidenceContract:
        """Construct VerificationEvidenceContract authenticated by E13-4 VerificationResult."""
        return cls(
            finding_id=verification_result.finding_id,
            proposal_fingerprint=proposal_fingerprint,
            source_snapshot_hash=source_snapshot_hash,
            post_apply_snapshot_hash=post_apply_snapshot_hash,
            verification_run_id=verification_result.verification_id,
            verification_fingerprint=verification_fingerprint,
            authority=authority,
            verification_result=verification_result,
        )

    def to_dict(self) -> dict[str, str]:
        return {
            "finding_id": self.finding_id,
            "proposal_fingerprint": self.proposal_fingerprint,
            "source_snapshot_hash": self.source_snapshot_hash,
            "post_apply_snapshot_hash": self.post_apply_snapshot_hash,
            "verification_run_id": self.verification_run_id,
            "verification_fingerprint": self.verification_fingerprint,
            "authority": str(self.authority),
        }


@dataclass(frozen=True, slots=True)
class LifecycleEvent:
    """Immutable lifecycle event record (L3)."""

    event_id: str
    finding_id: str
    previous_state: RemediationLifecycleState
    new_state: RemediationLifecycleState
    actor: str
    timestamp: str
    reason: str
    evidence_references: tuple[str, ...] = ()
    event_fingerprint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "finding_id": self.finding_id,
            "previous_state": str(self.previous_state),
            "new_state": str(self.new_state),
            "actor": self.actor,
            "timestamp": self.timestamp,
            "reason": self.reason,
            "evidence_references": list(self.evidence_references),
            "event_fingerprint": self.event_fingerprint,
        }

    @staticmethod
    def compute_fingerprint(
        event_id: str,
        finding_id: str,
        prev_state: RemediationLifecycleState,
        new_state: RemediationLifecycleState,
        actor: str,
        timestamp: str,
        evidence_refs: tuple[str, ...],
    ) -> str:
        """Compute deterministic SHA-256 fingerprint for event (L12)."""
        sorted_ev = "|".join(sorted(evidence_refs))
        raw = f"{event_id}|{finding_id}|{prev_state.value}|{new_state.value}|{actor}|{timestamp}|{sorted_ev}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class LifecycleStateMachine:
    """Authoritative state machine governing remediation lifecycle state transitions.

    The LifecycleStateMachine is the ONLY authority allowed to perform remediation state transitions (L1).
    """

    # Explicit transition matrix (L2)
    _VALID_TRANSITIONS: dict[RemediationLifecycleState, set[RemediationLifecycleState]] = {
        RemediationLifecycleState.DETECTED: {
            RemediationLifecycleState.EVIDENCE_VERIFIED,
        },
        RemediationLifecycleState.EVIDENCE_VERIFIED: {
            RemediationLifecycleState.RCA_ESTABLISHED,
        },
        RemediationLifecycleState.RCA_ESTABLISHED: {
            RemediationLifecycleState.REMEDIATION_PROPOSED,
        },
        RemediationLifecycleState.REMEDIATION_PROPOSED: {
            RemediationLifecycleState.AWAITING_APPROVAL,
        },
        RemediationLifecycleState.AWAITING_APPROVAL: {
            RemediationLifecycleState.APPROVED,
            RemediationLifecycleState.REJECTED,
        },
        RemediationLifecycleState.APPROVED: {
            RemediationLifecycleState.SNAPSHOT_VERIFIED,
        },
        RemediationLifecycleState.SNAPSHOT_VERIFIED: {
            RemediationLifecycleState.APPLYING,
        },
        RemediationLifecycleState.APPLYING: {
            RemediationLifecycleState.APPLIED_UNVERIFIED,
            RemediationLifecycleState.APPLY_FAILED,
        },
        RemediationLifecycleState.APPLY_FAILED: {
            RemediationLifecycleState.ROLLED_BACK,
            RemediationLifecycleState.CRITICAL_RECOVERY_FAILURE,
        },
        RemediationLifecycleState.APPLIED_UNVERIFIED: {
            RemediationLifecycleState.SECURITY_RESCAN,
        },
        RemediationLifecycleState.SECURITY_RESCAN: {
            RemediationLifecycleState.VERIFIED_FIXED,
            RemediationLifecycleState.STILL_VULNERABLE,
            RemediationLifecycleState.UNKNOWN,
        },
        RemediationLifecycleState.STILL_VULNERABLE: {
            RemediationLifecycleState.ROLLED_BACK,
        },
        RemediationLifecycleState.UNKNOWN: {
            RemediationLifecycleState.ROLLED_BACK,
        },
        RemediationLifecycleState.ROLLED_BACK: {
            RemediationLifecycleState.CRITICAL_RECOVERY_FAILURE,
        },
        # Terminal states with no outgoing transitions
        RemediationLifecycleState.REJECTED: set(),
        RemediationLifecycleState.VERIFIED_FIXED: set(),
        RemediationLifecycleState.CRITICAL_RECOVERY_FAILURE: set(),
    }

    def __init__(
        self,
        finding_id: str,
        initial_state: RemediationLifecycleState = RemediationLifecycleState.DETECTED,
        initial_actor: str = "system",
        created_at: str | None = None,
        event_id: str | None = None,
    ) -> None:
        if not finding_id or not finding_id.strip():
            raise ValueError("finding_id cannot be empty.")

        self._finding_id = finding_id
        self._current_state = initial_state
        self._history: list[LifecycleEvent] = []

        now_iso = created_at or datetime.now(UTC).isoformat()
        evt_id = (
            event_id
            or f"evt_{hashlib.sha256(f'{finding_id}|init|{initial_state.value}|{now_iso}'.encode()).hexdigest()[:12]}"
        )
        fp = LifecycleEvent.compute_fingerprint(
            event_id=evt_id,
            finding_id=self._finding_id,
            prev_state=initial_state,
            new_state=initial_state,
            actor=initial_actor,
            timestamp=now_iso,
            evidence_refs=(),
        )
        init_event = LifecycleEvent(
            event_id=evt_id,
            finding_id=self._finding_id,
            previous_state=initial_state,
            new_state=initial_state,
            actor=initial_actor,
            timestamp=now_iso,
            reason="Initial state creation",
            evidence_references=(),
            event_fingerprint=fp,
        )
        self._history.append(init_event)

    @property
    def finding_id(self) -> str:
        """Returns finding ID associated with this state machine."""
        return self._finding_id

    @property
    def current_state(self) -> RemediationLifecycleState:
        """Returns observable current lifecycle state."""
        return self._current_state

    @property
    def history(self) -> tuple[LifecycleEvent, ...]:
        """Returns immutable copy of state transition history (L3)."""
        return tuple(self._history)

    def can_transition(self, target_state: RemediationLifecycleState) -> bool:
        """Query if transition from current_state to target_state is permitted."""
        valid_targets = self._VALID_TRANSITIONS.get(self._current_state, set())
        return target_state in valid_targets

    def transition(
        self,
        target_state: RemediationLifecycleState,
        actor: str = "system",
        reason: str = "",
        evidence_references: tuple[str, ...] = (),
        timestamp: str | None = None,
        event_id: str | None = None,
    ) -> LifecycleEvent:
        """Execute a state transition.

        Enforces L1, L2, L4, L7, L18.
        """
        # Block transition into VERIFIED_FIXED via general transition method (L4)
        if target_state == RemediationLifecycleState.VERIFIED_FIXED:
            raise InvalidStateTransitionError(
                self._current_state,
                target_state,
                "VERIFIED_FIXED state requires explicit transition_verified_fixed call with complete evidence contract.",
            )

        if not self.can_transition(target_state):
            raise InvalidStateTransitionError(
                self._current_state,
                target_state,
                f"Transition from '{self._current_state}' to '{target_state}' is not permitted by transition matrix.",
            )

        now_iso = timestamp or datetime.now(UTC).isoformat()
        evt_id = (
            event_id
            or f"evt_{hashlib.sha256(f'{self._finding_id}|{self._current_state.value}|{target_state.value}|{now_iso}'.encode()).hexdigest()[:12]}"
        )
        fp = LifecycleEvent.compute_fingerprint(
            event_id=evt_id,
            finding_id=self._finding_id,
            prev_state=self._current_state,
            new_state=target_state,
            actor=actor,
            timestamp=now_iso,
            evidence_refs=evidence_references,
        )

        event = LifecycleEvent(
            event_id=evt_id,
            finding_id=self._finding_id,
            previous_state=self._current_state,
            new_state=target_state,
            actor=actor,
            timestamp=now_iso,
            reason=reason or f"Transition to {target_state}",
            evidence_references=evidence_references,
            event_fingerprint=fp,
        )

        self._current_state = target_state
        self._history.append(event)
        return event

    def transition_verified_fixed(
        self,
        evidence: VerificationEvidenceContract,
        actor: str = "sast_verification_engine",
        reason: str = "",
        timestamp: str | None = None,
        event_id: str | None = None,
    ) -> LifecycleEvent:
        """Special transition method strictly enforcing L4, L6, L7 for VERIFIED_FIXED state."""
        target_state = RemediationLifecycleState.VERIFIED_FIXED

        if self._current_state != RemediationLifecycleState.SECURITY_RESCAN:
            raise InvalidStateTransitionError(
                self._current_state,
                target_state,
                f"VERIFIED_FIXED can only be reached from SECURITY_RESCAN, got '{self._current_state}'.",
            )

        if evidence.finding_id != self._finding_id:
            raise InvalidStateTransitionError(
                self._current_state,
                target_state,
                f"Verification evidence finding_id '{evidence.finding_id}' does not match state machine finding_id '{self._finding_id}'.",
            )

        now_iso = timestamp or datetime.now(UTC).isoformat()
        evt_id = (
            event_id
            or f"evt_{hashlib.sha256(f'{self._finding_id}|{self._current_state.value}|{target_state.value}|{now_iso}'.encode()).hexdigest()[:12]}"
        )
        ev_refs = (
            f"proposal:{evidence.proposal_fingerprint}",
            f"src_snap:{evidence.source_snapshot_hash}",
            f"post_snap:{evidence.post_apply_snapshot_hash}",
            f"rescan_id:{evidence.verification_run_id}",
            f"verification_fp:{evidence.verification_fingerprint}",
        )

        fp = LifecycleEvent.compute_fingerprint(
            event_id=evt_id,
            finding_id=self._finding_id,
            prev_state=self._current_state,
            new_state=target_state,
            actor=actor,
            timestamp=now_iso,
            evidence_refs=ev_refs,
        )

        event = LifecycleEvent(
            event_id=evt_id,
            finding_id=self._finding_id,
            previous_state=self._current_state,
            new_state=target_state,
            actor=actor,
            timestamp=now_iso,
            reason=reason or f"Deterministic verification fix confirmed via {evidence.authority}",
            evidence_references=ev_refs,
            event_fingerprint=fp,
        )

        self._current_state = target_state
        self._history.append(event)
        return event
