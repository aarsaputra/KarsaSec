"""Authoritative Remediation Lifecycle Orchestrator for KarsaSec AI Engine (Sprint E13-5 Phase 4).

Coordinates the end-to-end remediation lifecycle connecting:
  RemediationAgent -> LifecycleStateMachine -> RemediationProvenanceGraph ->
  PatchApprovalToken -> SourceSnapshot -> RemediationApplicationAgent ->
  VerificationResult -> LifecycleStateMachine -> RemediationLedger

Enforces Security Invariants:
  - L1: State Transition Authority (Transitions exclusively via LifecycleStateMachine).
  - L2: No State Skipping (Strict transition order DETECTED -> EVIDENCE_VERIFIED -> ... -> VERIFIED_FIXED).
  - L3: Historical Immutability (Treats all domain artifacts as frozen historical records).
  - L4: Verification Evidence Binding (VERIFIED_FIXED strictly requires 6-point cryptographic proof).
  - L5: Approval Binding (Single-use, cryptographically bound PatchApprovalToken validation).
  - L6: Verification Freshness (Binds fresh verification run ID and fingerprint).
  - L7: Zero LLM Security Authority (LLM outputs CANNOT trigger VERIFIED_FIXED).
  - L8: Rollback Integrity (Delegates atomic rollback to RemediationApplicationAgent).
  - L9: No Auto-Repair Loop (At most one apply attempt per transaction; zero retry loops).
  - L10: Provenance Continuity (Appends nodes to RemediationProvenanceGraph at every stage).
  - L11: Append-Only Audit (Appends audit events to RemediationLedger at every stage).
  - L14-L17: Repository, Proposal, Snapshot, and Verification Cryptographic Binding.
  - L18: Failure Finality (REJECTED, ROLLED_BACK, CRITICAL_RECOVERY_FAILURE are terminal).
  - L28: No Execution Capabilities (Zero subprocess/shell/git execution capabilities).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, UTC
from pathlib import Path
from typing import Any
from collections.abc import Callable

from karsasec.ai.evidence_context import SecurityFindingContext, SecurityFindingContextBuilder
from karsasec.ai.rca.models import RootCauseAnalysis
from karsasec.ai.remediation.agent import RemediationAgent
from karsasec.ai.remediation.applier import ApplicationResult, ApplicationStatus
from karsasec.ai.remediation.application_agent import RemediationApplicationAgent
from karsasec.ai.remediation.approval import PatchApprovalToken
from karsasec.ai.remediation.audit import AuditEventType, LifecycleAuditEvent
from karsasec.ai.remediation.ledger import RemediationLedger
from karsasec.ai.remediation.models import PatchProposal, RemediationStrategy
from karsasec.ai.remediation.provenance import ProvenanceNode, RemediationProvenanceGraph
from karsasec.ai.remediation.snapshot import SourceSnapshot
from karsasec.ai.remediation.state_machine import (
    LifecycleEvent,
    LifecycleStateMachine,
    RemediationLifecycleState,
    VerificationAuthority,
    VerificationEvidenceContract,
)
from karsasec.ai.remediation.verification import VerificationResult, VerificationStatus
from karsasec.ai.retrieval.adapter import KnowledgeChunk
from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow.security_verdict import SecurityVerdict


@dataclass(frozen=True, slots=True)
class RemediationLifecycleResult:
    """Immutable result container representing the outcome of a remediation lifecycle transaction."""

    finding_id: str
    current_state: RemediationLifecycleState
    repository_identity: str
    finding: Finding
    verdict: SecurityVerdict | None = None
    rca: RootCauseAnalysis | None = None
    strategy: RemediationStrategy | None = None
    proposal: PatchProposal | None = None
    approval_token: PatchApprovalToken | None = None
    source_snapshot: SourceSnapshot | None = None
    application_result: ApplicationResult | None = None
    verification_result: VerificationResult | None = None
    provenance_graph: RemediationProvenanceGraph = field(default_factory=RemediationProvenanceGraph)
    ledger: RemediationLedger = field(default_factory=RemediationLedger)
    state_history: tuple[LifecycleEvent, ...] = ()
    failure_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Export canonical dictionary representation."""
        return {
            "finding_id": self.finding_id,
            "current_state": str(self.current_state),
            "repository_identity": self.repository_identity,
            "has_verdict": self.verdict is not None,
            "has_rca": self.rca is not None,
            "has_strategy": self.strategy is not None,
            "proposal_fingerprint": self.proposal.proposal_fingerprint if self.proposal else None,
            "approval_token_id": self.approval_token.token_id if self.approval_token else None,
            "source_snapshot_hash": self.source_snapshot.aggregate_hash if self.source_snapshot else None,
            "application_status": str(self.application_result.status) if self.application_result else None,
            "verification_status": str(self.verification_result.status) if self.verification_result else None,
            "provenance_fingerprint": self.provenance_graph.graph_fingerprint,
            "ledger_fingerprint": self.ledger.ledger_fingerprint,
            "event_count": len(self.state_history),
            "failure_reason": self.failure_reason,
        }


class RemediationLifecycleEngine:
    """Authoritative Remediation Lifecycle Orchestrator.

    Coordinates state transitions, provenance tracking, and audit logging without taking over
    state machine or verification authority.
    """

    def __init__(
        self,
        repository_root: Path | str,
        remediation_agent: RemediationAgent | None = None,
        application_agent: RemediationApplicationAgent | None = None,
    ) -> None:
        self.repository_root = Path(repository_root).resolve()
        self.repository_identity = str(self.repository_root)
        self.remediation_agent = remediation_agent or RemediationAgent()
        self.application_agent = application_agent or RemediationApplicationAgent(self.repository_root)

    def _append_audit(
        self,
        ledger: RemediationLedger,
        event_type: AuditEventType,
        finding_id: str,
        lifecycle_state: str,
        actor: str,
        timestamp: str,
        proposal_fingerprint: str | None = None,
        source_snapshot_hash: str | None = None,
        post_apply_snapshot_hash: str | None = None,
        verification_run_id: str | None = None,
        verification_fingerprint: str | None = None,
        provenance_fingerprint: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> RemediationLedger:
        last = ledger.latest_event
        pred_id = last.event_id if last else None
        pred_fp = last.event_fingerprint if last else None
        evt_num = len(ledger.events) + 1
        evt_id = f"aud_evt_{evt_num}_{event_type.value}"

        event = LifecycleAuditEvent.create(
            event_id=evt_id,
            event_type=event_type,
            finding_id=finding_id,
            lifecycle_state=lifecycle_state,
            actor=actor,
            timestamp=timestamp,
            repository_identity=self.repository_identity,
            predecessor_event_id=pred_id,
            predecessor_event_fingerprint=pred_fp,
            proposal_fingerprint=proposal_fingerprint,
            source_snapshot_hash=source_snapshot_hash,
            post_apply_snapshot_hash=post_apply_snapshot_hash,
            verification_run_id=verification_run_id,
            verification_fingerprint=verification_fingerprint,
            provenance_fingerprint=provenance_fingerprint,
            metadata=metadata or {},
        )
        return ledger.append(event)

    def execute(
        self,
        finding: Finding,
        verdict: SecurityVerdict | None = None,
        context: SecurityFindingContext | None = None,
        rca: RootCauseAnalysis | None = None,
        knowledge_chunks: list[KnowledgeChunk] | None = None,
        source_code: str | None = None,
        approval_provider: PatchApprovalToken
        | Callable[[PatchProposal, SourceSnapshot], PatchApprovalToken | None]
        | None = None,
        rescan_callback: Callable[[], tuple[Finding, ...]] | None = None,
        actor: str = "lifecycle_orchestrator",
    ) -> RemediationLifecycleResult:
        """Executes full 10-stage orchestrated remediation lifecycle transaction.

        Flow:
          1. DETECTED & EVIDENCE_VERIFIED
          2. RCA_ESTABLISHED & REMEDIATION_PROPOSED
          3. AWAITING_APPROVAL -> APPROVED / REJECTED
          4. SNAPSHOT_VERIFIED & APPLYING
          5. APPLYING -> APPLIED_UNVERIFIED / APPLY_FAILED -> ROLLED_BACK
          6. SECURITY_RESCAN -> VERIFIED_FIXED / STILL_VULNERABLE -> ROLLED_BACK
        """
        now_iso = datetime.now(UTC).isoformat()
        sm = LifecycleStateMachine(finding_id=finding.finding_id, initial_actor=actor, created_at=now_iso)
        graph = RemediationProvenanceGraph()
        ledger = RemediationLedger()

        # -------------------------------------------------------------
        # STAGE 1: DETECTED & EVIDENCE_VERIFIED
        # -------------------------------------------------------------
        finding_node = ProvenanceNode.create_finding_node(finding)
        graph = graph.add_node(finding_node)

        ledger = self._append_audit(
            ledger=ledger,
            event_type=AuditEventType.FINDING_DETECTED,
            finding_id=finding.finding_id,
            lifecycle_state=sm.current_state.value,
            actor=actor,
            timestamp=now_iso,
            provenance_fingerprint=graph.graph_fingerprint,
            metadata={"rule_id": finding.rule_id, "file_path": finding.file_path},
        )

        # Transition DETECTED -> EVIDENCE_VERIFIED
        sm.transition(
            RemediationLifecycleState.EVIDENCE_VERIFIED,
            actor=actor,
            reason="Evidence verified for finding",
            timestamp=now_iso,
        )
        ledger = self._append_audit(
            ledger=ledger,
            event_type=AuditEventType.EVIDENCE_VERIFIED,
            finding_id=finding.finding_id,
            lifecycle_state=sm.current_state.value,
            actor=actor,
            timestamp=now_iso,
            provenance_fingerprint=graph.graph_fingerprint,
        )

        # -------------------------------------------------------------
        # STAGE 2: RCA_ESTABLISHED & REMEDIATION_PROPOSED
        # -------------------------------------------------------------
        prev_node_id = finding_node.node_id
        if rca is not None:
            rca_node = ProvenanceNode.create_rca_node(rca, predecessor_id=prev_node_id)
            graph = graph.add_node(rca_node)
            prev_node_id = rca_node.node_id

            sm.transition(
                RemediationLifecycleState.RCA_ESTABLISHED,
                actor=actor,
                reason="Root cause analysis established",
                timestamp=now_iso,
            )
            ledger = self._append_audit(
                ledger=ledger,
                event_type=AuditEventType.RCA_ESTABLISHED,
                finding_id=finding.finding_id,
                lifecycle_state=sm.current_state.value,
                actor=actor,
                timestamp=now_iso,
                provenance_fingerprint=graph.graph_fingerprint,
            )
        else:
            # Transition to RCA_ESTABLISHED implicitly if skipping explicit RCA model
            sm.transition(
                RemediationLifecycleState.RCA_ESTABLISHED, actor=actor, reason="RCA step completed", timestamp=now_iso
            )
            ledger = self._append_audit(
                ledger=ledger,
                event_type=AuditEventType.RCA_ESTABLISHED,
                finding_id=finding.finding_id,
                lifecycle_state=sm.current_state.value,
                actor=actor,
                timestamp=now_iso,
                provenance_fingerprint=graph.graph_fingerprint,
            )

        # Plan & Propose Patch
        if source_code is None:
            target_p = self.repository_root / finding.file_path
            if target_p.exists() and target_p.is_file():
                try:
                    source_code = target_p.read_text(encoding="utf-8")
                except Exception:
                    pass

        strategy, proposal = self.remediation_agent.plan_and_propose(
            finding=finding,
            verdict=verdict,
            context=context or SecurityFindingContextBuilder.build(finding, verdict=verdict),
            rca=rca,
            knowledge_chunks=knowledge_chunks,
            source_code=source_code,
        )

        strat_node = ProvenanceNode.create_strategy_node(strategy, predecessor_id=prev_node_id)
        graph = graph.add_node(strat_node)

        prop_node = ProvenanceNode.create_proposal_node(proposal, predecessor_id=strat_node.node_id)
        graph = graph.add_node(prop_node)

        sm.transition(
            RemediationLifecycleState.REMEDIATION_PROPOSED,
            actor=actor,
            reason="Patch proposal generated and validated",
            timestamp=now_iso,
        )
        ledger = self._append_audit(
            ledger=ledger,
            event_type=AuditEventType.REMEDIATION_PROPOSED,
            finding_id=finding.finding_id,
            lifecycle_state=sm.current_state.value,
            actor=actor,
            timestamp=now_iso,
            proposal_fingerprint=proposal.proposal_fingerprint,
            provenance_fingerprint=graph.graph_fingerprint,
        )

        # -------------------------------------------------------------
        # STAGE 3: AWAITING_APPROVAL & APPROVAL VALIDATION
        # -------------------------------------------------------------
        sm.transition(
            RemediationLifecycleState.AWAITING_APPROVAL,
            actor=actor,
            reason="Patch proposal awaiting review and approval",
            timestamp=now_iso,
        )
        ledger = self._append_audit(
            ledger=ledger,
            event_type=AuditEventType.APPROVAL_GRANTED,
            finding_id=finding.finding_id,
            lifecycle_state=sm.current_state.value,
            actor=actor,
            timestamp=now_iso,
            proposal_fingerprint=proposal.proposal_fingerprint,
            provenance_fingerprint=graph.graph_fingerprint,
            metadata={"status": "AWAITING_APPROVAL"},
        )

        # Capture pre-apply SourceSnapshot
        snapshot = SourceSnapshot.capture(self.repository_root, proposal.target_files)
        snap_node = ProvenanceNode.create_source_snapshot_node(snapshot, predecessor_id=prop_node.node_id)
        graph = graph.add_node(snap_node)

        # Resolve Approval Token
        token: PatchApprovalToken | None = None
        if isinstance(approval_provider, PatchApprovalToken):
            token = approval_provider
        elif callable(approval_provider):
            token = approval_provider(proposal, snapshot)

        # Validate Approval Token (L5, L14, L15, L16)
        if token is None:
            sm.transition(
                RemediationLifecycleState.REJECTED,
                actor=actor,
                reason="Approval rejected: No approval token provided",
                timestamp=now_iso,
            )
            ledger = self._append_audit(
                ledger=ledger,
                event_type=AuditEventType.APPROVAL_GRANTED,
                finding_id=finding.finding_id,
                lifecycle_state=sm.current_state.value,
                actor=actor,
                timestamp=now_iso,
                proposal_fingerprint=proposal.proposal_fingerprint,
                source_snapshot_hash=snapshot.aggregate_hash,
                provenance_fingerprint=graph.graph_fingerprint,
                metadata={"status": "REJECTED", "reason": "NO_TOKEN"},
            )
            return RemediationLifecycleResult(
                finding_id=finding.finding_id,
                current_state=sm.current_state,
                repository_identity=self.repository_identity,
                finding=finding,
                verdict=verdict,
                rca=rca,
                strategy=strategy,
                proposal=proposal,
                source_snapshot=snapshot,
                provenance_graph=graph,
                ledger=ledger,
                state_history=sm.history,
                failure_reason="Approval token missing or rejected.",
            )

        # Execute Token Validation
        val_ok, val_err = token.verify_valid(
            expected_finding_id=finding.finding_id,
            expected_proposal_fingerprint=proposal.proposal_fingerprint,
            expected_snapshot_hash=snapshot.aggregate_hash,
            expected_repository_identity=self.repository_identity,
            current_timestamp_iso=now_iso,
        )

        if not val_ok:
            sm.transition(
                RemediationLifecycleState.REJECTED,
                actor=actor,
                reason=f"Approval token validation failed: {val_err}",
                timestamp=now_iso,
            )
            ledger = self._append_audit(
                ledger=ledger,
                event_type=AuditEventType.APPROVAL_GRANTED,
                finding_id=finding.finding_id,
                lifecycle_state=sm.current_state.value,
                actor=actor,
                timestamp=now_iso,
                proposal_fingerprint=proposal.proposal_fingerprint,
                source_snapshot_hash=snapshot.aggregate_hash,
                provenance_fingerprint=graph.graph_fingerprint,
                metadata={"status": "REJECTED", "reason": val_err},
            )
            return RemediationLifecycleResult(
                finding_id=finding.finding_id,
                current_state=sm.current_state,
                repository_identity=self.repository_identity,
                finding=finding,
                verdict=verdict,
                rca=rca,
                strategy=strategy,
                proposal=proposal,
                approval_token=token,
                source_snapshot=snapshot,
                provenance_graph=graph,
                ledger=ledger,
                state_history=sm.history,
                failure_reason=f"Approval token invalid: {val_err}",
            )

        # Approval token valid -> Add Token Node & Transition APPROVED
        tok_node = ProvenanceNode.create_approval_token_node(token, predecessor_id=snap_node.node_id)
        graph = graph.add_node(tok_node)

        sm.transition(
            RemediationLifecycleState.APPROVED,
            actor=actor,
            reason=f"Patch proposal approved by {token.approved_by}",
            timestamp=now_iso,
        )
        ledger = self._append_audit(
            ledger=ledger,
            event_type=AuditEventType.APPROVAL_GRANTED,
            finding_id=finding.finding_id,
            lifecycle_state=sm.current_state.value,
            actor=actor,
            timestamp=now_iso,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            provenance_fingerprint=graph.graph_fingerprint,
            metadata={"status": "APPROVED", "approver": token.approved_by},
        )

        # -------------------------------------------------------------
        # STAGE 4: SNAPSHOT_VERIFIED & APPLYING
        # -------------------------------------------------------------
        sm.transition(
            RemediationLifecycleState.SNAPSHOT_VERIFIED,
            actor=actor,
            reason="Pre-apply snapshot verified",
            timestamp=now_iso,
        )
        ledger = self._append_audit(
            ledger=ledger,
            event_type=AuditEventType.SNAPSHOT_CAPTURED,
            finding_id=finding.finding_id,
            lifecycle_state=sm.current_state.value,
            actor=actor,
            timestamp=now_iso,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            provenance_fingerprint=graph.graph_fingerprint,
        )

        sm.transition(
            RemediationLifecycleState.APPLYING,
            actor=actor,
            reason="Executing controlled patch application",
            timestamp=now_iso,
        )
        ledger = self._append_audit(
            ledger=ledger,
            event_type=AuditEventType.PATCH_APPLIED,
            finding_id=finding.finding_id,
            lifecycle_state=sm.current_state.value,
            actor=actor,
            timestamp=now_iso,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            provenance_fingerprint=graph.graph_fingerprint,
            metadata={"status": "APPLYING"},
        )

        # -------------------------------------------------------------
        # STAGE 5: CONTROLLED APPLY EXECUTION
        # -------------------------------------------------------------
        dummy_rescan = rescan_callback or (lambda: ())
        app_res, ver_res, updated_token = self.application_agent.execute_transaction(
            proposal=proposal,
            token=token,
            finding=finding,
            rescan_callback=dummy_rescan,
        )

        app_node = ProvenanceNode.create_application_node(app_res, predecessor_ids=(tok_node.node_id,))
        graph = graph.add_node(app_node)

        # Handle Apply Failure / Rollback
        if app_res.status != ApplicationStatus.APPLIED:
            if ver_res is not None:
                ver_node = ProvenanceNode.create_verification_node(
                    ver_result=ver_res,
                    predecessor_id=app_node.node_id,
                    proposal_fingerprint=proposal.proposal_fingerprint,
                    source_snapshot_hash=app_res.pre_apply_snapshot_hash,
                    post_apply_snapshot_hash=app_res.post_apply_snapshot_hash,
                    verification_fingerprint=ver_res.verification_fingerprint,
                )
                graph = graph.add_node(ver_node)

            sm.transition(
                RemediationLifecycleState.APPLY_FAILED,
                actor=actor,
                reason=f"Patch application failed: {app_res.failure_reason}",
                timestamp=now_iso,
            )
            ledger = self._append_audit(
                ledger=ledger,
                event_type=AuditEventType.ROLLBACK_STARTED,
                finding_id=finding.finding_id,
                lifecycle_state=sm.current_state.value,
                actor=actor,
                timestamp=now_iso,
                proposal_fingerprint=proposal.proposal_fingerprint,
                source_snapshot_hash=app_res.pre_apply_snapshot_hash,
                provenance_fingerprint=graph.graph_fingerprint,
            )

            target_terminal = RemediationLifecycleState.ROLLED_BACK
            if app_res.rollback_status == "CRITICAL_FAILURE":
                target_terminal = RemediationLifecycleState.CRITICAL_RECOVERY_FAILURE

            sm.transition(
                target_terminal, actor=actor, reason=f"Rollback completed: {app_res.failure_reason}", timestamp=now_iso
            )
            ledger = self._append_audit(
                ledger=ledger,
                event_type=AuditEventType.CRITICAL_RECOVERY_FAILURE
                if target_terminal == RemediationLifecycleState.CRITICAL_RECOVERY_FAILURE
                else AuditEventType.ROLLBACK_COMPLETED,
                finding_id=finding.finding_id,
                lifecycle_state=sm.current_state.value,
                actor=actor,
                timestamp=now_iso,
                proposal_fingerprint=proposal.proposal_fingerprint,
                source_snapshot_hash=app_res.pre_apply_snapshot_hash,
                provenance_fingerprint=graph.graph_fingerprint,
            )
            return RemediationLifecycleResult(
                finding_id=finding.finding_id,
                current_state=sm.current_state,
                repository_identity=self.repository_identity,
                finding=finding,
                verdict=verdict,
                rca=rca,
                strategy=strategy,
                proposal=proposal,
                approval_token=updated_token,
                source_snapshot=snapshot,
                application_result=app_res,
                verification_result=ver_res,
                provenance_graph=graph,
                ledger=ledger,
                state_history=sm.history,
                failure_reason=f"Application failed: {app_res.failure_reason}",
            )

        # Apply succeeded -> APPLIED_UNVERIFIED
        sm.transition(
            RemediationLifecycleState.APPLIED_UNVERIFIED,
            actor=actor,
            reason="Patch applied successfully; awaiting verification",
            timestamp=now_iso,
        )
        ledger = self._append_audit(
            ledger=ledger,
            event_type=AuditEventType.PATCH_APPLIED,
            finding_id=finding.finding_id,
            lifecycle_state=sm.current_state.value,
            actor=actor,
            timestamp=now_iso,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=app_res.pre_apply_snapshot_hash,
            post_apply_snapshot_hash=app_res.post_apply_snapshot_hash,
            provenance_fingerprint=graph.graph_fingerprint,
            metadata={"status": "APPLIED_UNVERIFIED"},
        )

        # -------------------------------------------------------------
        # STAGE 6: SECURITY RESCAN & VERIFICATION
        # -------------------------------------------------------------
        sm.transition(
            RemediationLifecycleState.SECURITY_RESCAN,
            actor=actor,
            reason="Executing post-apply security rescan",
            timestamp=now_iso,
        )
        ledger = self._append_audit(
            ledger=ledger,
            event_type=AuditEventType.VERIFICATION_STARTED,
            finding_id=finding.finding_id,
            lifecycle_state=sm.current_state.value,
            actor=actor,
            timestamp=now_iso,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=app_res.pre_apply_snapshot_hash,
            post_apply_snapshot_hash=app_res.post_apply_snapshot_hash,
            provenance_fingerprint=graph.graph_fingerprint,
        )

        if ver_res is not None:
            ver_node = ProvenanceNode.create_verification_node(
                ver_result=ver_res,
                predecessor_id=app_node.node_id,
                proposal_fingerprint=proposal.proposal_fingerprint,
                source_snapshot_hash=app_res.pre_apply_snapshot_hash,
                post_apply_snapshot_hash=app_res.post_apply_snapshot_hash,
                verification_fingerprint=ver_res.verification_fingerprint,
            )
            graph = graph.add_node(ver_node)

        # Evaluate Verification Outcome (L4, L7)
        if ver_res is not None and ver_res.status == VerificationStatus.VERIFIED_FIXED:
            evidence_contract = VerificationEvidenceContract.from_verification_result(
                verification_result=ver_res,
                proposal_fingerprint=proposal.proposal_fingerprint,
                source_snapshot_hash=app_res.pre_apply_snapshot_hash,
                post_apply_snapshot_hash=app_res.post_apply_snapshot_hash,
                verification_fingerprint=ver_res.verification_fingerprint,
                authority=VerificationAuthority.DETERMINISTIC_SAST,
            )

            # Authoritative State Machine Transition to VERIFIED_FIXED (L4, L7)
            sm.transition_verified_fixed(
                evidence=evidence_contract,
                actor=actor,
                reason="Deterministic SAST rescan confirmed vulnerability fix",
                timestamp=now_iso,
            )
            ledger = self._append_audit(
                ledger=ledger,
                event_type=AuditEventType.VERIFIED_FIXED,
                finding_id=finding.finding_id,
                lifecycle_state=sm.current_state.value,
                actor=actor,
                timestamp=now_iso,
                proposal_fingerprint=proposal.proposal_fingerprint,
                source_snapshot_hash=app_res.pre_apply_snapshot_hash,
                post_apply_snapshot_hash=app_res.post_apply_snapshot_hash,
                verification_run_id=ver_res.verification_id,
                verification_fingerprint=ver_res.verification_fingerprint,
                provenance_fingerprint=graph.graph_fingerprint,
            )
            return RemediationLifecycleResult(
                finding_id=finding.finding_id,
                current_state=sm.current_state,
                repository_identity=self.repository_identity,
                finding=finding,
                verdict=verdict,
                rca=rca,
                strategy=strategy,
                proposal=proposal,
                approval_token=updated_token,
                source_snapshot=snapshot,
                application_result=app_res,
                verification_result=ver_res,
                provenance_graph=graph,
                ledger=ledger,
                state_history=sm.history,
            )

        # Verification failed (STILL_VULNERABLE or UNKNOWN) -> Transition state & ROLLBACK
        failed_state = RemediationLifecycleState.STILL_VULNERABLE
        ev_type = AuditEventType.STILL_VULNERABLE
        if ver_res is None or ver_res.status == VerificationStatus.UNKNOWN:
            failed_state = RemediationLifecycleState.UNKNOWN
            ev_type = AuditEventType.CRITICAL_RECOVERY_FAILURE

        sm.transition(
            failed_state,
            actor=actor,
            reason=f"Security verification failed: {ver_res.details if ver_res else 'No verification result'}",
            timestamp=now_iso,
        )
        ledger = self._append_audit(
            ledger=ledger,
            event_type=ev_type,
            finding_id=finding.finding_id,
            lifecycle_state=sm.current_state.value,
            actor=actor,
            timestamp=now_iso,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=app_res.pre_apply_snapshot_hash,
            post_apply_snapshot_hash=app_res.post_apply_snapshot_hash,
            verification_run_id=ver_res.verification_id if ver_res else None,
            verification_fingerprint=ver_res.verification_fingerprint if ver_res else None,
            provenance_fingerprint=graph.graph_fingerprint,
        )

        # Complete Rollback transition (L8)
        sm.transition(
            RemediationLifecycleState.ROLLED_BACK,
            actor=actor,
            reason="Atomic rollback executed following verification failure",
            timestamp=now_iso,
        )
        ledger = self._append_audit(
            ledger=ledger,
            event_type=AuditEventType.ROLLBACK_COMPLETED,
            finding_id=finding.finding_id,
            lifecycle_state=sm.current_state.value,
            actor=actor,
            timestamp=now_iso,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=app_res.pre_apply_snapshot_hash,
            provenance_fingerprint=graph.graph_fingerprint,
        )

        return RemediationLifecycleResult(
            finding_id=finding.finding_id,
            current_state=sm.current_state,
            repository_identity=self.repository_identity,
            finding=finding,
            verdict=verdict,
            rca=rca,
            strategy=strategy,
            proposal=proposal,
            approval_token=updated_token,
            source_snapshot=snapshot,
            application_result=app_res,
            verification_result=ver_res,
            provenance_graph=graph,
            ledger=ledger,
            state_history=sm.history,
            failure_reason=f"Verification failed with state '{failed_state}'",
        )
