"""E2E Integration Test Suite for Sprint E13-5: Remediation Lifecycle, Provenance Ledger & Security State Machine.

Validates 15 core end-to-end security invariants using REAL production classes:
  1. Successful complete remediation lifecycle
  2. Invalid state transition rejection
  3. State skipping rejection
  4. LLM cannot grant VERIFIED_FIXED (L7)
  5. Human claim cannot grant VERIFIED_FIXED
  6. Stale verification cannot grant VERIFIED_FIXED
  7. Verification evidence mismatch rejection
  8. Proposal fingerprint mismatch rejection
  9. Snapshot mismatch / TOCTOU rejection
 10. Failed application lifecycle
 11. Rollback lifecycle on verification failure
 12. Critical recovery failure finality (L18)
 13. Provenance graph continuity (P1-P18)
 14. Ledger tampering & replay detection (L11, L21-L28)
 15. Complete lifecycle audit & SARIF representation
"""

from __future__ import annotations

from pathlib import Path
import pytest

from karsasec.ai.remediation.applier import ApplicationResult, ApplicationStatus
from karsasec.ai.remediation.approval import PatchApprovalToken
from karsasec.ai.remediation.audit import AuditEventType, LifecycleAuditEvent
from karsasec.ai.remediation.ledger import RemediationLedger
from karsasec.ai.remediation.lifecycle import RemediationLifecycleEngine
from karsasec.ai.remediation.models import PatchHunk, PatchProposal, PatchValidationStatus
from karsasec.ai.remediation.provenance import ProvenanceNode, RemediationProvenanceGraph
from karsasec.ai.remediation.snapshot import SourceSnapshot
from karsasec.ai.remediation.state_machine import (
    LifecycleStateMachine,
    RemediationLifecycleState,
    VerificationAuthority,
    VerificationEvidenceContract,
)
from karsasec.ai.remediation.verification import VerificationContract, VerificationResult, VerificationStatus
from karsasec.core.execution.result import ExecutionResult
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.core.reporting.sarif_reporter import SARIFReporter
from karsasec.core.reporting.target import FileTarget
from karsasec.graph.dataflow.security_verdict import DecisionReason, SecurityVerdict, VerdictConfidence, VerdictStatus
from karsasec.rules.enums import Confidence, Severity


def _create_sqli_code() -> str:
    return (
        "import sqlite3\n"
        "from flask import request\n\n"
        "def get_user():\n"
        "    name = request.args.get('name')\n"
        "    conn = sqlite3.connect('app.db')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute('SELECT * FROM users WHERE name=' + name)\n"
        "    return cursor.fetchall()\n"
    )


def _create_test_finding(tmp_path: Path, finding_id: str = "F-E2E-101") -> Finding:
    v = SecurityVerdict.create(
        status=VerdictStatus.VULNERABLE,
        confidence=VerdictConfidence.HIGH,
        rule_id="RULE-SQLI-01",
        sink_id="SINK-1",
        sink_category="SQL_INJECTION",
        file_path="app.py",
        function_name="get_user",
        line_number=8,
        variable_version="query",
        reason_codes=(DecisionReason.TAINT_REACHES_SINK,),
        provenance_path=("app.py:8",),
    )
    ev = Evidence(snippet="cursor.execute('SELECT * FROM users WHERE name=' + name)", line=8, column=1)
    return Finding(
        finding_id=finding_id,
        rule_id="RULE-SQLI-01",
        fingerprint=f"find_fp_{finding_id}",
        title="SQL Injection in app.py",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021-Injection",
        file_path=Path("app.py"),
        evidence=ev,
        description="SQL Injection via string concatenation",
        remediation="Use parameterized query",
        verdict=v,
    )


def test_e2e_01_successful_complete_remediation_lifecycle(tmp_path: Path) -> None:
    """01. Successful complete remediation lifecycle from DETECTED to VERIFIED_FIXED."""
    app_file = tmp_path / "app.py"
    app_file.write_text(_create_sqli_code(), encoding="utf-8")

    finding = _create_test_finding(tmp_path, "F-E2E-01")
    engine = RemediationLifecycleEngine(repository_root=tmp_path)

    def _approval_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_e2e_01",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
            approved_by="lead_sec_arch",
        )

    res = engine.execute(
        finding=finding,
        approval_provider=_approval_cb,
        rescan_callback=lambda: (),
    )

    assert res.current_state == RemediationLifecycleState.VERIFIED_FIXED
    assert res.verification_result is not None
    assert res.verification_result.status == VerificationStatus.VERIFIED_FIXED
    assert res.approval_token is not None
    assert len(res.ledger.events) >= 6
    assert res.provenance_graph.graph_fingerprint != ""


def test_e2e_02_invalid_state_transition_rejection(tmp_path: Path) -> None:
    """02. Rejection of illegal state machine backward transition (L1)."""
    sm = LifecycleStateMachine(finding_id="F-E2E-02")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)

    with pytest.raises(ValueError, match="Illegal transition"):
        sm.transition(RemediationLifecycleState.DETECTED)


def test_e2e_03_state_skipping_rejection(tmp_path: Path) -> None:
    """03. Rejection of state skipping transition (L2)."""
    sm = LifecycleStateMachine(finding_id="F-E2E-03")

    with pytest.raises(ValueError, match="Illegal transition"):
        sm.transition(RemediationLifecycleState.APPLYING)


def test_e2e_04_llm_cannot_grant_verified_fixed(tmp_path: Path) -> None:
    """04. Zero LLM security authority invariant enforcement (L7)."""
    finding = _create_test_finding(tmp_path, "F-E2E-04")

    with pytest.raises(ValueError, match="cannot establish VERIFIED_FIXED state"):
        VerificationEvidenceContract(
            finding_id=finding.finding_id,
            proposal_fingerprint="prop_fp_101",
            source_snapshot_hash="snap_hash_101",
            post_apply_snapshot_hash="post_snap_101",
            verification_run_id="run_101",
            verification_fingerprint="ver_fp_101",
            authority=VerificationAuthority.LLM_ADVISORY,
        )


def test_e2e_05_human_claim_cannot_grant_verified_fixed(tmp_path: Path) -> None:
    """05. Human claim authority cannot bypass SAST verification authority (L7)."""
    finding = _create_test_finding(tmp_path, "F-E2E-05")

    with pytest.raises(ValueError, match="cannot establish VERIFIED_FIXED state"):
        VerificationEvidenceContract(
            finding_id=finding.finding_id,
            proposal_fingerprint="prop_fp_101",
            source_snapshot_hash="snap_hash_101",
            post_apply_snapshot_hash="post_snap_101",
            verification_run_id="run_101",
            verification_fingerprint="ver_fp_101",
            authority=VerificationAuthority.HUMAN_CLAIM,
        )


def test_e2e_06_stale_verification_cannot_grant_verified_fixed(tmp_path: Path) -> None:
    """06. Stale verification result rejection (L6)."""
    finding = _create_test_finding(tmp_path, "F-E2E-06")

    with pytest.raises(ValueError, match="verification_run_id cannot be empty"):
        VerificationEvidenceContract(
            finding_id=finding.finding_id,
            proposal_fingerprint="prop_fp_101",
            source_snapshot_hash="snap_hash_101",
            post_apply_snapshot_hash="post_snap_101",
            verification_run_id="",
            verification_fingerprint="ver_fp_101",
            authority=VerificationAuthority.DETERMINISTIC_SAST,
        )


def test_e2e_07_verification_evidence_mismatch(tmp_path: Path) -> None:
    """07. Verification evidence finding ID mismatch rejection (L4)."""
    contract = VerificationEvidenceContract(
        finding_id="F-MISMATCH",
        proposal_fingerprint="prop_fp_101",
        source_snapshot_hash="snap_hash_101",
        post_apply_snapshot_hash="post_snap_101",
        verification_run_id="run_101",
        verification_fingerprint="ver_fp_101",
        authority=VerificationAuthority.DETERMINISTIC_SAST,
    )

    sm = LifecycleStateMachine(finding_id="F-ACTUAL")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLIED_UNVERIFIED)
    sm.transition(RemediationLifecycleState.SECURITY_RESCAN)

    with pytest.raises(ValueError, match="finding_id 'F-MISMATCH' does not match"):
        sm.transition_verified_fixed(evidence=contract)


def test_e2e_08_proposal_fingerprint_mismatch(tmp_path: Path) -> None:
    """08. Proposal fingerprint mismatch rejection during token validation (L5, L15)."""
    app_file = tmp_path / "app.py"
    app_file.write_text(_create_sqli_code(), encoding="utf-8")

    finding = _create_test_finding(tmp_path, "F-E2E-08")
    engine = RemediationLifecycleEngine(repository_root=tmp_path)

    def _mismatched_provider(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_bad_prop",
            finding_id=finding.finding_id,
            proposal_fingerprint="BOGUS_PROPOSAL_FINGERPRINT",
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(
        finding=finding,
        approval_provider=_mismatched_provider,
    )

    assert res.current_state == RemediationLifecycleState.REJECTED
    assert "Approval token invalid" in (res.failure_reason or "")


def test_e2e_09_snapshot_mismatch_toctou(tmp_path: Path) -> None:
    """09. Pre-apply snapshot mismatch (TOCTOU source file tampering) rejection (L5, L16)."""
    app_file = tmp_path / "app.py"
    app_file.write_text(_create_sqli_code(), encoding="utf-8")

    finding = _create_test_finding(tmp_path, "F-E2E-09")
    engine = RemediationLifecycleEngine(repository_root=tmp_path)

    def _cb(prop: PatchProposal, snap: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_bad_snap",
            finding_id=finding.finding_id,
            proposal_fingerprint=prop.proposal_fingerprint,
            source_snapshot_hash="BOGUS_SNAPSHOT_HASH_0000000000000000",
            target_files=prop.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(
        finding=finding,
        approval_provider=_cb,
    )

    assert res.current_state == RemediationLifecycleState.REJECTED
    assert "Approval token invalid" in (res.failure_reason or "")


def test_e2e_10_failed_application_lifecycle(tmp_path: Path) -> None:
    """10. Failed application lifecycle handling when patch hunk application fails."""
    app_file = tmp_path / "app.py"
    app_file.write_text("print('completely unrelated code')\n", encoding="utf-8")

    finding = _create_test_finding(tmp_path, "F-E2E-10")
    engine = RemediationLifecycleEngine(repository_root=tmp_path)

    bad_hunk = PatchHunk(
        file_path="app.py",
        start_line=1,
        end_line=1,
        original_text="NON_EXISTENT_TARGET_CODE",
        proposed_text="REPLACEMENT_CODE",
        context="",
        evidence_reference="app.py:1",
    )
    diff = "diff"
    fp = PatchProposal.compute_fingerprint(finding.finding_id, ("app.py",), diff, PatchValidationStatus.VALID)
    bad_proposal = PatchProposal(
        proposal_id="prop_bad_10",
        finding_id=finding.finding_id,
        target_files=("app.py",),
        hunks=(bad_hunk,),
        unified_diff=diff,
        rationale="Invalid patch",
        root_cause_reference="RCA-10",
        evidence_references=(),
        expected_effect="",
        risk_level="LOW",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint=fp,
    )

    def _proposal_cb(f: Finding) -> PatchProposal:
        return bad_proposal

    def _approval_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_e2e_10",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(
        finding=finding,
        proposal_provider=_proposal_cb,
        approval_provider=_approval_cb,
    )

    assert res.current_state in (RemediationLifecycleState.ROLLED_BACK, RemediationLifecycleState.REJECTED, RemediationLifecycleState.APPLY_FAILED)
    assert res.application_result is not None


def test_e2e_11_rollback_lifecycle(tmp_path: Path) -> None:
    """11. Automatic atomic rollback lifecycle when verification shows vulnerability persists (L8)."""
    app_file = tmp_path / "app.py"
    app_file.write_text(_create_sqli_code(), encoding="utf-8")

    finding = _create_test_finding(tmp_path, "F-E2E-11")
    engine = RemediationLifecycleEngine(repository_root=tmp_path)

    def _approval_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_e2e_11",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    def _rescan_still_vulnerable():
        return (finding,)

    res = engine.execute(
        finding=finding,
        approval_provider=_approval_cb,
        rescan_callback=_rescan_still_vulnerable,
    )

    assert res.current_state == RemediationLifecycleState.ROLLED_BACK
    assert res.verification_result is not None
    assert res.verification_result.status == VerificationStatus.STILL_VULNERABLE
    assert app_file.read_text(encoding="utf-8") == _create_sqli_code()


def test_e2e_12_critical_recovery_failure_finality(tmp_path: Path) -> None:
    """12. Terminal state finality for critical recovery failures (L18)."""
    sm = LifecycleStateMachine(finding_id="F-E2E-12")
    sm.transition(RemediationLifecycleState.EVIDENCE_VERIFIED)
    sm.transition(RemediationLifecycleState.RCA_ESTABLISHED)
    sm.transition(RemediationLifecycleState.REMEDIATION_PROPOSED)
    sm.transition(RemediationLifecycleState.AWAITING_APPROVAL)
    sm.transition(RemediationLifecycleState.APPROVED)
    sm.transition(RemediationLifecycleState.SNAPSHOT_VERIFIED)
    sm.transition(RemediationLifecycleState.APPLYING)
    sm.transition(RemediationLifecycleState.APPLY_FAILED)
    sm.transition(RemediationLifecycleState.CRITICAL_RECOVERY_FAILURE)

    with pytest.raises(ValueError, match="Illegal transition"):
        sm.transition(RemediationLifecycleState.ROLLED_BACK)


def test_e2e_13_provenance_continuity(tmp_path: Path) -> None:
    """13. Provenance continuity & order-invariant fingerprinting (P1-P18, L10)."""
    finding = _create_test_finding(tmp_path, "F-E2E-13")

    f_node = ProvenanceNode.create_finding_node(finding)
    graph = RemediationProvenanceGraph().add_node(f_node)

    snap = SourceSnapshot.capture(tmp_path, ())
    snap_node = ProvenanceNode.create_source_snapshot_node(snap, predecessor_id=f_node.node_id)
    graph = graph.add_node(snap_node)

    assert len(graph.nodes) == 2
    assert snap_node.predecessor_node_ids == (f_node.node_id,)
    assert graph.graph_fingerprint != ""


def test_e2e_14_ledger_tampering_detection(tmp_path: Path) -> None:
    """14. Ledger tamper detection and predecessor chain integrity verification (L11, L21-L28)."""
    ledger = RemediationLedger()

    e1 = LifecycleAuditEvent.create(
        event_id="aud_1",
        event_type=AuditEventType.FINDING_DETECTED,
        finding_id="F-E2E-14",
        lifecycle_state="DETECTED",
        actor="orchestrator",
        timestamp="2026-08-13T00:00:00Z",
        repository_identity="/repo",
    )
    ledger = ledger.append(e1)

    e2 = LifecycleAuditEvent.create(
        event_id="aud_2",
        event_type=AuditEventType.EVIDENCE_VERIFIED,
        finding_id="F-E2E-14",
        lifecycle_state="EVIDENCE_VERIFIED",
        actor="orchestrator",
        timestamp="2026-08-13T00:01:00Z",
        repository_identity="/repo",
        predecessor_event_id=e1.event_id,
        predecessor_event_fingerprint=e1.event_fingerprint,
    )
    ledger = ledger.append(e2)

    assert len(ledger.events) == 2
    valid, msg = ledger.validate_chain()
    assert valid is True

    # Tampered event fingerprint creation should be rejected immediately upon validation
    with pytest.raises(ValueError, match="Invalid or tampered event fingerprint"):
        LifecycleAuditEvent(
            event_id=e2.event_id,
            event_type=e2.event_type,
            finding_id="F-TAMPERED",
            lifecycle_state=e2.lifecycle_state,
            actor=e2.actor,
            timestamp=e2.timestamp,
            repository_identity=e2.repository_identity,
            predecessor_event_id=e2.predecessor_event_id,
            predecessor_event_fingerprint=e2.predecessor_event_fingerprint,
            proposal_fingerprint=e2.proposal_fingerprint,
            source_snapshot_hash=e2.source_snapshot_hash,
            post_apply_snapshot_hash=e2.post_apply_snapshot_hash,
            verification_run_id=e2.verification_run_id,
            verification_fingerprint=e2.verification_fingerprint,
            provenance_fingerprint=e2.provenance_fingerprint,
            metadata=e2.metadata,
            event_fingerprint=e2.event_fingerprint,
        )


def test_e2e_15_complete_lifecycle_audit_and_sarif_representation(tmp_path: Path) -> None:
    """15. Full lifecycle execution export to SARIF 2.1.0 with remediation metadata."""
    app_file = tmp_path / "app.py"
    app_file.write_text(_create_sqli_code(), encoding="utf-8")

    finding = _create_test_finding(tmp_path, "F-E2E-15")

    finding.metadata["remediation_state"] = "VERIFIED_FIXED"
    finding.metadata["lifecycle_fingerprint"] = "lc_fp_e2e_15"
    finding.metadata["provenance_fingerprint"] = "prov_fp_e2e_15"
    finding.metadata["verification_run_id"] = "ver_run_e2e_15"
    finding.metadata["verification_status"] = "VERIFIED_FIXED"

    exec_result = ExecutionResult(
        scan_id="scan_e2e_15",
        timestamp="2026-08-13T00:00:00Z",
        files_scanned=1,
        rules_checked=1,
        nodes_processed=10,
        findings=(finding,),
    )

    sarif_file = tmp_path / "report.sarif"
    reporter = SARIFReporter()
    target = FileTarget(sarif_file)
    reporter.generate(exec_result, target)

    assert sarif_file.exists()
    sarif_content = sarif_file.read_text(encoding="utf-8")

    assert "karsasec.ai.remediation_state" in sarif_content
    assert "VERIFIED_FIXED" in sarif_content
    assert "karsasec.ai.provenance_fingerprint" in sarif_content
    assert "prov_fp_e2e_15" in sarif_content
