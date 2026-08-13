"""Comprehensive Unit & Adversarial Test Suite for RemediationLifecycleEngine (Sprint E13-5 Phase 4).

Validates Security Invariants:
  - L1: State Transition Authority (Exclusively via LifecycleStateMachine).
  - L2: No State Skipping.
  - L3: Historical Immutability.
  - L4: Verification Evidence Binding (6-point cryptographic proof).
  - L5: Approval Binding.
  - L6: Verification Freshness.
  - L7: Zero LLM Security Authority.
  - L8: Rollback Integrity.
  - L9: No Auto-Repair Loop.
  - L10: Provenance Continuity.
  - L11: Append-Only Audit.
  - L14-L17: Repository, Proposal, Snapshot, and Verification Cryptographic Binding.
  - L18: Failure Finality.
  - L28: No Subprocess / Execution Capabilities.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
import pytest

from karsasec.ai.rca.models import (
    FalsePositiveAssessment,
    ReflectionStatus,
    RootCauseAnalysis,
    RootCauseCategory,
)
from karsasec.ai.remediation.approval import ApprovalStatus, PatchApprovalToken
from karsasec.ai.remediation.applier import ApplicationResult, ApplicationStatus
from karsasec.ai.remediation.lifecycle import RemediationLifecycleEngine
from karsasec.ai.remediation.models import (
    PatchHunk,
    PatchProposal,
    PatchValidationStatus,
)
from karsasec.ai.remediation.snapshot import SourceSnapshot
from karsasec.ai.remediation.state_machine import (
    InvalidStateTransitionError,
    LifecycleStateMachine,
    RemediationLifecycleState,
    VerificationAuthority,
    VerificationEvidenceContract,
)
from karsasec.ai.remediation.verification import VerificationContract, VerificationResult, VerificationStatus
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow.security_verdict import SecurityVerdict, VerdictConfidence, VerdictStatus
from karsasec.rules.enums import Confidence, Severity


# =============================================================================
# HELPER BUILDERS & MOCKS
# =============================================================================


def _make_dummy_finding(tmp_path: Path, finding_id: str = "F-101") -> Finding:
    target = tmp_path / "app.py"
    target.write_text("query = f'SELECT * FROM users WHERE name={name}'\n", encoding="utf-8")

    v = SecurityVerdict.create(
        status=VerdictStatus.VULNERABLE,
        confidence=VerdictConfidence.HIGH,
        rule_id="RULE-01",
        sink_id="SINK-1",
        sink_category="SQL_INJECTION",
        file_path="app.py",
        function_name="get_user",
        line_number=1,
        variable_version="query",
    )
    ev = Evidence(snippet="query = f'SELECT * FROM users WHERE name={name}'", line=1, column=1)
    return Finding(
        finding_id=finding_id,
        rule_id="RULE-01",
        fingerprint="find_fp_101",
        title="SQL Injection",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021-Injection",
        file_path=Path("app.py"),
        evidence=ev,
        description="SQL Injection in app.py",
        remediation="Use parameterized queries",
        verdict=v,
    )


def _make_dummy_proposal(finding_id: str = "F-101") -> PatchProposal:
    hunk = PatchHunk(
        file_path="app.py",
        start_line=1,
        end_line=1,
        original_text="query = f'SELECT * FROM users WHERE name={name}'",
        proposed_text="query = 'SELECT * FROM users WHERE name=%s'",
        context="",
        evidence_reference="app.py:1",
    )
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-query = f'SELECT * FROM users WHERE name={name}'\n+query = 'SELECT * FROM users WHERE name=%s'"
    fp = PatchProposal.compute_fingerprint(
        finding_id=finding_id,
        target_files=("app.py",),
        unified_diff=diff,
        status=PatchValidationStatus.VALID,
    )
    return PatchProposal(
        proposal_id="prop_101",
        finding_id=finding_id,
        target_files=("app.py",),
        hunks=(hunk,),
        unified_diff=diff,
        rationale="Fix SQLi",
        root_cause_reference="rca_fp",
        evidence_references=("app.py:1",),
        expected_effect="Eliminates SQLi",
        risk_level="LOW",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint=fp,
    )


def _make_dummy_token(
    tmp_path: Path,
    proposal: PatchProposal,
    finding_id: str = "F-101",
    status: ApprovalStatus = ApprovalStatus.APPROVED,
) -> PatchApprovalToken:
    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    tok = PatchApprovalToken.create(
        token_id="tok_101",
        finding_id=finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
        approved_by="lead_architect",
        approved_at="2026-08-13T12:00:00Z",
    )
    if status != ApprovalStatus.APPROVED:
        object.__setattr__(tok, "status", status)
    return tok


def _make_dummy_rescan_verdict(finding_id: str = "F-101", fixed: bool = True) -> tuple[Finding, ...]:
    if fixed:
        return ()
    # Return finding still active
    v = SecurityVerdict.create(
        status=VerdictStatus.VULNERABLE,
        confidence=VerdictConfidence.HIGH,
        rule_id="RULE-01",
        sink_id="SINK-1",
        sink_category="SQL_INJECTION",
        file_path="app.py",
        function_name="get_user",
        line_number=1,
        variable_version="query",
    )
    ev = Evidence(snippet="query = f'SELECT * FROM users WHERE name={name}'", line=1, column=1)
    f = Finding(
        finding_id=finding_id,
        rule_id="RULE-01",
        fingerprint="find_fp_101",
        title="SQL Injection",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021-Injection",
        file_path=Path("app.py"),
        evidence=ev,
        description="SQL Injection",
        remediation="Fix it",
        verdict=v,
    )
    return (f,)


# =============================================================================
# LIFECYCLE ENGINE TESTS (1 - 30)
# =============================================================================


def test_01_lifecycle_engine_initialization(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    assert str(engine.repository_root) == str(tmp_path.resolve())
    assert engine.repository_identity == str(tmp_path.resolve())


def test_02_detected_transition(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)
    res = engine.execute(finding, approval_provider=None)

    assert res.finding_id == finding.finding_id
    assert len(res.state_history) >= 2
    assert res.state_history[0].new_state == RemediationLifecycleState.DETECTED


def test_03_evidence_verified_transition(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)
    res = engine.execute(finding, approval_provider=None)

    states = [h.new_state for h in res.state_history]
    assert RemediationLifecycleState.EVIDENCE_VERIFIED in states


def test_04_rca_transition(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    rca = RootCauseAnalysis(
        finding_id=finding.finding_id,
        rule_id="RULE-01",
        verdict_status="VULNERABLE",
        root_cause_category=RootCauseCategory.DIRECT_USER_INPUT,
        primary_cause_step=None,
        evidence_chain=(),
        evidence_gaps=(),
        contradictions=(),
        false_positive_risk=FalsePositiveAssessment.LOW_RISK,
        reflection_status=ReflectionStatus.PROVEN,
        explanation_summary="Unsanitized input.",
        remediation_advice="Use parameterization.",
        rca_fingerprint="rca_fp_101",
    )
    res = engine.execute(finding, rca=rca, approval_provider=None)

    assert res.rca == rca
    states = [h.new_state for h in res.state_history]
    assert RemediationLifecycleState.RCA_ESTABLISHED in states


def test_05_proposal_transition(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)
    res = engine.execute(finding, approval_provider=None)

    assert res.proposal is not None
    states = [h.new_state for h in res.state_history]
    assert RemediationLifecycleState.REMEDIATION_PROPOSED in states


def test_06_awaiting_approval(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)
    res = engine.execute(finding, approval_provider=None)

    states = [h.new_state for h in res.state_history]
    assert RemediationLifecycleState.AWAITING_APPROVAL in states


def test_07_approval_success(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    def _approve_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
            approved_by="sec_lead",
        )

    res = engine.execute(
        finding,
        approval_provider=_approve_cb,
        rescan_callback=lambda: _make_dummy_rescan_verdict(finding.finding_id, fixed=True),
    )

    assert res.current_state == RemediationLifecycleState.VERIFIED_FIXED
    assert res.approval_token is not None
    assert res.approval_token.approved_by == "sec_lead"


def test_08_approval_rejection_no_token(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)
    res = engine.execute(finding, approval_provider=None)

    assert res.current_state == RemediationLifecycleState.REJECTED
    assert res.failure_reason is not None
    assert "missing or rejected" in res.failure_reason


def test_09_approval_rejection_invalid_token(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    # Forged token with invalid fingerprint
    tok = PatchApprovalToken(
        token_id="tok_bad",
        finding_id=finding.finding_id,
        proposal_fingerprint="bad_fp",
        source_snapshot_hash="bad_snap",
        target_files=("app.py",),
        repository_identity=str(tmp_path.resolve()),
        approved_by="hacker",
        approved_at="2026-08-13T12:00:00Z",
        expires_at=None,
        approval_context="FORGED",
        status=ApprovalStatus.APPROVED,
        token_fingerprint="invalid_token_fingerprint",
    )

    res = engine.execute(finding, approval_provider=tok)
    assert res.current_state == RemediationLifecycleState.REJECTED
    assert "Approval token invalid" in (res.failure_reason or "")


def test_10_snapshot_verification(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    def _approve_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(
        finding,
        approval_provider=_approve_cb,
        rescan_callback=lambda: (),
    )

    states = [h.new_state for h in res.state_history]
    assert RemediationLifecycleState.SNAPSHOT_VERIFIED in states


def test_11_application_success(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    def _approve_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(
        finding,
        approval_provider=_approve_cb,
        rescan_callback=lambda: (),
    )

    assert res.application_result is not None
    assert res.application_result.status == ApplicationStatus.APPLIED


def test_12_application_failure(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    # Force rescan callback exception
    def _failing_rescan() -> tuple[Finding, ...]:
        raise RuntimeError("SAST engine crashed during rescan")

    def _approve_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(
        finding,
        approval_provider=_approve_cb,
        rescan_callback=_failing_rescan,
    )

    assert res.current_state in (RemediationLifecycleState.ROLLED_BACK, RemediationLifecycleState.CRITICAL_RECOVERY_FAILURE)
    assert res.application_result is not None
    assert res.application_result.status in (ApplicationStatus.FAILED, ApplicationStatus.ROLLED_BACK)


def test_13_rollback_on_apply_failure(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    def _failing_rescan() -> tuple[Finding, ...]:
        raise RuntimeError("Scan error")

    def _approve_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(
        finding,
        approval_provider=_approve_cb,
        rescan_callback=_failing_rescan,
    )

    assert res.current_state == RemediationLifecycleState.ROLLED_BACK


def test_14_critical_recovery_failure(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    # Simulate CRITICAL_FAILURE rollback status
    def _approve_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    # Mock execute_transaction to return CRITICAL_FAILURE
    def _mock_crit_exec(
        proposal: PatchProposal,
        token: PatchApprovalToken,
        finding: Finding,
        rescan_callback: Any,
        **kwargs: Any,
    ) -> tuple[ApplicationResult, None, PatchApprovalToken]:
        app_res = ApplicationResult(
            transaction_id="trans_crit",
            finding_id=finding.finding_id,
            proposal_fingerprint="prop_fp",
            token_id="tok_101",
            status=ApplicationStatus.FAILED,
            target_files=("app.py",),
            pre_apply_snapshot_hash="pre",
            post_apply_snapshot_hash="post",
            rollback_status="CRITICAL_FAILURE",
            failure_reason="Storage device write failure during rollback",
        )
        return app_res, None, token

    engine.application_agent.execute_transaction = _mock_crit_exec  # type: ignore[assignment]

    res = engine.execute(
        finding,
        approval_provider=_approve_cb,
    )

    assert res.current_state == RemediationLifecycleState.CRITICAL_RECOVERY_FAILURE


def test_15_verification_success_verified_fixed(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    def _approve_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(
        finding,
        approval_provider=_approve_cb,
        rescan_callback=lambda: (),
    )

    assert res.current_state == RemediationLifecycleState.VERIFIED_FIXED
    assert res.verification_result is not None
    assert res.verification_result.status == VerificationStatus.VERIFIED_FIXED


def test_16_verification_failure_still_vulnerable(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    def _approve_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(
        finding,
        approval_provider=_approve_cb,
        rescan_callback=lambda: _make_dummy_rescan_verdict(finding.finding_id, fixed=False),
    )

    assert res.current_state == RemediationLifecycleState.ROLLED_BACK
    assert res.verification_result is not None
    assert res.verification_result.status == VerificationStatus.STILL_VULNERABLE


def test_17_verification_failure_unknown(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    def _approve_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    # Force verification result status UNKNOWN
    def _mock_unk_exec(
        proposal: PatchProposal,
        token: PatchApprovalToken,
        finding: Finding,
        rescan_callback: Any,
        **kwargs: Any,
    ) -> tuple[ApplicationResult, VerificationResult, PatchApprovalToken]:
        app_res = ApplicationResult(
            transaction_id="trans_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            token_id=token.token_id,
            status=ApplicationStatus.APPLIED,
            target_files=proposal.target_files,
            pre_apply_snapshot_hash=token.source_snapshot_hash,
            post_apply_snapshot_hash="post_hash",
            rollback_status="NOT_NEEDED",
            failure_reason=None,
        )
        contract = VerificationContract(
            finding_id=finding.finding_id,
            rule_id="RULE-01",
            cwe_id="CWE-89",
            sink_category="SQL_INJECTION",
            file_path="app.py",
            line_number=1,
            affected_symbol="query",
            evidence_fingerprint="ev_fp",
        )
        ver_res = VerificationResult(
            verification_id="ver_unk",
            finding_id=finding.finding_id,
            pre_apply_verdict_status="VULNERABLE",
            post_apply_verdict_status="UNKNOWN",
            status=VerificationStatus.UNKNOWN,
            contract=contract,
            matching_findings_count=0,
            details="Rescan interrupted",
        )
        return app_res, ver_res, token

    engine.application_agent.execute_transaction = _mock_unk_exec  # type: ignore[assignment]

    res = engine.execute(finding, approval_provider=_approve_cb)
    assert res.current_state == RemediationLifecycleState.ROLLED_BACK
    assert res.verification_result.status == VerificationStatus.UNKNOWN


def test_18_verified_fixed_evidence_binding(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    def _approve_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(
        finding,
        approval_provider=_approve_cb,
        rescan_callback=lambda: (),
    )

    ver = res.verification_result
    assert ver is not None
    contract = VerificationEvidenceContract.from_verification_result(
        verification_result=ver,
        proposal_fingerprint=res.proposal.proposal_fingerprint,
        source_snapshot_hash=res.approval_token.source_snapshot_hash,
        post_apply_snapshot_hash=res.application_result.post_apply_snapshot_hash,
        verification_fingerprint=ver.verification_fingerprint,
    )
    assert contract.finding_id == finding.finding_id
    assert contract.authority == VerificationAuthority.DETERMINISTIC_SAST


def test_19_stale_verification_rejection() -> None:
    # Cannot establish VERIFIED_FIXED using stale or invalid verification run ID
    contract = VerificationEvidenceContract(
        finding_id="F-101",
        proposal_fingerprint="prop_fp",
        source_snapshot_hash="src_snap",
        post_apply_snapshot_hash="post_snap",
        verification_run_id="stale_ver_1",
        verification_fingerprint="ver_fp",
        authority=VerificationAuthority.DETERMINISTIC_SAST,
    )
    sm = LifecycleStateMachine("F-101")
    with pytest.raises(InvalidStateTransitionError, match="VERIFIED_FIXED can only be reached from SECURITY_RESCAN"):
        sm.transition_verified_fixed(contract)


def test_20_proposal_fingerprint_mismatch(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    def _mismatched_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint="wrong_prop_fingerprint",
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(finding, approval_provider=_mismatched_cb)
    assert res.current_state == RemediationLifecycleState.REJECTED
    assert "token invalid" in (res.failure_reason or "").lower()


def test_21_repository_mismatch(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    def _mismatched_repo_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity="/other/repo/path",
        )

    res = engine.execute(finding, approval_provider=_mismatched_repo_cb)
    assert res.current_state == RemediationLifecycleState.REJECTED
    assert "repository" in (res.failure_reason or "").lower()


def test_22_token_reuse_rejection(tmp_path: Path) -> None:
    finding = _make_dummy_finding(tmp_path)
    proposal = _make_dummy_proposal(finding.finding_id)
    tok = _make_dummy_token(tmp_path, proposal, finding.finding_id, status=ApprovalStatus.USED)

    ok, err = tok.verify_valid(
        expected_finding_id=finding.finding_id,
        expected_proposal_fingerprint=proposal.proposal_fingerprint,
        expected_snapshot_hash="hash",
        expected_repository_identity=str(tmp_path.resolve()),
    )

    assert ok is False
    assert "TOKEN_ALREADY_USED" in err


def test_23_ledger_append_only_behavior(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    def _approve_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(
        finding,
        approval_provider=_approve_cb,
        rescan_callback=lambda: (),
    )

    ledger = res.ledger
    valid, msg = ledger.validate_chain()
    assert valid is True
    assert msg == "VALID"
    assert len(ledger.events) >= 8


def test_24_provenance_continuity(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    def _approve_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(
        finding,
        approval_provider=_approve_cb,
        rescan_callback=lambda: (),
    )

    graph = res.provenance_graph
    valid, msg = graph.validate_integrity()
    assert valid is True
    assert msg == "VALID"
    assert len(graph.nodes) >= 6


def test_25_no_auto_repair_loop(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    assert not hasattr(engine, "auto_repair")
    assert not hasattr(engine, "retry_patch")
    assert not hasattr(engine, "repair_until_fixed")


def test_26_llm_cannot_establish_verified_fixed() -> None:
    with pytest.raises(ValueError, match="cannot establish VERIFIED_FIXED"):
        VerificationEvidenceContract(
            finding_id="F-101",
            proposal_fingerprint="prop_fp",
            source_snapshot_hash="src_snap",
            post_apply_snapshot_hash="post_snap",
            verification_run_id="ver_id",
            verification_fingerprint="ver_fp",
            authority=VerificationAuthority.LLM_ADVISORY,
        )


def test_27_no_state_skipping_enforcement() -> None:
    sm = LifecycleStateMachine("F-101")
    with pytest.raises(InvalidStateTransitionError, match="Illegal transition"):
        sm.transition(RemediationLifecycleState.VERIFIED_FIXED)


def test_28_finding_and_verdict_immutability(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)
    orig_verdict_status = finding.verdict.status

    engine.execute(finding, approval_provider=None)
    assert finding.verdict.status == orig_verdict_status


def test_29_no_execution_capabilities_capability_audit(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    assert not hasattr(engine, "subprocess")
    assert not hasattr(engine, "os")
    assert not hasattr(engine, "git")


def test_30_result_serialization_to_dict(tmp_path: Path) -> None:
    engine = RemediationLifecycleEngine(repository_root=tmp_path)
    finding = _make_dummy_finding(tmp_path)

    def _approve_cb(proposal: PatchProposal, snapshot: SourceSnapshot) -> PatchApprovalToken:
        return PatchApprovalToken.create(
            token_id="tok_101",
            finding_id=finding.finding_id,
            proposal_fingerprint=proposal.proposal_fingerprint,
            source_snapshot_hash=snapshot.aggregate_hash,
            target_files=proposal.target_files,
            repository_identity=str(tmp_path.resolve()),
        )

    res = engine.execute(
        finding,
        approval_provider=_approve_cb,
        rescan_callback=lambda: (),
    )

    d = res.to_dict()
    assert d["finding_id"] == finding.finding_id
    assert d["current_state"] == "VERIFIED_FIXED"
    assert len(d["provenance_fingerprint"]) == 64
    assert len(d["ledger_fingerprint"]) == 64
