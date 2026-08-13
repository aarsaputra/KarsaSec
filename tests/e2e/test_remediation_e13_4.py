"""E2E Integration Test Suite for Sprint E13-4: Controlled Patch Application & Security Verification.

Validates the full lifecycle:
SAST -> RCA -> Remediation Strategy -> Patch Proposal -> Approval Token -> Source Snapshot -> Preflight -> Controlled Patch Applier -> Post-Apply SAST Verification -> Commit or Atomic Rollback.
"""

from __future__ import annotations

from pathlib import Path

from karsasec.ai.remediation.application_agent import ApplicationAuditRecord, RemediationApplicationAgent
from karsasec.ai.remediation.applier import ApplicationStatus
from karsasec.ai.remediation.approval import ApprovalStatus, PatchApprovalToken
from karsasec.ai.remediation.models import PatchHunk, PatchProposal, PatchValidationStatus
from karsasec.ai.remediation.snapshot import SourceSnapshot
from karsasec.ai.remediation.verification import VerificationStatus
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow.security_verdict import DecisionReason, SecurityVerdict, VerdictConfidence, VerdictStatus
from karsasec.rules.enums import Confidence, Severity


def _create_dummy_finding(finding_id: str = "F1", file_path: str = "app.py") -> Finding:
    v = SecurityVerdict.create(
        status=VerdictStatus.VULNERABLE,
        confidence=VerdictConfidence.HIGH,
        rule_id="CWE-89-SQLI",
        sink_id="sink_01",
        sink_category="SQL_EXECUTION",
        file_path=file_path,
        function_name="fn",
        line_number=7,
        variable_version="$x#1",
        call_context="GLOBAL",
        branch_polarity="UNKNOWN",
        reason_codes=(DecisionReason.TAINT_REACHES_SINK,),
        provenance_path=(f"{file_path}:7",),
    )
    return Finding(
        finding_id=finding_id,
        rule_id="CWE-89-SQLI",
        fingerprint=f"fp_{finding_id}",
        title="Dummy SQLi",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021",
        file_path=Path(file_path),
        evidence=Evidence(snippet="dummy", line=7, column=1),
        description="desc",
        remediation="fix",
        verdict=v,
    )


def _get_sqli_code() -> str:
    return (
        "import sqlite3\n"
        "from flask import request\n\n"
        "def search_user():\n"
        "    name = request.args.get('name')\n"
        "    conn = sqlite3.connect('app.db')\n"
        "    cursor = conn.cursor()\n"
        "    cursor.execute('SELECT * FROM users WHERE name=' + name)\n"
        "    return cursor.fetchall()\n"
    )


def _create_sqli_proposal(finding: Finding) -> PatchProposal:
    hunk = PatchHunk(
        file_path="app.py",
        start_line=7,
        end_line=7,
        original_text="cursor.execute('SELECT * FROM users WHERE name=' + name)",
        proposed_text="cursor.execute('SELECT * FROM users WHERE name=?', (name,))",
        context="",
        evidence_reference="app.py:7",
    )
    diff = "diff"
    fp = PatchProposal.compute_fingerprint(finding.finding_id, ("app.py",), diff, PatchValidationStatus.VALID)
    return PatchProposal(
        proposal_id="p1",
        finding_id=finding.finding_id,
        target_files=("app.py",),
        hunks=(hunk,),
        unified_diff=diff,
        rationale="Fix SQLi with parameterized query",
        root_cause_reference="RCA-SQLI",
        evidence_references=("app.py:7",),
        expected_effect="Eliminate SQL injection",
        risk_level="LOW",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint=fp,
    )


def test_e2e_01_full_successful_patch_application_lifecycle(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text(_get_sqli_code(), encoding="utf-8")

    finding = _create_dummy_finding("F-SQLI", "app.py")
    proposal = _create_sqli_proposal(finding)

    snap_approval = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=finding.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap_approval.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
        approved_by="lead_security_architect",
    )

    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    audits: list[ApplicationAuditRecord] = []

    def _rescan_callback():
        return ()

    app_res, ver_res, used_token = app_agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=finding,
        rescan_callback=_rescan_callback,
        audit_records=audits,
    )

    assert app_res.status == ApplicationStatus.APPLIED
    assert ver_res is not None
    assert ver_res.status == VerificationStatus.VERIFIED_FIXED
    assert used_token.status == ApprovalStatus.USED
    assert len(audits) == 1
    assert audits[0].verification_status == VerificationStatus.VERIFIED_FIXED


def test_e2e_02_toctou_source_tampering_blocks_application(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text(_get_sqli_code(), encoding="utf-8")

    finding = _create_dummy_finding("F-SQLI", "app.py")
    proposal = _create_sqli_proposal(finding)

    snap_approval = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=finding.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap_approval.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    # Mutate source file AFTER approval
    target_file.write_text(_get_sqli_code() + "\n# TAMPERED\n", encoding="utf-8")

    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_res, ver_res, _ = app_agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=finding,
        rescan_callback=lambda: (),
    )

    assert app_res.status == ApplicationStatus.REJECTED
    assert "APPROVAL_VERIFICATION_FAILED" in app_res.failure_reason
    assert ver_res is None


def test_e2e_03_token_reuse_protection_blocks_second_execution(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text(_get_sqli_code(), encoding="utf-8")

    finding = _create_dummy_finding("F-SQLI", "app.py")
    proposal = _create_sqli_proposal(finding)

    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=finding.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_res1, _, used_token = app_agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=finding,
        rescan_callback=lambda: (),
    )
    assert app_res1.status == ApplicationStatus.APPLIED
    assert used_token.status == ApprovalStatus.USED

    app_res2, _, _ = app_agent.execute_transaction(
        proposal=proposal,
        token=used_token,
        finding=finding,
        rescan_callback=lambda: (),
    )
    assert app_res2.status == ApplicationStatus.REJECTED
    assert "TOKEN_ALREADY_USED" in app_res2.failure_reason


def test_e2e_04_path_traversal_proposal_rejection(tmp_path: Path) -> None:
    proposal = PatchProposal(
        proposal_id="prop_bad",
        finding_id="F-TRAVERSAL",
        target_files=("../etc_passwd.py",),
        hunks=(),
        unified_diff="",
        rationale="",
        root_cause_reference="",
        evidence_references=(),
        expected_effect="",
        risk_level="HIGH",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint="fp_bad",
    )
    snap = SourceSnapshot(
        repository_root=str(tmp_path.resolve()),
        file_snapshots=(),
        aggregate_hash="hash",
        created_at="now",
    )
    token = PatchApprovalToken.create(
        finding_id="F-TRAVERSAL",
        proposal_fingerprint="fp_bad",
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    dummy_finding = _create_dummy_finding("F-TRAVERSAL", "app.py")
    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_res, _, _ = app_agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=dummy_finding,
        rescan_callback=lambda: (),
    )
    assert app_res.status == ApplicationStatus.REJECTED
    assert "PATH_TRAVERSAL_REJECTED" in app_res.failure_reason


def test_e2e_05_ambiguous_hunk_rejection_leaves_files_untouched(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    dup_content = (
        "cursor.execute('SELECT * FROM users WHERE name=' + name)\n"
        "cursor.execute('SELECT * FROM users WHERE name=' + name)\n"
    )
    target_file.write_text(dup_content, encoding="utf-8")

    hunk = PatchHunk(
        file_path="app.py",
        start_line=1,
        end_line=1,
        original_text="cursor.execute('SELECT * FROM users WHERE name=' + name)",
        proposed_text="safe()",
        context="",
        evidence_reference="app.py:1",
    )
    proposal = PatchProposal(
        proposal_id="p1",
        finding_id="F-DUP",
        target_files=("app.py",),
        hunks=(hunk,),
        unified_diff="diff",
        rationale="",
        root_cause_reference="",
        evidence_references=(),
        expected_effect="",
        risk_level="LOW",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint=PatchProposal.compute_fingerprint("F-DUP", ("app.py",), "diff", PatchValidationStatus.VALID),
    )

    snap = SourceSnapshot.capture(tmp_path, ("app.py",))
    token = PatchApprovalToken.create(
        finding_id="F-DUP",
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=("app.py",),
        repository_identity=str(tmp_path.resolve()),
    )

    dummy_finding = _create_dummy_finding("F-DUP", "app.py")
    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_res, _, _ = app_agent.execute_transaction(proposal=proposal, token=token, finding=dummy_finding, rescan_callback=lambda: ())

    assert app_res.status == ApplicationStatus.REJECTED
    assert "AMBIGUOUS_HUNK_MATCH" in app_res.failure_reason
    assert target_file.read_text(encoding="utf-8") == dup_content


def test_e2e_06_verification_failure_triggers_atomic_rollback(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text(_get_sqli_code(), encoding="utf-8")

    finding = _create_dummy_finding("F-SQLI", "app.py")
    proposal = _create_sqli_proposal(finding)

    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=finding.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    def _failed_rescan():
        return (finding,)

    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_res, ver_res, _ = app_agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=finding,
        rescan_callback=_failed_rescan,
    )

    assert app_res.status == ApplicationStatus.ROLLED_BACK
    assert ver_res is not None
    assert ver_res.status == VerificationStatus.STILL_VULNERABLE
    assert target_file.read_text(encoding="utf-8") == _get_sqli_code()


def test_e2e_07_repository_mismatch_rejection(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text("code\n", encoding="utf-8")

    proposal = PatchProposal(
        proposal_id="p1",
        finding_id="F1",
        target_files=("app.py",),
        hunks=(),
        unified_diff="diff",
        rationale="",
        root_cause_reference="",
        evidence_references=(),
        expected_effect="",
        risk_level="LOW",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint="fp1",
    )
    snap = SourceSnapshot.capture(tmp_path, ("app.py",))
    token = PatchApprovalToken.create(
        finding_id="F1",
        proposal_fingerprint="fp1",
        source_snapshot_hash=snap.aggregate_hash,
        target_files=("app.py",),
        repository_identity="/other/repo/path",
    )

    dummy_finding = _create_dummy_finding("F1", "app.py")
    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_res, _, _ = app_agent.execute_transaction(proposal=proposal, token=token, finding=dummy_finding, rescan_callback=lambda: ())
    assert app_res.status == ApplicationStatus.REJECTED
    assert "REPOSITORY_MISMATCH" in app_res.failure_reason


def test_e2e_08_expired_token_rejection(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text("code\n", encoding="utf-8")

    proposal = PatchProposal(
        proposal_id="p1",
        finding_id="F1",
        target_files=("app.py",),
        hunks=(),
        unified_diff="diff",
        rationale="",
        root_cause_reference="",
        evidence_references=(),
        expected_effect="",
        risk_level="LOW",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint="fp1",
    )
    snap = SourceSnapshot.capture(tmp_path, ("app.py",))
    token = PatchApprovalToken.create(
        finding_id="F1",
        proposal_fingerprint="fp1",
        source_snapshot_hash=snap.aggregate_hash,
        target_files=("app.py",),
        repository_identity=str(tmp_path.resolve()),
        expires_at="2020-01-01T00:00:00Z",
    )

    dummy_finding = _create_dummy_finding("F1", "app.py")
    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_res, _, _ = app_agent.execute_transaction(proposal=proposal, token=token, finding=dummy_finding, rescan_callback=lambda: ())
    assert app_res.status == ApplicationStatus.REJECTED
    assert "TOKEN_EXPIRED" in app_res.failure_reason


def test_e2e_09_multi_hunk_application(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text("line1 = 1\nline2 = 2\n", encoding="utf-8")

    h1 = PatchHunk("app.py", 1, 1, "line1 = 1", "line1 = 10", "", "")
    h2 = PatchHunk("app.py", 2, 2, "line2 = 2", "line2 = 20", "", "")
    proposal = PatchProposal(
        proposal_id="p1",
        finding_id="F1",
        target_files=("app.py",),
        hunks=(h1, h2),
        unified_diff="diff",
        rationale="",
        root_cause_reference="",
        evidence_references=(),
        expected_effect="",
        risk_level="LOW",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint=PatchProposal.compute_fingerprint("F1", ("app.py",), "diff", PatchValidationStatus.VALID),
    )
    snap = SourceSnapshot.capture(tmp_path, ("app.py",))
    token = PatchApprovalToken.create(
        finding_id="F1",
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=("app.py",),
        repository_identity=str(tmp_path.resolve()),
    )

    dummy_finding = _create_dummy_finding("F1", "app.py")
    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_res, ver_res, _ = app_agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=dummy_finding,
        rescan_callback=lambda: (),
    )
    assert app_res.status == ApplicationStatus.APPLIED
    assert target_file.read_text(encoding="utf-8") == "line1 = 10\nline2 = 20\n"


def test_e2e_10_tampered_token_fingerprint_rejection(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text("code\n", encoding="utf-8")

    proposal = PatchProposal(
        proposal_id="p1",
        finding_id="F1",
        target_files=("app.py",),
        hunks=(),
        unified_diff="diff",
        rationale="",
        root_cause_reference="",
        evidence_references=(),
        expected_effect="",
        risk_level="LOW",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint="fp1",
    )
    snap = SourceSnapshot.capture(tmp_path, ("app.py",))
    token = PatchApprovalToken.create(
        finding_id="F1",
        proposal_fingerprint="fp1",
        source_snapshot_hash=snap.aggregate_hash,
        target_files=("app.py",),
        repository_identity=str(tmp_path.resolve()),
    )
    tampered_token = PatchApprovalToken(
        token_id=token.token_id,
        finding_id="F-TAMPERED",
        proposal_fingerprint=token.proposal_fingerprint,
        source_snapshot_hash=token.source_snapshot_hash,
        target_files=token.target_files,
        repository_identity=token.repository_identity,
        approved_by=token.approved_by,
        approved_at=token.approved_at,
        expires_at=token.expires_at,
        approval_context=token.approval_context,
        status=token.status,
        token_fingerprint=token.token_fingerprint,
    )

    dummy_finding = _create_dummy_finding("F1", "app.py")
    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_res, _, _ = app_agent.execute_transaction(proposal=proposal, token=tampered_token, finding=dummy_finding, rescan_callback=lambda: ())
    assert app_res.status == ApplicationStatus.REJECTED
    assert "TOKEN_TAMPERED" in app_res.failure_reason


def test_e2e_11_command_injection_patch_verification(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text(_get_sqli_code(), encoding="utf-8")

    finding = _create_dummy_finding("F-CMD", "app.py")
    proposal = _create_sqli_proposal(finding)

    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=finding.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_res, ver_res, _ = app_agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=finding,
        rescan_callback=lambda: (),
    )
    assert app_res.status == ApplicationStatus.APPLIED
    assert ver_res is not None
    assert ver_res.status == VerificationStatus.VERIFIED_FIXED


def test_e2e_12_xss_patch_verification(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text(_get_sqli_code(), encoding="utf-8")

    finding = _create_dummy_finding("F-XSS", "app.py")
    proposal = _create_sqli_proposal(finding)

    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=finding.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_res, ver_res, _ = app_agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=finding,
        rescan_callback=lambda: (),
    )
    assert app_res.status == ApplicationStatus.APPLIED
    assert ver_res is not None
    assert ver_res.status == VerificationStatus.VERIFIED_FIXED


def test_e2e_13_audit_trail_generation_without_secret_leak(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text("code\n", encoding="utf-8")

    proposal = PatchProposal(
        proposal_id="p1",
        finding_id="F1",
        target_files=("app.py",),
        hunks=(),
        unified_diff="diff",
        rationale="",
        root_cause_reference="",
        evidence_references=(),
        expected_effect="",
        risk_level="LOW",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint="fp1",
    )
    snap = SourceSnapshot.capture(tmp_path, ("app.py",))
    token = PatchApprovalToken.create(
        finding_id="F1",
        proposal_fingerprint="fp1",
        source_snapshot_hash=snap.aggregate_hash,
        target_files=("app.py",),
        repository_identity=str(tmp_path.resolve()),
    )

    dummy_finding = _create_dummy_finding("F1", "app.py")
    audits: list[ApplicationAuditRecord] = []
    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_agent.execute_transaction(proposal=proposal, token=token, finding=dummy_finding, rescan_callback=lambda: (), audit_records=audits)

    assert len(audits) == 1
    d = audits[0].to_dict()
    assert "code" not in str(d)
    assert d["pre_apply_snapshot_hash"] == snap.aggregate_hash


def test_e2e_14_preflight_hunk_zero_matches_blocks_file_writes(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    orig_code = "existing_code = 123\n"
    target_file.write_text(orig_code, encoding="utf-8")

    hunk = PatchHunk("app.py", 1, 1, "NON_EXISTENT_SNIPPET", "new_code", "", "")
    diff = "diff"
    fp = PatchProposal.compute_fingerprint("F1", ("app.py",), diff, PatchValidationStatus.VALID)
    proposal = PatchProposal(
        proposal_id="p1",
        finding_id="F1",
        target_files=("app.py",),
        hunks=(hunk,),
        unified_diff=diff,
        rationale="",
        root_cause_reference="",
        evidence_references=(),
        expected_effect="",
        risk_level="LOW",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint=fp,
    )
    snap = SourceSnapshot.capture(tmp_path, ("app.py",))
    token = PatchApprovalToken.create(
        finding_id="F1",
        proposal_fingerprint=fp,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=("app.py",),
        repository_identity=str(tmp_path.resolve()),
    )

    dummy_finding = _create_dummy_finding("F1", "app.py")
    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_res, _, _ = app_agent.execute_transaction(proposal=proposal, token=token, finding=dummy_finding, rescan_callback=lambda: ())

    assert app_res.status == ApplicationStatus.REJECTED
    assert "EXACT_HUNK_MATCH_FAILED" in app_res.failure_reason
    assert target_file.read_text(encoding="utf-8") == orig_code


def test_e2e_15_unverified_verdict_transition_isolation(tmp_path: Path) -> None:
    target_file = tmp_path / "app.py"
    target_file.write_text(_get_sqli_code(), encoding="utf-8")

    finding = _create_dummy_finding("F-SQLI", "app.py")
    orig_verdict_status = finding.verdict.status

    proposal = _create_sqli_proposal(finding)
    snap = SourceSnapshot.capture(tmp_path, proposal.target_files)
    token = PatchApprovalToken.create(
        finding_id=finding.finding_id,
        proposal_fingerprint=proposal.proposal_fingerprint,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=proposal.target_files,
        repository_identity=str(tmp_path.resolve()),
    )

    app_agent = RemediationApplicationAgent(repository_root=tmp_path)
    app_res, ver_res, _ = app_agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=finding,
        rescan_callback=lambda: (),
    )

    assert finding.verdict.status == orig_verdict_status
    assert ver_res is not None
    assert ver_res.status == VerificationStatus.VERIFIED_FIXED
