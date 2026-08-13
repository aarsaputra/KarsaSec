"""Unit tests for RemediationApplicationAgent orchestrator (Sprint E13-4)."""

from __future__ import annotations

from pathlib import Path

from karsasec.ai.remediation.application_agent import ApplicationAuditRecord, RemediationApplicationAgent
from karsasec.ai.remediation.applier import ApplicationStatus
from karsasec.ai.remediation.approval import PatchApprovalToken
from karsasec.ai.remediation.models import PatchHunk, PatchProposal, PatchValidationStatus
from karsasec.ai.remediation.snapshot import SourceSnapshot
from karsasec.ai.remediation.verification import VerificationStatus
from karsasec.core.finding.evidence import Evidence
from karsasec.core.finding.model import Finding
from karsasec.graph.dataflow.security_verdict import DecisionReason, SecurityVerdict, VerdictConfidence, VerdictStatus
from karsasec.rules.enums import Confidence, Severity


def _create_agent_test_setup(tmp_path: Path) -> tuple[Finding, PatchProposal, SourceSnapshot, PatchApprovalToken]:
    src_file = tmp_path / "app.py"
    src_file.write_text("cursor.execute('SELECT * FROM users WHERE name=' + name)\n", encoding="utf-8")

    v = SecurityVerdict.create(
        status=VerdictStatus.VULNERABLE,
        confidence=VerdictConfidence.HIGH,
        rule_id="CWE-89-SQLI",
        sink_id="sink_01",
        sink_category="SQL_EXECUTION",
        file_path="app.py",
        function_name="query",
        line_number=1,
        variable_version="$name#1",
        call_context="GLOBAL",
        branch_polarity="UNKNOWN",
        reason_codes=(DecisionReason.TAINT_REACHES_SINK,),
        provenance_path=("app.py:1",),
    )
    finding = Finding(
        finding_id="F-401",
        rule_id="CWE-89-SQLI",
        fingerprint="fp_401",
        title="SQLi",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        cwe_id="CWE-89",
        owasp="A03:2021",
        file_path=Path("app.py"),
        evidence=Evidence(snippet="cursor.execute(...)", line=1, column=1),
        description="SQLi",
        remediation="Parametrize",
        verdict=v,
    )

    hunk = PatchHunk(
        file_path="app.py",
        start_line=1,
        end_line=1,
        original_text="cursor.execute('SELECT * FROM users WHERE name=' + name)",
        proposed_text="cursor.execute('SELECT * FROM users WHERE name=?', (name,))",
        context="",
        evidence_reference="app.py:1",
    )
    diff = "--- a/app.py\n+++ b/app.py\n@@ -1,1 +1,1 @@\n-orig\n+prop\n"
    fp = PatchProposal.compute_fingerprint("F-401", ("app.py",), diff, PatchValidationStatus.VALID)
    proposal = PatchProposal(
        proposal_id="prop_401",
        finding_id="F-401",
        target_files=("app.py",),
        hunks=(hunk,),
        unified_diff=diff,
        rationale="Fix SQLi",
        root_cause_reference="RCA-401",
        evidence_references=("app.py:1",),
        expected_effect="Safe",
        risk_level="LOW",
        assumptions=(),
        validation_status=PatchValidationStatus.VALID,
        proposal_fingerprint=fp,
    )

    snap = SourceSnapshot.capture(tmp_path, ("app.py",))
    token = PatchApprovalToken.create(
        finding_id="F-401",
        proposal_fingerprint=fp,
        source_snapshot_hash=snap.aggregate_hash,
        target_files=("app.py",),
        repository_identity=str(tmp_path.resolve()),
    )

    return finding, proposal, snap, token


def test_01_successful_end_to_end_application_transaction(tmp_path: Path) -> None:
    finding, proposal, snap, token = _create_agent_test_setup(tmp_path)
    agent = RemediationApplicationAgent(repository_root=tmp_path)
    audits: list[ApplicationAuditRecord] = []

    # SAST rescan returns empty tuple (vulnerability fixed)
    def rescan_cb():
        return ()

    app_res, ver_res, used_tok = agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=finding,
        rescan_callback=rescan_cb,
        audit_records=audits,
    )

    assert app_res.status == ApplicationStatus.APPLIED
    assert ver_res is not None
    assert ver_res.status == VerificationStatus.VERIFIED_FIXED
    assert used_tok.status.value == "USED"
    assert len(audits) == 1
    assert audits[0].verification_status == VerificationStatus.VERIFIED_FIXED


def test_02_verification_failure_triggers_automatic_atomic_rollback(tmp_path: Path) -> None:
    finding, proposal, snap, token = _create_agent_test_setup(tmp_path)
    agent = RemediationApplicationAgent(repository_root=tmp_path)
    audits: list[ApplicationAuditRecord] = []

    # SAST rescan returns the finding again (still vulnerable)
    def rescan_cb():
        return (finding,)

    app_res, ver_res, _ = agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=finding,
        rescan_callback=rescan_cb,
        audit_records=audits,
    )

    # Assert status was ROLLED_BACK
    assert app_res.status == ApplicationStatus.ROLLED_BACK
    assert ver_res is not None
    assert ver_res.status == VerificationStatus.STILL_VULNERABLE
    # Assert source file was restored to original byte state (H5)
    src_text = (tmp_path / "app.py").read_text(encoding="utf-8")
    assert "cursor.execute('SELECT * FROM users WHERE name=' + name)" in src_text


def test_03_sast_rescan_exception_triggers_rollback(tmp_path: Path) -> None:
    finding, proposal, snap, token = _create_agent_test_setup(tmp_path)
    agent = RemediationApplicationAgent(repository_root=tmp_path)

    # SAST rescan raises unexpected exception
    def rescan_cb():
        raise RuntimeError("SAST engine unavailable")

    app_res, ver_res, _ = agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=finding,
        rescan_callback=rescan_cb,
    )

    assert app_res.status == ApplicationStatus.FAILED
    assert "SAST_RESCAN_FAILED" in app_res.failure_reason


def test_04_audit_record_serialization(tmp_path: Path) -> None:
    finding, proposal, snap, token = _create_agent_test_setup(tmp_path)
    agent = RemediationApplicationAgent(repository_root=tmp_path)
    audits: list[ApplicationAuditRecord] = []

    agent.execute_transaction(
        proposal=proposal,
        token=token,
        finding=finding,
        rescan_callback=lambda: (),
        audit_records=audits,
    )

    d = audits[0].to_dict()
    assert d["finding_id"] == "F-401"
    assert d["application_status"] == "APPLIED"
    assert d["verification_status"] == "VERIFIED_FIXED"
