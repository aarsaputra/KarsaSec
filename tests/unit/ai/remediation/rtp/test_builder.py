"""Unit tests for RemediationTransactionPackageBuilder (Sprint F0)."""

from __future__ import annotations

from unittest.mock import MagicMock

from karsasec.ai.remediation.lifecycle import RemediationLifecycleResult
from karsasec.ai.remediation.rtp.builder import RemediationTransactionPackageBuilder
from karsasec.ai.remediation.rtp.models import (
    RemediationTransactionPackage,
)
from karsasec.ai.remediation.state_machine import RemediationLifecycleState


def test_builder_extracts_commitments() -> None:
    mock_finding = MagicMock()
    mock_finding.finding_id = "F-100"
    mock_finding.rule_id = "KS-PY-SQL-001"
    mock_finding.file_path = "app/db.py"
    mock_finding.severity = "HIGH"
    mock_finding.cwe_id = "CWE-89"
    mock_finding.fingerprint = "fp_finding_100"
    mock_finding.evidence = MagicMock(line=42)

    mock_proposal = MagicMock()
    mock_proposal.proposal_id = "prop_123"
    mock_proposal.risk_level = "LOW"
    mock_proposal.target_files = ("app/db.py",)
    mock_proposal.proposal_fingerprint = "fp_proposal_abc"

    mock_token = MagicMock()
    mock_token.token_id = "tok_456"
    mock_token.approved_by = "sec_admin"
    mock_token.status = "APPROVED"
    mock_token.token_fingerprint = "fp_token_def"

    mock_src_snap = MagicMock()
    mock_src_snap.aggregate_hash = "sha256_src_111"

    mock_app_res = MagicMock()
    mock_app_res.status = "APPLIED"
    mock_app_res.post_apply_snapshot = MagicMock(snapshot_hash="sha256_post_222")

    mock_ver_res = MagicMock()
    mock_ver_res.verification_id = "ver_789"
    mock_ver_res.status = "VERIFIED_FIXED"
    mock_ver_res.matching_findings_count = 0
    mock_ver_res.verification_fingerprint = "fp_ver_333"

    mock_prov = MagicMock()
    mock_prov.graph_fingerprint = "fp_graph_444"

    mock_ledger = MagicMock()
    mock_ledger.ledger_fingerprint = "fp_ledger_555"

    lifecycle_result = RemediationLifecycleResult(
        finding_id="F-100",
        current_state=RemediationLifecycleState.VERIFIED_FIXED,
        repository_identity="repo:test/project",
        finding=mock_finding,
        proposal=mock_proposal,
        approval_token=mock_token,
        source_snapshot=mock_src_snap,
        application_result=mock_app_res,
        verification_result=mock_ver_res,
        provenance_graph=mock_prov,
        ledger=mock_ledger,
    )

    rtp = RemediationTransactionPackageBuilder.build(
        lifecycle_result=lifecycle_result,
        transaction_id="RTP-TEST-001",
        created_at="2026-08-13T12:00:00Z",
    )

    assert isinstance(rtp, RemediationTransactionPackage)
    assert rtp.transaction_id == "RTP-TEST-001"
    assert rtp.status == "VERIFIED_FIXED"
    assert rtp.finding.finding_id == "F-100"
    assert rtp.finding.rule_id == "KS-PY-SQL-001"
    assert rtp.proposal.proposal_id == "prop_123" if rtp.proposal else False
    assert rtp.application.source_snapshot_hash == "sha256_src_111" if rtp.application else False
    assert rtp.verification.verification_run_id == "ver_789" if rtp.verification else False
    assert len(rtp.receipt_fingerprint) == 64
