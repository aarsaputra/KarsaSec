"""Unit tests for Verification Receipt (Sprint F0)."""

from __future__ import annotations

from karsasec.ai.remediation.rtp.models import (
    AuditCommitment,
    FindingCommitment,
    IntegrityStatus,
    ProvenanceCommitment,
    RTP_SCHEMA_NAME,
    RTP_SCHEMA_VERSION,
    RemediationTransactionPackage,
    RTPValidationResult,
    SecurityVerificationStatus,
    VerificationCommitment,
)
from karsasec.ai.remediation.rtp.receipt import VerificationReceipt


def test_verification_receipt_from_rtp() -> None:
    finding = FindingCommitment(
        finding_id="F-100",
        rule_id="KS-PY-SQL-001",
        severity="HIGH",
        cwe="CWE-89",
        file_path="app/db.py",
        line_number=42,
        finding_fingerprint="fp_finding_123",
    )
    ver = VerificationCommitment(
        verification_run_id="ver_999",
        status="VERIFIED_FIXED",
        matching_findings_count=0,
        verification_fingerprint="fp_ver_111",
    )
    prov = ProvenanceCommitment(graph_fingerprint="fp_prov_456")
    audit = AuditCommitment(ledger_fingerprint="fp_audit_789")

    pkg_fp = RemediationTransactionPackage.compute_package_fingerprint(
        schema_name=RTP_SCHEMA_NAME,
        schema_version=RTP_SCHEMA_VERSION,
        transaction_id="tx_001",
        repository_identity="repo:test/project",
        created_at="2026-08-13T12:00:00Z",
        status="VERIFIED_FIXED",
        finding=finding,
        evidence=None,
        root_cause=None,
        strategy=None,
        proposal=None,
        approval=None,
        application=None,
        verification=ver,
        provenance=prov,
        audit=audit,
    )

    rtp = RemediationTransactionPackage(
        schema_name=RTP_SCHEMA_NAME,
        schema_version=RTP_SCHEMA_VERSION,
        transaction_id="tx_001",
        repository_identity="repo:test/project",
        created_at="2026-08-13T12:00:00Z",
        status="VERIFIED_FIXED",
        finding=finding,
        evidence=None,
        root_cause=None,
        strategy=None,
        proposal=None,
        approval=None,
        application=None,
        verification=ver,
        provenance=prov,
        audit=audit,
        receipt_fingerprint=pkg_fp,
    )

    val_res = RTPValidationResult(
        is_valid=True,
        integrity_status=IntegrityStatus.VALID,
        security_verification_status=SecurityVerificationStatus.SECURITY_VERIFIED,
    )

    receipt = VerificationReceipt.from_rtp(rtp, val_res, receipt_id="RCP-TEST-01")

    assert receipt.receipt_id == "RCP-TEST-01"
    assert receipt.transaction_id == "tx_001"
    assert receipt.integrity_status == IntegrityStatus.VALID
    assert receipt.security_verification_status == SecurityVerificationStatus.SECURITY_VERIFIED
    assert receipt.matching_findings_count == 0
    assert len(receipt.receipt_fingerprint) == 64
