"""Unit tests for RTP Domain Models (Sprint F0)."""

from __future__ import annotations


from karsasec.ai.remediation.rtp.models import (
    AuditCommitment,
    FindingCommitment,
    ProvenanceCommitment,
    RTP_SCHEMA_NAME,
    RTP_SCHEMA_VERSION,
    RemediationTransactionPackage,
)


def test_finding_commitment_to_dict() -> None:
    fc = FindingCommitment(
        finding_id="F-100",
        rule_id="KS-PY-SQL-001",
        severity="HIGH",
        cwe="CWE-89",
        file_path="app/db.py",
        line_number=42,
        finding_fingerprint="fp_finding_123",
    )
    d = fc.to_dict()
    assert d["finding_id"] == "F-100"
    assert d["rule_id"] == "KS-PY-SQL-001"
    assert d["line_number"] == 42


def test_rtp_package_fingerprint_determinism() -> None:
    finding = FindingCommitment(
        finding_id="F-100",
        rule_id="KS-PY-SQL-001",
        severity="HIGH",
        cwe="CWE-89",
        file_path="app/db.py",
        line_number=42,
        finding_fingerprint="fp_finding_123",
    )
    prov = ProvenanceCommitment(graph_fingerprint="fp_prov_456")
    audit = AuditCommitment(ledger_fingerprint="fp_audit_789")

    fp_1 = RemediationTransactionPackage.compute_package_fingerprint(
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
        verification=None,
        provenance=prov,
        audit=audit,
    )

    fp_2 = RemediationTransactionPackage.compute_package_fingerprint(
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
        verification=None,
        provenance=prov,
        audit=audit,
    )

    assert fp_1 == fp_2
    assert len(fp_1) == 64
