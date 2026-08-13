"""Unit tests for RTP Validator Engine (Sprint F0)."""

from __future__ import annotations


from karsasec.ai.remediation.rtp.models import (
    ApplicationCommitment,
    AuditCommitment,
    FindingCommitment,
    IntegrityStatus,
    ProposalCommitment,
    ProvenanceCommitment,
    RTP_SCHEMA_NAME,
    RTP_SCHEMA_VERSION,
    RemediationTransactionPackage,
    SecurityVerificationStatus,
    StrategyCommitment,
    VerificationCommitment,
)
from karsasec.ai.remediation.rtp.validator import RTPValidator


def _build_valid_rtp(
    verification_status: str = "VERIFIED_FIXED",
    matching_findings_count: int = 0,
) -> RemediationTransactionPackage:
    finding = FindingCommitment(
        finding_id="F-100",
        rule_id="KS-PY-SQL-001",
        severity="HIGH",
        cwe="CWE-89",
        file_path="app/db.py",
        line_number=42,
        finding_fingerprint="fp_finding_123",
    )
    strat = StrategyCommitment(
        strategy_type="ADD_PARAMETERIZATION",
        target_file="app/db.py",
        strategy_fingerprint="fp_strat_000",
    )
    prop = ProposalCommitment(
        proposal_id="prop_100",
        risk_level="LOW",
        target_files=("app/db.py",),
        proposal_fingerprint="fp_prop_100",
    )
    app = ApplicationCommitment(
        source_snapshot_hash="src_sha_111",
        post_apply_snapshot_hash="post_sha_222",
        application_status="APPLIED",
    )
    ver = VerificationCommitment(
        verification_run_id="ver_999",
        status=verification_status,
        matching_findings_count=matching_findings_count,
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
        strategy=strat,
        proposal=prop,
        approval=None,
        application=app,
        verification=ver,
        provenance=prov,
        audit=audit,
    )

    return RemediationTransactionPackage(
        schema_name=RTP_SCHEMA_NAME,
        schema_version=RTP_SCHEMA_VERSION,
        transaction_id="tx_001",
        repository_identity="repo:test/project",
        created_at="2026-08-13T12:00:00Z",
        status="VERIFIED_FIXED",
        finding=finding,
        evidence=None,
        root_cause=None,
        strategy=strat,
        proposal=prop,
        approval=None,
        application=app,
        verification=ver,
        provenance=prov,
        audit=audit,
        receipt_fingerprint=pkg_fp,
    )


def test_validator_valid_rtp() -> None:
    rtp = _build_valid_rtp()
    res = RTPValidator.validate(rtp)

    assert res.is_valid is True
    assert res.integrity_status == IntegrityStatus.VALID
    assert res.security_verification_status == SecurityVerificationStatus.SECURITY_VERIFIED
    assert len(res.errors) == 0


def test_validator_unverified_rtp_gives_security_not_verified() -> None:
    rtp = _build_valid_rtp(verification_status="STILL_VULNERABLE", matching_findings_count=1)
    res = RTPValidator.validate(rtp)

    assert res.is_valid is True
    assert res.integrity_status == IntegrityStatus.VALID
    assert res.security_verification_status == SecurityVerificationStatus.SECURITY_NOT_VERIFIED


def test_validator_tampered_fingerprint_gives_integrity_invalid() -> None:
    valid_rtp = _build_valid_rtp()
    tampered_rtp = RemediationTransactionPackage(
        schema_name=valid_rtp.schema_name,
        schema_version=valid_rtp.schema_version,
        transaction_id=valid_rtp.transaction_id,
        repository_identity=valid_rtp.repository_identity,
        created_at=valid_rtp.created_at,
        status=valid_rtp.status,
        finding=valid_rtp.finding,
        evidence=valid_rtp.evidence,
        root_cause=valid_rtp.root_cause,
        strategy=valid_rtp.strategy,
        proposal=valid_rtp.proposal,
        approval=valid_rtp.approval,
        application=valid_rtp.application,
        verification=valid_rtp.verification,
        provenance=valid_rtp.provenance,
        audit=valid_rtp.audit,
        receipt_fingerprint="0" * 64,  # Bad fingerprint
    )

    res = RTPValidator.validate(tampered_rtp)

    assert res.is_valid is False
    assert res.integrity_status == IntegrityStatus.INVALID
    assert res.security_verification_status == SecurityVerificationStatus.SECURITY_NOT_VERIFIED
    assert any("fingerprint tampering" in e for e in res.errors)
