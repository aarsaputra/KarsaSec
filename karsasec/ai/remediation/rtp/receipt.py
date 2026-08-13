"""Verification Receipt Model & Derivation Engine (Sprint F0).

Derives an immutable, portable Verification Receipt binding transaction evidence commitments.
Enforces Invariant L7: Zero LLM Security Authority.
Separates cryptographic integrity status from deterministic security verification status.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
import uuid

from karsasec.ai.remediation.rtp.canonical import compute_canonical_hash
from karsasec.ai.remediation.rtp.models import (
    IntegrityStatus,
    RemediationTransactionPackage,
    RTPValidationResult,
    SecurityVerificationStatus,
)


@dataclass(frozen=True, slots=True)
class VerificationReceipt:
    """Concise, cryptographically bound security verification receipt."""

    receipt_version: str
    receipt_id: str
    transaction_id: str
    repository_identity: str
    finding_id: str
    rule_id: str
    proposal_fingerprint: str | None
    approval_token_id: str | None
    source_snapshot_hash: str | None
    post_apply_snapshot_hash: str | None
    verification_run_id: str | None
    verification_fingerprint: str | None
    provenance_fingerprint: str
    ledger_fingerprint: str
    integrity_status: IntegrityStatus
    security_verification_status: SecurityVerificationStatus
    matching_findings_count: int
    receipt_fingerprint: str

    @staticmethod
    def compute_receipt_fingerprint(
        receipt_version: str,
        receipt_id: str,
        transaction_id: str,
        repository_identity: str,
        finding_id: str,
        rule_id: str,
        proposal_fingerprint: str | None,
        approval_token_id: str | None,
        source_snapshot_hash: str | None,
        post_apply_snapshot_hash: str | None,
        verification_run_id: str | None,
        verification_fingerprint: str | None,
        provenance_fingerprint: str,
        ledger_fingerprint: str,
        integrity_status: IntegrityStatus | str,
        security_verification_status: SecurityVerificationStatus | str,
        matching_findings_count: int,
    ) -> str:
        """Computes deterministic SHA-256 fingerprint over receipt commitments."""
        payload = {
            "receipt_version": receipt_version,
            "receipt_id": receipt_id,
            "transaction_id": transaction_id,
            "repository_identity": repository_identity.replace("\\", "/").rstrip("/"),
            "finding_id": finding_id,
            "rule_id": rule_id,
            "proposal_fingerprint": proposal_fingerprint,
            "approval_token_id": approval_token_id,
            "source_snapshot_hash": source_snapshot_hash,
            "post_apply_snapshot_hash": post_apply_snapshot_hash,
            "verification_run_id": verification_run_id,
            "verification_fingerprint": verification_fingerprint,
            "provenance_fingerprint": provenance_fingerprint,
            "ledger_fingerprint": ledger_fingerprint,
            "integrity_status": str(integrity_status),
            "security_verification_status": str(security_verification_status),
            "matching_findings_count": matching_findings_count,
        }
        return compute_canonical_hash(payload)

    @classmethod
    def from_rtp(
        cls,
        rtp: RemediationTransactionPackage,
        validation_result: RTPValidationResult,
        receipt_id: str | None = None,
    ) -> VerificationReceipt:
        """Derives a VerificationReceipt from a validated RTP."""
        rec_id = receipt_id or f"RCP-{uuid.uuid4().hex[:12]}"
        proposal_fp = rtp.proposal.proposal_fingerprint if rtp.proposal else None
        approval_id = rtp.approval.approval_token_id if rtp.approval else None
        src_hash = rtp.application.source_snapshot_hash if rtp.application else None
        post_hash = rtp.application.post_apply_snapshot_hash if rtp.application else None
        ver_run_id = rtp.verification.verification_run_id if rtp.verification else None
        ver_fp = rtp.verification.verification_fingerprint if rtp.verification else None
        match_count = rtp.verification.matching_findings_count if rtp.verification else -1

        receipt_fp = cls.compute_receipt_fingerprint(
            receipt_version="1.0",
            receipt_id=rec_id,
            transaction_id=rtp.transaction_id,
            repository_identity=rtp.repository_identity,
            finding_id=rtp.finding.finding_id,
            rule_id=rtp.finding.rule_id,
            proposal_fingerprint=proposal_fp,
            approval_token_id=approval_id,
            source_snapshot_hash=src_hash,
            post_apply_snapshot_hash=post_hash,
            verification_run_id=ver_run_id,
            verification_fingerprint=ver_fp,
            provenance_fingerprint=rtp.provenance.graph_fingerprint,
            ledger_fingerprint=rtp.audit.ledger_fingerprint,
            integrity_status=validation_result.integrity_status,
            security_verification_status=validation_result.security_verification_status,
            matching_findings_count=match_count,
        )

        return cls(
            receipt_version="1.0",
            receipt_id=rec_id,
            transaction_id=rtp.transaction_id,
            repository_identity=rtp.repository_identity,
            finding_id=rtp.finding.finding_id,
            rule_id=rtp.finding.rule_id,
            proposal_fingerprint=proposal_fp,
            approval_token_id=approval_id,
            source_snapshot_hash=src_hash,
            post_apply_snapshot_hash=post_hash,
            verification_run_id=ver_run_id,
            verification_fingerprint=ver_fp,
            provenance_fingerprint=rtp.provenance.graph_fingerprint,
            ledger_fingerprint=rtp.audit.ledger_fingerprint,
            integrity_status=validation_result.integrity_status,
            security_verification_status=validation_result.security_verification_status,
            matching_findings_count=match_count,
            receipt_fingerprint=receipt_fp,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt_version": self.receipt_version,
            "receipt_id": self.receipt_id,
            "transaction_id": self.transaction_id,
            "repository_identity": self.repository_identity,
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "proposal_fingerprint": self.proposal_fingerprint,
            "approval_token_id": self.approval_token_id,
            "source_snapshot_hash": self.source_snapshot_hash,
            "post_apply_snapshot_hash": self.post_apply_snapshot_hash,
            "verification_run_id": self.verification_run_id,
            "verification_fingerprint": self.verification_fingerprint,
            "provenance_fingerprint": self.provenance_fingerprint,
            "ledger_fingerprint": self.ledger_fingerprint,
            "integrity_status": str(self.integrity_status),
            "security_verification_status": str(self.security_verification_status),
            "matching_findings_count": self.matching_findings_count,
            "receipt_fingerprint": self.receipt_fingerprint,
        }
