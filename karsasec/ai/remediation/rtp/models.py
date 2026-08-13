"""Immutable Domain Models for RTP Subsystem (Sprint F0).

Defines component commitments, Remediation Transaction Package (RTP), and validation results.
Enforces Invariants:
  - L7: Zero LLM Security Authority (AI cannot grant VERIFIED_FIXED).
  - R1-R6: Immutability and Canonical Fingerprinting.
  - R7-R9: Privacy Boundary (Zero raw source code, zero raw patch diffs, zero credentials).
  - Integrity vs. Security Truth separation.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from karsasec.ai.remediation.rtp.canonical import compute_canonical_hash

RTP_SCHEMA_NAME: str = "karsasec-remediation-transaction"
RTP_SCHEMA_VERSION: str = "1.0"


class IntegrityStatus(StrEnum):
    """Cryptographic integrity status for an RTP artifact."""

    VALID = "VALID"
    INVALID = "INVALID"


class SecurityVerificationStatus(StrEnum):
    """Deterministic security verification status for a remediated finding."""

    SECURITY_VERIFIED = "SECURITY_VERIFIED"
    SECURITY_NOT_VERIFIED = "SECURITY_NOT_VERIFIED"


@dataclass(frozen=True, slots=True)
class FindingCommitment:
    """Immutable commitment to SAST finding metadata (Privacy-safe: no raw source code)."""

    finding_id: str
    rule_id: str
    severity: str
    cwe: str
    file_path: str
    line_number: int
    finding_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "cwe": self.cwe,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "finding_fingerprint": self.finding_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class EvidenceCommitment:
    """Immutable commitment to SAST evidence context."""

    evidence_count: int
    evidence_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_count": self.evidence_count,
            "evidence_fingerprint": self.evidence_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class RootCauseCommitment:
    """Immutable commitment to Root Cause Analysis (RCA)."""

    rca_category: str
    confidence: float
    rca_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rca_category": self.rca_category,
            "confidence": self.confidence,
            "rca_fingerprint": self.rca_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class StrategyCommitment:
    """Immutable commitment to Remediation Strategy."""

    strategy_type: str
    target_file: str
    strategy_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "strategy_type": self.strategy_type,
            "target_file": self.target_file,
            "strategy_fingerprint": self.strategy_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class ProposalCommitment:
    """Immutable commitment to Patch Proposal (Privacy-safe: zero raw diff text or hunks)."""

    proposal_id: str
    risk_level: str
    target_files: tuple[str, ...]
    proposal_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "risk_level": self.risk_level,
            "target_files": list(self.target_files),
            "proposal_fingerprint": self.proposal_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class ApprovalCommitment:
    """Immutable commitment to Approval Token."""

    approval_token_id: str
    approver: str
    approval_status: str
    approval_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "approval_token_id": self.approval_token_id,
            "approver": self.approver,
            "approval_status": self.approval_status,
            "approval_fingerprint": self.approval_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class ApplicationCommitment:
    """Immutable commitment to Source Snapshot & Application Result."""

    source_snapshot_hash: str
    post_apply_snapshot_hash: str
    application_status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_snapshot_hash": self.source_snapshot_hash,
            "post_apply_snapshot_hash": self.post_apply_snapshot_hash,
            "application_status": self.application_status,
        }


@dataclass(frozen=True, slots=True)
class VerificationCommitment:
    """Immutable commitment to Post-Apply Security Rescan Result."""

    verification_run_id: str
    status: str
    matching_findings_count: int
    verification_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "verification_run_id": self.verification_run_id,
            "status": self.status,
            "matching_findings_count": self.matching_findings_count,
            "verification_fingerprint": self.verification_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class ProvenanceCommitment:
    """Immutable commitment to Provenance Graph DAG."""

    graph_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {"graph_fingerprint": self.graph_fingerprint}


@dataclass(frozen=True, slots=True)
class AuditCommitment:
    """Immutable commitment to Append-Only Audit Ledger."""

    ledger_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {"ledger_fingerprint": self.ledger_fingerprint}


@dataclass(frozen=True, slots=True)
class RemediationTransactionPackage:
    """Authoritative, portable, privacy-safe Remediation Transaction Package (RTP)."""

    schema_name: str
    schema_version: str
    transaction_id: str
    repository_identity: str
    created_at: str
    status: str
    finding: FindingCommitment
    evidence: EvidenceCommitment | None
    root_cause: RootCauseCommitment | None
    strategy: StrategyCommitment | None
    proposal: ProposalCommitment | None
    approval: ApprovalCommitment | None
    application: ApplicationCommitment | None
    verification: VerificationCommitment | None
    provenance: ProvenanceCommitment
    audit: AuditCommitment
    receipt_fingerprint: str

    @staticmethod
    def compute_package_fingerprint(
        schema_name: str,
        schema_version: str,
        transaction_id: str,
        repository_identity: str,
        created_at: str,
        status: str,
        finding: FindingCommitment,
        evidence: EvidenceCommitment | None,
        root_cause: RootCauseCommitment | None,
        strategy: StrategyCommitment | None,
        proposal: ProposalCommitment | None,
        approval: ApprovalCommitment | None,
        application: ApplicationCommitment | None,
        verification: VerificationCommitment | None,
        provenance: ProvenanceCommitment,
        audit: AuditCommitment,
    ) -> str:
        """Compute canonical SHA-256 package fingerprint over all components."""
        payload = {
            "schema_name": schema_name,
            "schema_version": schema_version,
            "transaction_id": transaction_id,
            "repository_identity": repository_identity.replace("\\", "/").rstrip("/"),
            "created_at": created_at,
            "status": status,
            "finding": finding.to_dict(),
            "evidence": evidence.to_dict() if evidence else None,
            "root_cause": root_cause.to_dict() if root_cause else None,
            "strategy": strategy.to_dict() if strategy else None,
            "proposal": proposal.to_dict() if proposal else None,
            "approval": approval.to_dict() if approval else None,
            "application": application.to_dict() if application else None,
            "verification": verification.to_dict() if verification else None,
            "provenance": provenance.to_dict(),
            "audit": audit.to_dict(),
        }
        return compute_canonical_hash(payload)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_name": self.schema_name,
            "schema_version": self.schema_version,
            "transaction_id": self.transaction_id,
            "repository_identity": self.repository_identity,
            "created_at": self.created_at,
            "status": self.status,
            "finding": self.finding.to_dict(),
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "root_cause": self.root_cause.to_dict() if self.root_cause else None,
            "strategy": self.strategy.to_dict() if self.strategy else None,
            "proposal": self.proposal.to_dict() if self.proposal else None,
            "approval": self.approval.to_dict() if self.approval else None,
            "application": self.application.to_dict() if self.application else None,
            "verification": self.verification.to_dict() if self.verification else None,
            "provenance": self.provenance.to_dict(),
            "audit": self.audit.to_dict(),
            "receipt_fingerprint": self.receipt_fingerprint,
        }


@dataclass(frozen=True, slots=True)
class RTPValidationResult:
    """Immutable validation output separating integrity from security truth."""

    is_valid: bool
    integrity_status: IntegrityStatus
    security_verification_status: SecurityVerificationStatus
    errors: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_valid": self.is_valid,
            "integrity_status": str(self.integrity_status),
            "security_verification_status": str(self.security_verification_status),
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }
