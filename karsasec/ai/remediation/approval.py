"""Patch Approval Domain Models for KarsaSec AI Engine (Sprint E13-4).

Defines immutable, cryptographically bound approval tokens for patch application.

Enforces Security Invariants:
  - H1: Explicit Approval Token (Single-use, cryptographically bound).
  - H3: Cryptographic Proposal Binding (Fingerprint matching).
  - H18: Approval Context & Repository Identity Binding.
  - H19: Proposal Expiration (Rejects expired tokens).
  - H21: Approval Token is Authorization, Not Verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, UTC
from enum import StrEnum
import hashlib
from typing import Any
import uuid


class ApprovalStatus(StrEnum):
    """Lifecycle status for a patch approval token."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    USED = "USED"
    INVALIDATED = "INVALIDATED"


@dataclass(frozen=True, slots=True)
class PatchApprovalToken:
    """Immutable, cryptographically bound approval token for patch application."""

    token_id: str
    finding_id: str
    proposal_fingerprint: str
    source_snapshot_hash: str
    target_files: tuple[str, ...]
    repository_identity: str
    approved_by: str
    approved_at: str
    expires_at: str | None
    approval_context: str
    status: ApprovalStatus
    token_fingerprint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "finding_id": self.finding_id,
            "proposal_fingerprint": self.proposal_fingerprint,
            "source_snapshot_hash": self.source_snapshot_hash,
            "target_files": list(self.target_files),
            "repository_identity": self.repository_identity,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "expires_at": self.expires_at,
            "approval_context": self.approval_context,
            "status": str(self.status),
            "token_fingerprint": self.token_fingerprint,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PatchApprovalToken:
        return cls(
            token_id=data["token_id"],
            finding_id=data["finding_id"],
            proposal_fingerprint=data["proposal_fingerprint"],
            source_snapshot_hash=data["source_snapshot_hash"],
            target_files=tuple(data.get("target_files", [])),
            repository_identity=data["repository_identity"],
            approved_by=data["approved_by"],
            approved_at=data["approved_at"],
            expires_at=data.get("expires_at"),
            approval_context=data.get("approval_context", "MANUAL_REVIEW"),
            status=ApprovalStatus(data.get("status", "APPROVED")),
            token_fingerprint=data["token_fingerprint"],
        )

    @staticmethod
    def compute_fingerprint(
        token_id: str,
        finding_id: str,
        proposal_fingerprint: str,
        source_snapshot_hash: str,
        target_files: tuple[str, ...],
        repository_identity: str,
        approved_by: str,
        approved_at: str,
        expires_at: str | None,
        approval_context: str,
    ) -> str:
        """Compute canonical, byte-for-byte SHA-256 fingerprint for approval token."""
        sorted_files = "|".join(sorted(f.replace("\\", "/") for f in target_files))
        exp_str = expires_at or "NEVER"
        norm_repo = repository_identity.replace("\\", "/")
        raw = (
            f"{token_id}|{finding_id}|{proposal_fingerprint}|{source_snapshot_hash}|"
            f"{sorted_files}|{norm_repo}|{approved_by}|{approved_at}|{exp_str}|{approval_context}"
        )
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        finding_id: str,
        proposal_fingerprint: str,
        source_snapshot_hash: str,
        target_files: tuple[str, ...],
        repository_identity: str,
        approved_by: str = "security_reviewer",
        expires_at: str | None = None,
        approval_context: str = "HUMAN_APPROVED",
        token_id: str | None = None,
        approved_at: str | None = None,
    ) -> PatchApprovalToken:
        """Factory method to construct a valid, cryptographically bound PatchApprovalToken."""
        tid = token_id or f"tok_{uuid.uuid4().hex[:12]}"
        now_iso = approved_at or datetime.now(UTC).isoformat()
        fp = cls.compute_fingerprint(
            token_id=tid,
            finding_id=finding_id,
            proposal_fingerprint=proposal_fingerprint,
            source_snapshot_hash=source_snapshot_hash,
            target_files=target_files,
            repository_identity=repository_identity,
            approved_by=approved_by,
            approved_at=now_iso,
            expires_at=expires_at,
            approval_context=approval_context,
        )
        return cls(
            token_id=tid,
            finding_id=finding_id,
            proposal_fingerprint=proposal_fingerprint,
            source_snapshot_hash=source_snapshot_hash,
            target_files=target_files,
            repository_identity=repository_identity,
            approved_by=approved_by,
            approved_at=now_iso,
            expires_at=expires_at,
            approval_context=approval_context,
            status=ApprovalStatus.APPROVED,
            token_fingerprint=fp,
        )

    def mark_used(self) -> PatchApprovalToken:
        """Return a new PatchApprovalToken with status set irreversibly to USED."""
        if self.status == ApprovalStatus.USED:
            raise ValueError(f"Approval token '{self.token_id}' is already USED.")
        return PatchApprovalToken(
            token_id=self.token_id,
            finding_id=self.finding_id,
            proposal_fingerprint=self.proposal_fingerprint,
            source_snapshot_hash=self.source_snapshot_hash,
            target_files=self.target_files,
            repository_identity=self.repository_identity,
            approved_by=self.approved_by,
            approved_at=self.approved_at,
            expires_at=self.expires_at,
            approval_context=self.approval_context,
            status=ApprovalStatus.USED,
            token_fingerprint=self.token_fingerprint,
        )

    def verify_valid(
        self,
        expected_finding_id: str,
        expected_proposal_fingerprint: str,
        expected_snapshot_hash: str,
        expected_repository_identity: str,
        current_timestamp_iso: str | None = None,
    ) -> tuple[bool, str]:
        """Comprehensive cryptographic and lifecycle token verification."""
        # 1. Status Check
        if self.status == ApprovalStatus.USED:
            return False, "TOKEN_ALREADY_USED: Token has already been consumed."
        if self.status != ApprovalStatus.APPROVED:
            return False, f"INVALID_TOKEN_STATUS: Token status is '{self.status}', expected APPROVED."

        # 2. Cryptographic Fingerprint Verification
        expected_fp = self.compute_fingerprint(
            token_id=self.token_id,
            finding_id=self.finding_id,
            proposal_fingerprint=self.proposal_fingerprint,
            source_snapshot_hash=self.source_snapshot_hash,
            target_files=self.target_files,
            repository_identity=self.repository_identity,
            approved_by=self.approved_by,
            approved_at=self.approved_at,
            expires_at=self.expires_at,
            approval_context=self.approval_context,
        )
        if self.token_fingerprint != expected_fp:
            return False, "TOKEN_TAMPERED: Approval token fingerprint does not match computed digest."

        # 3. Finding ID Binding
        if self.finding_id != expected_finding_id:
            return False, f"FINDING_MISMATCH: Token finding_id '{self.finding_id}' != expected '{expected_finding_id}'."

        # 4. Proposal Fingerprint Binding
        if self.proposal_fingerprint != expected_proposal_fingerprint:
            return False, "PROPOSAL_FINGERPRINT_MISMATCH: Token proposal fingerprint does not match proposal."

        # 5. Snapshot Hash Binding (TOCTOU H2)
        if self.source_snapshot_hash != expected_snapshot_hash:
            return False, "SNAPSHOT_HASH_MISMATCH: Source code modified after approval (TOCTOU violation)."

        # 6. Repository Identity Binding (H18)
        norm_token_repo = self.repository_identity.replace("\\", "/").rstrip("/")
        norm_exp_repo = expected_repository_identity.replace("\\", "/").rstrip("/")
        if norm_token_repo != norm_exp_repo:
            return False, f"REPOSITORY_MISMATCH: Token repository '{norm_token_repo}' != current '{norm_exp_repo}'."

        # 7. Expiration Check (H19)
        if self.expires_at:
            now_dt = (
                datetime.fromisoformat(current_timestamp_iso)
                if current_timestamp_iso
                else datetime.now(UTC)
            )
            exp_dt = datetime.fromisoformat(self.expires_at)
            if now_dt > exp_dt:
                return False, f"TOKEN_EXPIRED: Token expired at {self.expires_at}."

        return True, "VALID"
