"""Remediation DTOs for KarsaSec REST API.

Request and response models for /api/v1/remediations endpoints.
Security verification status is OUTPUT-ONLY — never accepted from client input.
Raw source code, unified diffs, and credentials are never exposed.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ApprovalTokenInputDTO(BaseModel):
    """Client-supplied approval token reference."""

    approval_token_id: str = Field(..., description="Approval token identifier.")
    token: str = Field(..., description="Approval token credential.")


class RemediationRequestDTO(BaseModel):
    """Request DTO for POST /api/v1/remediations.

    Note: ``security_verification_status`` is NOT an input field.
    It is computed exclusively by the E13/F0 verification engine.
    """

    finding_id: str = Field(..., description="ID of the finding to remediate.")
    approval: ApprovalTokenInputDTO = Field(..., description="Approval token binding.")


class RemediationResponseDTO(BaseModel):
    """Response DTO for remediation transaction results.

    All fields are privacy-safe metadata.  No source code, diffs, or
    credentials are ever included.

    ``security_verification_status`` is OUTPUT-ONLY and determined
    exclusively by RTPValidator based on deterministic SAST rescan.
    """

    transaction_id: str = Field(..., description="Unique remediation transaction identifier.")
    finding_id: str = Field(..., description="Finding identifier that was remediated.")
    state: str = Field(..., description="Current lifecycle state.")
    integrity_status: str = Field(..., description="RTP integrity check result (VALID | INVALID).")
    security_verification_status: str = Field(
        ...,
        description="Security verification status (SECURITY_VERIFIED | SECURITY_NOT_VERIFIED). OUTPUT-ONLY.",
    )
    verification_run_id: str | None = Field(default=None, description="Verification run identifier.")
    receipt_fingerprint: str | None = Field(default=None, description="SHA-256 receipt fingerprint.")
    provenance_fingerprint: str | None = Field(default=None, description="Provenance graph fingerprint.")
    ledger_fingerprint: str | None = Field(default=None, description="Audit ledger fingerprint.")
