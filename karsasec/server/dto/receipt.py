"""Verification Receipt DTOs for KarsaSec REST API.

Response model for GET /api/v1/remediations/{id}/receipt.
The receipt is retrieved from the F0 RTP subsystem — the API
does NOT compute its own security verdict.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class VerificationReceiptResponseDTO(BaseModel):
    """Privacy-safe Verification Receipt response.

    All fingerprints are SHA-256 hex digests derived deterministically
    by the F0 canonical engine.
    """

    receipt_version: str = Field(default="1.0", description="Receipt schema version.")
    receipt_id: str = Field(..., description="Unique receipt identifier.")
    transaction_id: str = Field(..., description="Associated remediation transaction ID.")
    finding_id: str = Field(..., description="Finding identifier.")
    rule_id: str = Field(default="", description="Detection rule identifier.")
    integrity_status: str = Field(..., description="VALID | INVALID.")
    security_verification_status: str = Field(
        ...,
        description="SECURITY_VERIFIED | SECURITY_NOT_VERIFIED. Derived exclusively by RTPValidator.",
    )
    verification_run_id: str | None = Field(default=None, description="SAST rescan run identifier.")
    matching_findings_count: int | None = Field(default=None, description="Post-rescan matching findings.")
    proposal_fingerprint: str | None = Field(default=None, description="Proposal commitment SHA-256.")
    provenance_fingerprint: str | None = Field(default=None, description="Provenance graph SHA-256.")
    ledger_fingerprint: str | None = Field(default=None, description="Audit ledger SHA-256.")
    receipt_fingerprint: str = Field(..., description="SHA-256 of canonical receipt payload.")
