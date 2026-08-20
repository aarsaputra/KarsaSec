"""Receipt Application Service for KarsaSec REST API.

Pure application service — no HTTP code, no FastAPI dependency, no Request object.
Retrieves VerificationReceipt objects from RemediationService and maps to DTOs.
"""

from __future__ import annotations

from karsasec.server.dto.receipt import VerificationReceiptResponseDTO
from karsasec.server.services.remediation_service import RemediationService


class ReceiptService:
    """Application service for retrieving cryptographic verification receipts."""

    def __init__(self, remediation_service: RemediationService) -> None:
        self._remediation_service = remediation_service

    def get_receipt(self, transaction_id: str) -> VerificationReceiptResponseDTO | None:
        """Retrieve the VerificationReceipt for a completed transaction and map to DTO."""
        receipt = self._remediation_service.get_receipt(transaction_id)
        if not receipt:
            return None
        return VerificationReceiptResponseDTO(
            receipt_version=receipt.receipt_version,
            receipt_id=receipt.receipt_id,
            transaction_id=receipt.transaction_id,
            finding_id=receipt.finding_id,
            rule_id=receipt.rule_id,
            integrity_status=str(receipt.integrity_status),
            security_verification_status=str(receipt.security_verification_status),
            verification_run_id=receipt.verification_run_id,
            matching_findings_count=receipt.matching_findings_count,
            proposal_fingerprint=receipt.proposal_fingerprint,
            provenance_fingerprint=receipt.provenance_fingerprint,
            ledger_fingerprint=receipt.ledger_fingerprint,
            receipt_fingerprint=receipt.receipt_fingerprint,
        )
