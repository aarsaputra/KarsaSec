"""Receipt router: GET /api/v1/remediations/{transaction_id}/receipt.

ARCHITECTURAL LAW #3: Router only validates, authenticates, authorizes, delegates, serializes.
Receipt contents are derived from F0 VerificationReceipt — the API does not compute any verdict.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from karsasec.server.dependencies import get_current_principal, get_receipt_service
from karsasec.server.dto.receipt import VerificationReceiptResponseDTO
from karsasec.server.security.authorization import authorize
from karsasec.server.security.models import Permission

router = APIRouter(tags=["receipts"])


@router.get(
    "/remediations/{transaction_id}/receipt",
    response_model=VerificationReceiptResponseDTO,
    summary="Get verification receipt",
    description=(
        "Retrieves the cryptographic F0 VerificationReceipt for a completed remediation transaction. "
        "The receipt's security_verification_status was derived exclusively by RTPValidator."
    ),
)
async def get_receipt(
    transaction_id: str,
    principal=Depends(get_current_principal),
    receipt_service=Depends(get_receipt_service),
) -> VerificationReceiptResponseDTO:
    """GET /api/v1/remediations/{transaction_id}/receipt — validate, authorize, delegate, serialize."""
    authorize(principal, Permission.RECEIPT_READ)
    result = receipt_service.get_receipt(transaction_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Verification receipt for transaction '{transaction_id}' not found.",
        )
    return result
