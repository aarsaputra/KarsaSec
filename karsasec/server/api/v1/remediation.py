"""Remediations router: POST /api/v1/remediations, GET /api/v1/remediations/{transaction_id}.

ARCHITECTURAL LAW #1 ENFORCEMENT (Router level):
  The router DOES NOT evaluate security status.
  It only delegates to RemediationService which delegates to E13 + RTPValidator.

ARCHITECTURAL LAW #3: Router only validates, authenticates, authorizes, delegates, serializes.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from karsasec.server.dependencies import get_current_principal, get_remediation_service
from karsasec.server.dto.remediation import RemediationRequestDTO, RemediationResponseDTO
from karsasec.server.security.authorization import authorize
from karsasec.server.security.models import Permission

router = APIRouter(prefix="/remediations", tags=["remediations"])


@router.post(
    "",
    response_model=RemediationResponseDTO,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Trigger remediation transaction",
    description=(
        "Triggers a full E13 remediation lifecycle transaction for a given finding. "
        "security_verification_status in the response is OUTPUT-ONLY, "
        "derived exclusively from RTPValidator — never from client input."
    ),
)
async def create_remediation(
    body: RemediationRequestDTO,
    principal=Depends(get_current_principal),
    remediation_service=Depends(get_remediation_service),
) -> RemediationResponseDTO:
    """POST /api/v1/remediations — validate, authorize, delegate, serialize."""
    authorize(principal, Permission.REMEDIATION_CREATE)
    return remediation_service.trigger_remediation(
        finding_id=body.finding_id,
        approval_token_id=body.approval.approval_token_id,
        token=body.approval.token,
    )


@router.get(
    "/{transaction_id}",
    response_model=RemediationResponseDTO,
    summary="Get remediation transaction status",
    description="Returns the current status of a remediation transaction.",
)
async def get_remediation(
    transaction_id: str,
    principal=Depends(get_current_principal),
    remediation_service=Depends(get_remediation_service),
) -> RemediationResponseDTO:
    """GET /api/v1/remediations/{transaction_id} — validate, authorize, delegate, serialize."""
    authorize(principal, Permission.REMEDIATION_READ)
    result = remediation_service.get_remediation(transaction_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Remediation transaction '{transaction_id}' not found.",
        )
    return result
