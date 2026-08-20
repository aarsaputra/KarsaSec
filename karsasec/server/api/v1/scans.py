"""Scans router: POST /api/v1/scans, GET /api/v1/scans/{scan_id}.

ARCHITECTURAL LAW #3: Router only validates, authenticates, authorizes, delegates, serializes.
All scan execution is delegated to ScanService.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, status

from karsasec.server.dependencies import get_current_principal, get_scan_service
from karsasec.server.dto.scan import ScanRequest, ScanResponseDTO
from karsasec.server.security.authorization import authorize
from karsasec.server.security.models import Permission

router = APIRouter(prefix="/scans", tags=["scans"])


@router.post(
    "",
    response_model=ScanResponseDTO,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Execute a SAST scan",
    description="Triggers a deterministic SAST scan against the specified target.",
)
async def create_scan(
    request: Request,
    body: ScanRequest,
    principal=Depends(get_current_principal),
    scan_service=Depends(get_scan_service),
) -> ScanResponseDTO:
    """POST /api/v1/scans — validate, authorize, delegate, serialize."""
    authorize(principal, Permission.SCAN_CREATE)
    return scan_service.execute_scan(body)


@router.get(
    "/{scan_id}",
    response_model=ScanResponseDTO,
    summary="Get scan result",
    description="Retrieves the result of a previously executed scan.",
)
async def get_scan(
    scan_id: str,
    principal=Depends(get_current_principal),
    scan_service=Depends(get_scan_service),
) -> ScanResponseDTO:
    """GET /api/v1/scans/{scan_id} — validate, authorize, delegate, serialize."""
    authorize(principal, Permission.SCAN_READ)
    result = scan_service.get_scan(scan_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )
    return result
