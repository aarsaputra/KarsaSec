"""Findings router: GET /api/v1/findings, GET /api/v1/findings/{finding_id}.

ARCHITECTURAL LAW #3: Router only validates, authenticates, authorizes, delegates, serializes.
All finding queries are delegated to FindingService which enforces deterministic ordering.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status

from karsasec.server.dependencies import get_current_principal, get_finding_service
from karsasec.server.dto.finding import FindingDTO, FindingListResponseDTO
from karsasec.server.security.authorization import authorize
from karsasec.server.security.models import Permission

router = APIRouter(prefix="/findings", tags=["findings"])


@router.get(
    "",
    response_model=FindingListResponseDTO,
    summary="List findings",
    description=(
        "Returns a deterministically ordered, paginated list of findings. "
        "Order: (severity_rank, file_path, line_number, finding_id)."
    ),
)
async def list_findings(
    scan_id: str | None = Query(default=None, description="Filter by scan ID."),
    page: int = Query(default=1, ge=1, description="Page number."),
    page_size: int = Query(default=50, ge=1, le=200, description="Page size."),
    principal=Depends(get_current_principal),
    finding_service=Depends(get_finding_service),
) -> FindingListResponseDTO:
    """GET /api/v1/findings — validate, authorize, delegate, serialize."""
    authorize(principal, Permission.FINDING_READ)
    return finding_service.list_findings(scan_id=scan_id, page=page, page_size=page_size)


@router.get(
    "/{finding_id}",
    response_model=FindingDTO,
    summary="Get finding detail",
    description="Retrieves the privacy-safe detail of a single finding.",
)
async def get_finding(
    finding_id: str,
    principal=Depends(get_current_principal),
    finding_service=Depends(get_finding_service),
) -> FindingDTO:
    """GET /api/v1/findings/{finding_id} — validate, authorize, delegate, serialize."""
    authorize(principal, Permission.FINDING_READ)
    result = finding_service.get_finding(finding_id)
    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found.",
        )
    return result
