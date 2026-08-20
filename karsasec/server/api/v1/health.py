"""Health endpoint: GET /api/v1/health.

ARCHITECTURAL LAW #3: Router only validates, authenticates, authorizes, delegates, serializes.
No business logic here.

Note: health endpoint is PUBLIC — no authentication required.
"""

from __future__ import annotations

from fastapi import APIRouter

from karsasec.server.dto.common import HealthResponse

router = APIRouter(tags=["health"])

_VERSION = "1.0.0"


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Service health check",
    description="Returns service health status. Exposes no internal configuration or environment details.",
)
async def health_check() -> HealthResponse:
    """Public health check endpoint. Zero internal detail exposure."""
    return HealthResponse(
        status="healthy",
        service="karsasec",
        version=_VERSION,
        api_version="v1",
    )
