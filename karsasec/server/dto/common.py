"""Common DTO models shared across KarsaSec API endpoints."""

from __future__ import annotations

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    """Response DTO for GET /api/v1/health."""

    status: str = Field(default="healthy", description="Service health status.")
    service: str = Field(default="karsasec", description="Service name.")
    version: str = Field(..., description="KarsaSec version string.")
    api_version: str = Field(default="v1", description="API version identifier.")


class PaginationMeta(BaseModel):
    """Pagination metadata for list endpoints."""

    total: int = Field(..., ge=0, description="Total matching items.")
    page: int = Field(default=1, ge=1, description="Current page number.")
    page_size: int = Field(default=50, ge=1, le=200, description="Items per page.")
