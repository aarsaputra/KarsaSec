"""Scan-related DTOs for KarsaSec REST API.

Request and response models for /api/v1/scans endpoints.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScanTargetDTO(BaseModel):
    """Describes the scan target."""

    type: str = Field(default="local_repository", description="Target type (local_repository).")
    identity: str = Field(..., description="Target identifier (e.g. repository path or identifier).")


class ScanRequest(BaseModel):
    """Request DTO for POST /api/v1/scans."""

    target: ScanTargetDTO = Field(..., description="Scan target specification.")
    languages: list[str] = Field(default_factory=list, description="Optional language filter.")
    rules: list[str] = Field(default_factory=list, description="Optional rule ID filter.")


class ScanResponseDTO(BaseModel):
    """Response DTO for scan operations."""

    scan_id: str = Field(..., description="Unique scan identifier.")
    status: str = Field(..., description="Scan status: QUEUED | RUNNING | COMPLETED | FAILED.")
    created_at: str = Field(..., description="ISO-8601 timestamp of scan creation.")
    finding_count: int = Field(default=0, ge=0, description="Number of findings detected.")
    files_scanned: int = Field(default=0, ge=0, description="Number of files scanned.")
    duration_ms: float = Field(default=0.0, ge=0, description="Scan duration in milliseconds.")
