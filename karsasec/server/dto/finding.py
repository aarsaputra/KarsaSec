"""Finding DTOs for KarsaSec REST API.

Response models for /api/v1/findings endpoints.
No raw source code is ever exposed through these DTOs.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from karsasec.server.dto.common import PaginationMeta


class FindingDTO(BaseModel):
    """Privacy-safe finding representation.

    Excludes: source_code, unified_diff, patch content, credentials.
    """

    finding_id: str = Field(..., description="Unique finding identifier.")
    rule_id: str = Field(..., description="Rule identifier that detected the finding.")
    severity: str = Field(..., description="Severity level (CRITICAL, HIGH, MEDIUM, LOW, INFO).")
    cwe: str = Field(default="", description="CWE identifier if applicable.")
    file_path: str = Field(..., description="Relative file path where finding was detected.")
    line_number: int = Field(default=0, ge=0, description="Line number of the finding.")
    message: str = Field(default="", description="Finding description message.")
    scan_id: str = Field(default="", description="ID of the scan that produced this finding.")
    status: str = Field(default="OPEN", description="Finding status (OPEN, RESOLVED, etc).")


class FindingListResponseDTO(BaseModel):
    """Paginated finding list response."""

    items: list[FindingDTO] = Field(default_factory=list, description="Finding items.")
    pagination: PaginationMeta = Field(..., description="Pagination metadata.")
