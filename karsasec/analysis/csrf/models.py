"""Data models for KarsaSec CSRF & CORS Reasoning Engine (Batch C1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class CSRFVulnerabilityType(StrEnum):
    MISSING_CSRF_PROTECTION = "MISSING_CSRF_PROTECTION"
    STATE_CHANGING_GET = "STATE_CHANGING_GET"
    LOGIN_CSRF = "LOGIN_CSRF"
    CORS_WILDCARD_WITH_CREDENTIALS = "CORS_WILDCARD_WITH_CREDENTIALS"
    CORS_ORIGIN_REFLECTION = "CORS_ORIGIN_REFLECTION"
    ORIGIN_VALIDATION_BYPASS = "ORIGIN_VALIDATION_BYPASS"


@dataclass
class CrossOriginRequestNode:
    """Represents an incoming HTTP request evaluate for CSRF & CORS security."""

    http_method: str
    origin_header: str | None = None
    referer_header: str | None = None
    has_auth_cookie: bool = True
    has_bearer_token: bool = False
    is_state_changing: bool = True
    has_csrf_token: bool = False
    is_csrf_token_valid: bool = False
    is_login_endpoint: bool = False


@dataclass
class CORSHeaderNode:
    """Represents outgoing CORS response headers."""

    allow_origin: str | None = None
    allow_credentials: bool = False
    is_reflected_origin: bool = False
    is_validated_origin: bool = False


@dataclass
class CSRFEvidence:
    """Machine-readable evidence output for CSRF & CORS findings."""

    category: CSRFVulnerabilityType
    origin: str
    cross_origin: bool
    credential_type: str
    state_changing: bool
    csrf_protection: bool
    authorization_required: bool
    evidence_path: list[str] = field(default_factory=list)
    resolution: str = "VULNERABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "origin": self.origin,
            "cross_origin": self.cross_origin,
            "credential_type": self.credential_type,
            "state_changing": self.state_changing,
            "csrf_protection": self.csrf_protection,
            "authorization_required": self.authorization_required,
            "evidence_path": self.evidence_path,
            "resolution": self.resolution,
        }
