"""Data models for KarsaSec Session Management Reasoning Engine (Batch B3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class SessionState(StrEnum):
    CREATED = "CREATED"
    AUTHENTICATED = "AUTHENTICATED"
    MFA_PENDING = "MFA_PENDING"
    ACTIVE = "ACTIVE"
    ROTATING = "ROTATING"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"
    LOGGED_OUT = "LOGGED_OUT"
    UNKNOWN = "UNKNOWN"


class SessionVulnerabilityType(StrEnum):
    SESSION_FIXATION = "SESSION_FIXATION"
    MISSING_SESSION_ROTATION = "MISSING_SESSION_ROTATION"
    REFRESH_TOKEN_REUSE = "REFRESH_TOKEN_REUSE"
    INSECURE_COOKIE_ATTRIBUTES = "INSECURE_COOKIE_ATTRIBUTES"
    SESSION_NOT_INVALIDATED_ON_LOGOUT = "SESSION_NOT_INVALIDATED_ON_LOGOUT"
    TOKEN_IN_URL = "TOKEN_IN_URL"
    TOKEN_LEAKAGE = "TOKEN_LEAKAGE"
    CONCURRENT_SESSION_ABUSE = "CONCURRENT_SESSION_ABUSE"


@dataclass
class SessionToken:
    """Represents a session or access token."""

    token_id: str
    token_type: str = "SESSION_ID"  # SESSION_ID, ACCESS_TOKEN, REFRESH_TOKEN
    is_secure: bool = False
    is_httponly: bool = False
    samesite: str = "Unknown"  # Strict, Lax, None, Missing, Unknown
    exp_seconds: int | None = None
    is_rotated: bool = False
    is_revoked: bool = False


@dataclass
class SessionSubject:
    """Represents the user subject linked to the session state."""

    subject_id: str
    pre_auth_session_id: str | None = None
    post_auth_session_id: str | None = None
    state: SessionState = SessionState.CREATED
    roles: list[str] = field(default_factory=list)


@dataclass
class CookieAttributes:
    """Cookie security flag configuration."""

    name: str
    is_secure: bool = False
    is_httponly: bool = False
    samesite: str = "Missing"
    is_auth_sensitive: bool = True


@dataclass
class SessionEvidence:
    """Machine-readable evidence output for Session Management findings."""

    category: SessionVulnerabilityType
    subject_id: str
    session_id: str
    pre_auth_state: str
    post_auth_state: str
    rotation_required: bool
    rotation_observed: bool
    authentication_transition: str
    evidence_path: list[str] = field(default_factory=list)
    resolution: str = "VULNERABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value,
            "subject": self.subject_id,
            "session": self.session_id,
            "pre_auth_state": self.pre_auth_state,
            "post_auth_state": self.post_auth_state,
            "rotation_required": self.rotation_required,
            "rotation_observed": self.rotation_observed,
            "authentication_transition": self.authentication_transition,
            "evidence_path": self.evidence_path,
            "resolution": self.resolution,
        }
