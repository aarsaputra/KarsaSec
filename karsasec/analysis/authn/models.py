"""Data models for KarsaSec Authentication Reasoning Engine (Batch B2)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class AuthnVulnerabilityType(StrEnum):
    WEAK_CREDENTIAL_HASHING = "WEAK_CREDENTIAL_HASHING"
    INSECURE_PASSWORD_RESET = "INSECURE_PASSWORD_RESET"
    MFA_BYPASS = "MFA_BYPASS"
    ACCOUNT_ENUMERATION = "ACCOUNT_ENUMERATION"
    TIMING_ATTACK_SURFACE = "TIMING_ATTACK_SURFACE"


@dataclass
class AuthStateNode:
    """Represents the current state of an authentication transaction."""

    step_name: str
    password_accepted: bool = False
    mfa_required: bool = False
    mfa_completed: bool = False
    session_issued: bool = False


@dataclass
class ResetTokenNode:
    """Represents a password reset token instance."""

    token_str: str
    has_entropy: bool = True
    has_expiration: bool = True
    is_user_bound: bool = True
    is_single_use: bool = True


@dataclass
class AuthnEvidence:
    """Machine-readable evidence output for Authentication findings."""

    vulnerability_type: AuthnVulnerabilityType
    location: str
    finding: str
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "vulnerability_type": self.vulnerability_type.value,
            "location": self.location,
            "finding": self.finding,
            "description": self.description,
        }
