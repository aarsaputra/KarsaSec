"""Data models for KarsaSec Authorization Reasoning Engine (Batch B1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AuthzVulnerabilityType(StrEnum):
    IDOR = "IDOR"
    BOLA = "BOLA"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    TENANT_ISOLATION_FAILURE = "TENANT_ISOLATION_FAILURE"
    BFLA = "BFLA"


@dataclass
class SubjectNode:
    """Represents the authenticated or unauthenticated entity requesting access."""

    subject_id: str
    roles: list[str] = field(default_factory=list)
    tenant_id: str | None = None
    is_authenticated: bool = True


@dataclass
class ObjectNode:
    """Represents the target data resource or entity being accessed."""

    object_id: str
    owner_id: str | None = None
    tenant_id: str | None = None
    resource_type: str = "GENERIC_RESOURCE"


@dataclass
class AuthzDecisionNode:
    """Represents the presence or absence of authorization checks in the dataflow path."""

    has_ownership_check: bool = False
    has_tenant_check: bool = False
    has_role_check: bool = False
    has_field_allowlist: bool = False


@dataclass
class AuthzEvidence:
    """Machine-readable evidence output for Authorization findings."""

    subject_id: str
    object_id: str
    action: str
    ownership_check: bool
    tenant_check: bool
    role_check: bool
    vulnerability_type: AuthzVulnerabilityType
    description: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject_id,
            "object": self.object_id,
            "action": self.action,
            "ownership_check": self.ownership_check,
            "tenant_check": self.tenant_check,
            "role_check": self.role_check,
            "finding": self.vulnerability_type.value,
            "description": self.description,
        }
