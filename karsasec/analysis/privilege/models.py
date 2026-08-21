"""Data models for KarsaSec Privilege Escalation Graph & Authorization Transition Engine (Batch C14)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class PrivilegeLevel(StrEnum):
    ANONYMOUS = "ANONYMOUS"
    USER = "USER"
    VERIFIED_USER = "VERIFIED_USER"
    TENANT_ADMIN = "TENANT_ADMIN"
    ORG_ADMIN = "ORG_ADMIN"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    SYSTEM_OPERATOR = "SYSTEM_OPERATOR"
    ROOT = "ROOT"
    CLOUD_ADMIN = "CLOUD_ADMIN"
    UNKNOWN = "UNKNOWN"


class IdentityType(StrEnum):
    END_USER = "END_USER"
    ADMIN_USER = "ADMIN_USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    ANONYMOUS_GUEST = "ANONYMOUS_GUEST"
    SYSTEM_PROCESS = "SYSTEM_PROCESS"
    UNKNOWN = "UNKNOWN"


class EscalationCategory(StrEnum):
    VERTICAL_PRIVILEGE_ESCALATION = "VERTICAL_PRIVILEGE_ESCALATION"
    HORIZONTAL_PRIVILEGE_ESCALATION = "HORIZONTAL_PRIVILEGE_ESCALATION"
    TENANT_BOUNDARY_ESCAPE = "TENANT_BOUNDARY_ESCAPE"
    ROLE_CONFUSION = "ROLE_CONFUSION"
    FUNCTION_LEVEL_AUTHZ_BYPASS = "FUNCTION_LEVEL_AUTHZ_BYPASS"
    RESOURCE_LEVEL_AUTHZ_BYPASS = "RESOURCE_LEVEL_AUTHZ_BYPASS"
    ADMIN_ENDPOINT_BYPASS = "ADMIN_ENDPOINT_BYPASS"
    SERVICE_ACCOUNT_ESCALATION = "SERVICE_ACCOUNT_ESCALATION"
    CLOUD_ROLE_ESCALATION = "CLOUD_ROLE_ESCALATION"
    ROOT_ACCESS = "ROOT_ACCESS"
    IMPERSONATION = "IMPERSONATION"
    TOKEN_PRIVILEGE_ESCALATION = "TOKEN_PRIVILEGE_ESCALATION"


@dataclass(frozen=True)
class PrivilegeTransition:
    """Represents a transition between identities or privilege levels."""

    source_identity: str
    source_privilege: str
    target_identity: str
    target_privilege: str
    trigger: str
    boundary: str
    verified: bool


@dataclass
class AuthorizationBoundary:
    """Represents an authorization boundary crossed during an attack."""

    boundary_type: str  # TENANT_RESOURCE, ADMIN_ENDPOINT, SYSTEM_RESOURCE
    is_crossed: bool
    tenant_id: str | None = None


@dataclass
class PrivilegeEvidence:
    """Machine-readable evidence output for Privilege Escalation findings."""

    category: EscalationCategory
    initial_identity: str
    initial_privilege: PrivilegeLevel | str
    transition_trigger: str
    authorization_boundary: str
    resulting_identity: str
    resulting_privilege: PrivilegeLevel | str
    authorization_verified: bool
    tenant_scope_verified: bool
    credential_validity: str = "UNKNOWN"
    evidence_path: list[str] = field(default_factory=list)
    root_cause_chain: list[str] = field(default_factory=list)
    capability_chain: list[str] = field(default_factory=list)
    impact_chain: list[str] = field(default_factory=list)
    resolution: str = "VULNERABLE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category.value if isinstance(self.category, EscalationCategory) else str(self.category),
            "initial_identity": self.initial_identity,
            "initial_privilege": self.initial_privilege.value if isinstance(self.initial_privilege, PrivilegeLevel) else str(self.initial_privilege),
            "transition_trigger": self.transition_trigger,
            "authorization_boundary": self.authorization_boundary,
            "resulting_identity": self.resulting_identity,
            "resulting_privilege": self.resulting_privilege.value if isinstance(self.resulting_privilege, PrivilegeLevel) else str(self.resulting_privilege),
            "authorization_verified": self.authorization_verified,
            "tenant_scope_verified": self.tenant_scope_verified,
            "credential_validity": self.credential_validity,
            "evidence_path": sorted(self.evidence_path),
            "root_cause_chain": sorted(self.root_cause_chain),
            "capability_chain": sorted(self.capability_chain),
            "impact_chain": sorted(self.impact_chain),
            "resolution": self.resolution,
        }


@dataclass
class PrivilegeGraph:
    """Graph extending C13 AttackGraph with explicit PrivilegeTransitions."""

    graph_id: str
    transitions: list[PrivilegeTransition] = field(default_factory=list)
    evidence: PrivilegeEvidence | None = None
    resolution: str = "VULNERABLE"
