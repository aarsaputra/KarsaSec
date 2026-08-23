"""Data models for KarsaSec Authorization Reasoning Engine & Context Propagation (Phase 3 & Sprint D3)."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class AuthzVulnerabilityType(StrEnum):
    IDOR = "IDOR"
    BOLA = "BOLA"
    MASS_ASSIGNMENT = "MASS_ASSIGNMENT"
    TENANT_ISOLATION_FAILURE = "TENANT_ISOLATION_FAILURE"
    BFLA = "BFLA"


class AuthorizationDecisionType(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


class AuthorizationEvidenceState(StrEnum):
    VALID = "VALID"
    STALE = "STALE"
    REVOKED = "REVOKED"
    CONFLICTING = "CONFLICTING"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


class AuthorizationFailureType(StrEnum):
    NONE = "NONE"
    MISSING_EVIDENCE = "MISSING_EVIDENCE"
    STALE_POLICY = "STALE_POLICY"
    STALE_AUTHORITY = "STALE_AUTHORITY"
    MEMBERSHIP_MISMATCH = "MEMBERSHIP_MISMATCH"
    REVOCATION = "REVOCATION"
    CONFLICT = "CONFLICT"
    INVALID_PROVENANCE = "INVALID_PROVENANCE"
    SCOPE_VIOLATION = "SCOPE_VIOLATION"
    TENANT_VIOLATION = "TENANT_VIOLATION"
    REPLAY = "REPLAY"
    UNKNOWN_CONNECTIVITY = "UNKNOWN_CONNECTIVITY"


@dataclass(frozen=True)
class AuthorizationContext:
    """Immutable representation of security authorization evidence and scope provenance."""

    actor: str = "END_USER"
    principal: str = "ANONYMOUS"
    required_permission: str = ""
    granted_permission: str = ""
    authorization_source: str = ""  # e.g., "@require_permission('ADMIN')"
    authorization_scope: str = "GLOBAL"  # e.g., "ADMIN", "TENANT", "USER"
    resource_scope: str = "GLOBAL"
    enforcement_point: str = ""  # function name or decorator site
    confidence: float = 1.0
    provenance: tuple[str, ...] = field(default_factory=tuple)
    is_verified: bool = True
    policy_version: int = 1
    authority_generation: int = 1
    membership_generation: int = 1
    revoked_principals: tuple[str, ...] = field(default_factory=tuple)
    revoked_grants: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "principal": self.principal,
            "required_permission": self.required_permission,
            "granted_permission": self.granted_permission,
            "authorization_source": self.authorization_source,
            "authorization_scope": self.authorization_scope,
            "resource_scope": self.resource_scope,
            "enforcement_point": self.enforcement_point,
            "confidence": self.confidence,
            "provenance": list(self.provenance),
            "is_verified": self.is_verified,
            "policy_version": self.policy_version,
            "authority_generation": self.authority_generation,
            "membership_generation": self.membership_generation,
            "revoked_principals": list(self.revoked_principals),
            "revoked_grants": list(self.revoked_grants),
        }

    def satisfies_scope(self, target_resource_scope: str = "GLOBAL") -> bool:
        """Returns True if authorization scope covers target resource scope."""
        if not self.is_verified or not self.authorization_source:
            return False
        if self.authorization_scope == "ADMIN" or self.required_permission == "ADMIN":
            return True
        if self.authorization_scope == target_resource_scope:
            return True
        return False


@dataclass(frozen=True)
class AuthorizationRequest:
    request_id: str
    principal: str
    resource: str
    action: str
    tenant_id: str = "default_tenant"
    namespace: str = "default_namespace"
    policy_id: str = "policy_default"
    policy_version: int = 1
    authority_generation: int = 1
    membership_generation: int = 1


@dataclass(frozen=True)
class AuthorizationPolicyRef:
    policy_id: str
    policy_version: int
    allowed_actions: tuple[str, ...]
    allowed_resources: tuple[str, ...]
    tenant_id: str = "default_tenant"
    namespace: str = "default_namespace"
    active: bool = True


@dataclass(frozen=True)
class DistributedAuthorizationEvidence:
    evidence_id: str
    source_node: str
    decision: AuthorizationDecisionType
    policy_version: int
    authority_generation: int
    membership_generation: int
    tenant_id: str = "default_tenant"
    namespace: str = "default_namespace"
    state: AuthorizationEvidenceState = AuthorizationEvidenceState.VALID
    is_authoritative: bool = True
    payload: str = ""


@dataclass(frozen=True)
class AuthorizationProvenance:
    decision: AuthorizationDecisionType
    principal_id: str
    resource_id: str
    action: str
    policy_id: str
    policy_version: int
    authority_generation: int
    membership_generation: int
    evidence_ids: tuple[str, ...]
    failure_type: AuthorizationFailureType
    reason_code: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "authority_generation": self.authority_generation,
            "decision": self.decision.value,
            "evidence_ids": list(self.evidence_ids),
            "failure_type": self.failure_type.value,
            "membership_generation": self.membership_generation,
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "principal_id": self.principal_id,
            "reason_code": self.reason_code,
            "resource_id": self.resource_id,
        }


@dataclass(frozen=True)
class AuthorizationDecision:
    decision: AuthorizationDecisionType
    failure_type: AuthorizationFailureType
    provenance: AuthorizationProvenance
    reason: str
    snapshot_digest: str = ""
    invariant_results: dict[str, bool] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)

    def is_allow(self) -> bool:
        return self.decision == AuthorizationDecisionType.ALLOW


@dataclass(frozen=True)
class AuthorizationEvent:
    event_id: str
    event_type: str
    principal: str
    resource: str
    action: str
    policy_version: int
    generation: int
    tenant_id: str = "default_tenant"
    payload: str = ""


@dataclass(frozen=True)
class AuthorizationSnapshot:
    generation: int
    policy_version: int
    membership_generation: int
    revocations: tuple[str, ...]
    grants: tuple[str, ...]
    applied_events: tuple[str, ...]

    def canonical_digest(self) -> str:
        payload = {
            "applied_events": sorted(self.applied_events),
            "generation": self.generation,
            "grants": sorted(self.grants),
            "membership_generation": self.membership_generation,
            "policy_version": self.policy_version,
            "revocations": sorted(self.revocations),
        }
        raw_json = json.dumps(payload, sort_keys=True)
        return hashlib.sha256(raw_json.encode("utf-8")).hexdigest()


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
    authz_context: AuthorizationContext | None = None


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
    authz_context: AuthorizationContext | None = None

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
            "authz_context": self.authz_context.to_dict() if self.authz_context else None,
        }
