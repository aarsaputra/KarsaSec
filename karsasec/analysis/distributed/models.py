"""Data models for KarsaSec Distributed Security Consistency Engine (Batch D3)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class IdentityType(StrEnum):
    END_USER = "END_USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    DELEGATED_IDENTITY = "DELEGATED_IDENTITY"
    IMPERSONATED_IDENTITY = "IMPERSONATED_IDENTITY"


class TemporalOrder(StrEnum):
    BEFORE = "BEFORE"
    AFTER = "AFTER"
    CONCURRENT = "CONCURRENT"
    UNKNOWN = "UNKNOWN"


class DistributedViolationCategory(StrEnum):
    CROSS_SERVICE_TRUST_VIOLATION = "CROSS_SERVICE_TRUST_VIOLATION"
    AUTHORIZATION_CONTEXT_DRIFT = "AUTHORIZATION_CONTEXT_DRIFT"
    IDENTITY_PROVENANCE_LOSS = "IDENTITY_PROVENANCE_LOSS"
    CROSS_SERVICE_TENANT_ESCAPE = "CROSS_SERVICE_TENANT_ESCAPE"
    DISTRIBUTED_PRIVILEGE_AMPLIFICATION = "DISTRIBUTED_PRIVILEGE_AMPLIFICATION"
    DISTRIBUTED_DELEGATION_VIOLATION = "DISTRIBUTED_DELEGATION_VIOLATION"
    AUTHORIZATION_CONTEXT_DETACHMENT = "AUTHORIZATION_CONTEXT_DETACHMENT"
    MESSAGE_SECURITY_CONTEXT_LOSS = "MESSAGE_SECURITY_CONTEXT_LOSS"
    ASYNC_AUTHORIZATION_DRIFT = "ASYNC_AUTHORIZATION_DRIFT"
    DISTRIBUTED_STATE_INCONSISTENCY = "DISTRIBUTED_STATE_INCONSISTENCY"
    DISTRIBUTED_CACHE_SECURITY_DRIFT = "DISTRIBUTED_CACHE_SECURITY_DRIFT"
    GATEWAY_BACKEND_SECURITY_MISMATCH = "GATEWAY_BACKEND_SECURITY_MISMATCH"
    SERVICE_USER_IDENTITY_CONFUSION = "SERVICE_USER_IDENTITY_CONFUSION"
    EVENT_PROVENANCE_VIOLATION = "EVENT_PROVENANCE_VIOLATION"
    DISTRIBUTED_REPLAY_VIOLATION = "DISTRIBUTED_REPLAY_VIOLATION"
    DISTRIBUTED_SOD_VIOLATION = "DISTRIBUTED_SOD_VIOLATION"
    DISTRIBUTED_DEFENSE_IN_DEPTH_VIOLATION = "DISTRIBUTED_DEFENSE_IN_DEPTH_VIOLATION"
    UNKNOWN_DISTRIBUTED_SECURITY_STATE = "UNKNOWN_DISTRIBUTED_SECURITY_STATE"


class DistributedSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class DistributedConfidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class DistributedResolution(StrEnum):
    SAFE = "SAFE"
    VULNERABLE = "VULNERABLE"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class DistributedService:
    service_id: str
    name: str
    trust_domain: str
    trust_level: str  # LOW, HIGH, UNKNOWN

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "name": self.name,
            "trust_domain": self.trust_domain,
            "trust_level": self.trust_level,
        }


@dataclass(frozen=True)
class DistributedIdentity:
    identity_id: str
    identity_type: IdentityType
    principal_name: str
    roles: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "identity_id": self.identity_id,
            "identity_type": self.identity_type.value,
            "principal_name": self.principal_name,
            "roles": list(self.roles),
        }


@dataclass(frozen=True)
class DistributedBoundary:
    boundary_id: str
    source_service: str
    target_service: str
    requires_validation: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "boundary_id": self.boundary_id,
            "source_service": self.source_service,
            "target_service": self.target_service,
            "requires_validation": self.requires_validation,
        }


@dataclass(frozen=True)
class DistributedEvent:
    event_id: str
    correlation_id: str
    service_id: str
    actor: DistributedIdentity
    action: str
    tenant_id: str
    temporal_order: TemporalOrder = TemporalOrder.UNKNOWN
    timestamp: float = 0.0
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "correlation_id": self.correlation_id,
            "service_id": self.service_id,
            "actor": self.actor.to_dict(),
            "action": self.action,
            "tenant_id": self.tenant_id,
            "temporal_order": self.temporal_order.value,
            "timestamp": self.timestamp,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class DistributedAuthorizationContext:
    context_id: str
    identity: DistributedIdentity
    tenant_id: str
    granted_privilege: str
    is_valid: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "context_id": self.context_id,
            "identity": self.identity.to_dict(),
            "tenant_id": self.tenant_id,
            "granted_privilege": self.granted_privilege,
            "is_valid": self.is_valid,
        }


@dataclass(frozen=True)
class DistributedEdge:
    source_id: str
    target_id: str
    relation: str
    correlation_id: str
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "relation": self.relation,
            "correlation_id": self.correlation_id,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class DistributedEvidence:
    evidence_id: str
    correlation_id: str
    category: DistributedViolationCategory
    services: tuple[DistributedService, ...] = field(default_factory=tuple)
    events: tuple[DistributedEvent, ...] = field(default_factory=tuple)
    edges: tuple[DistributedEdge, ...] = field(default_factory=tuple)
    proof_present: bool = False
    validation_present: bool = False
    explicit_delegation_present: bool = False
    impersonation_proof_present: bool = False
    replay_protection_present: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "correlation_id": self.correlation_id,
            "category": self.category.value,
            "services": [s.to_dict() for s in self.services],
            "events": [e.to_dict() for e in self.events],
            "edges": [e.to_dict() for e in self.edges],
            "proof_present": self.proof_present,
            "validation_present": self.validation_present,
            "explicit_delegation_present": self.explicit_delegation_present,
            "impersonation_proof_present": self.impersonation_proof_present,
            "replay_protection_present": self.replay_protection_present,
        }


@dataclass(frozen=True)
class DistributedViolation:
    violation_id: str
    category: DistributedViolationCategory
    severity: DistributedSeverity
    confidence: DistributedConfidence
    resolution: str  # SAFE, VULNERABLE, UNKNOWN
    services: tuple[str, ...]
    actor: str
    initial_privilege: str
    resulting_privilege: str
    tenant_context: str
    delegation_chain: tuple[str, ...]
    evidence_chain: tuple[str, ...]
    cross_boundary_path: tuple[str, ...]
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "violation_id": self.violation_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "resolution": self.resolution,
            "services": list(self.services),
            "actor": self.actor,
            "initial_privilege": self.initial_privilege,
            "resulting_privilege": self.resulting_privilege,
            "tenant_context": self.tenant_context,
            "delegation_chain": list(self.delegation_chain),
            "evidence_chain": list(self.evidence_chain),
            "cross_boundary_path": list(self.cross_boundary_path),
        }


@dataclass(frozen=True)
class DistributedGraph:
    graph_id: str
    services: tuple[DistributedService, ...] = field(default_factory=tuple)
    events: tuple[DistributedEvent, ...] = field(default_factory=tuple)
    edges: tuple[DistributedEdge, ...] = field(default_factory=tuple)
    violations: tuple[DistributedViolation, ...] = field(default_factory=tuple)
    resolution: str = "SAFE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "services": [s.to_dict() for s in self.services],
            "events": [e.to_dict() for e in self.events],
            "edges": [e.to_dict() for e in self.edges],
            "violations": [v.to_dict() for v in self.violations],
            "resolution": self.resolution,
        }
