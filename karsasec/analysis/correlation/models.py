"""Immutable data structures and enums for Batch D4 Cross-Batch Security Correlation Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, StrEnum
from typing import Any


class CorrelationViolationCategory(StrEnum):
    """Taxonomy categories for cross-batch correlation violations."""

    CROSS_BATCH_EVIDENCE_VIOLATION = "CROSS_BATCH_EVIDENCE_VIOLATION"
    CORRELATION_IDENTITY_VIOLATION = "CORRELATION_IDENTITY_VIOLATION"
    CAUSAL_CHAIN_VIOLATION = "CAUSAL_CHAIN_VIOLATION"
    TEMPORAL_CHAIN_VIOLATION = "TEMPORAL_CHAIN_VIOLATION"
    IDENTITY_CONTINUITY_VIOLATION = "IDENTITY_CONTINUITY_VIOLATION"
    PRIVILEGE_AMPLIFICATION = "PRIVILEGE_AMPLIFICATION"
    TENANT_ESCAPE = "TENANT_ESCAPE"
    SECURITY_BOUNDARY_COMPOSITION_VIOLATION = "SECURITY_BOUNDARY_COMPOSITION_VIOLATION"
    EXPLOITABILITY_REACHABILITY_VIOLATION = "EXPLOITABILITY_REACHABILITY_VIOLATION"
    INCOMPLETE_EXPLOIT_CHAIN = "INCOMPLETE_EXPLOIT_CHAIN"
    CORRELATION_CONFLICT = "CORRELATION_CONFLICT"
    COMPOSITE_SECURITY_VIOLATION = "COMPOSITE_SECURITY_VIOLATION"
    ROOT_CAUSE_CHAIN = "ROOT_CAUSE_CHAIN"
    UNKNOWN_CORRELATION_STATE = "UNKNOWN_CORRELATION_STATE"


class CorrelationSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class CorrelationConfidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class CorrelationResolution(StrEnum):
    SAFE = "SAFE"
    VULNERABLE = "VULNERABLE"
    UNKNOWN = "UNKNOWN"


class EvidenceSource(StrEnum):
    C13 = "C13"
    C14 = "C14"
    C15 = "C15"
    D1 = "D1"
    D2 = "D2"
    D3 = "D3"
    D4 = "D4"
    D5 = "D5"


class EdgeRelation(StrEnum):
    CAUSAL = "CAUSAL"
    TEMPORAL = "TEMPORAL"
    IDENTITY = "IDENTITY"
    PRIVILEGE = "PRIVILEGE"
    TENANT = "TENANT"
    DELEGATION = "DELEGATION"
    BOUNDARY = "BOUNDARY"
    REACHABILITY = "REACHABILITY"
    CORRELATION_ONLY = "CORRELATION_ONLY"


class CausalEvidenceType(StrEnum):
    """Typed causal evidence classes. Only these constitute genuine causal signals.

    Contextual correlation signals (same_actor, same_resource, same_timestamp,
    cross_batch, same_tenant) are NOT causal evidence — they are correlation
    context that may support but never independently prove causation.
    """

    DATA_DEPENDENCY = "DATA_DEPENDENCY"
    CONTROL_DEPENDENCY = "CONTROL_DEPENDENCY"
    PRIVILEGE_TRANSITION = "PRIVILEGE_TRANSITION"
    EXPLICIT_DELEGATION = "EXPLICIT_DELEGATION"
    EXPLICIT_PROVENANCE = "EXPLICIT_PROVENANCE"
    AUTHORIZATION_CONTEXT = "AUTHORIZATION_CONTEXT"


class TemporalRelation(StrEnum):
    BEFORE = "BEFORE"
    AFTER = "AFTER"
    CONCURRENT = "CONCURRENT"
    UNKNOWN = "UNKNOWN"


class IdentityType(StrEnum):
    END_USER = "END_USER"
    SERVICE_ACCOUNT = "SERVICE_ACCOUNT"
    DELEGATED_IDENTITY = "DELEGATED_IDENTITY"
    IMPERSONATED_IDENTITY = "IMPERSONATED_IDENTITY"
    UNKNOWN = "UNKNOWN"


class SecurityProperty(StrEnum):
    ACCOUNT_TAKEOVER = "ACCOUNT_TAKEOVER"
    ROOT_ACCESS = "ROOT_ACCESS"
    CLOUD_ADMIN = "CLOUD_ADMIN"
    TENANT_ESCAPE = "TENANT_ESCAPE"
    ADMIN_ACCESS = "ADMIN_ACCESS"
    SECRET_ACCESS = "SECRET_ACCESS"
    PAYMENT_MODIFICATION = "PAYMENT_MODIFICATION"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    CODE_EXECUTION = "CODE_EXECUTION"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CrossBatchNode:
    """Canonical representation of an ingested evidence node across C13-C15 and D1-D3."""

    node_id: str
    source_batch: EvidenceSource
    source_type: str
    source_id: str
    correlation_id: str
    actor_identity: str = "anonymous"
    identity_type: IdentityType = IdentityType.END_USER
    tenant_id: str = "tenant_default"
    privilege_level: str = "LOW"
    capability: str = "NONE"
    action: str = "READ"
    resource: str = "resource_default"
    security_property: SecurityProperty = SecurityProperty.UNKNOWN
    evidence_references: tuple[str, ...] = field(default_factory=tuple)
    temporal_metadata: tuple[str, ...] = field(default_factory=tuple)
    boundary_metadata: tuple[str, ...] = field(default_factory=tuple)
    causal_evidence: tuple[CausalEvidenceType, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "source_batch": self.source_batch.value,
            "source_type": self.source_type,
            "source_id": self.source_id,
            "correlation_id": self.correlation_id,
            "actor_identity": self.actor_identity,
            "identity_type": self.identity_type.value,
            "tenant_id": self.tenant_id,
            "privilege_level": self.privilege_level,
            "capability": self.capability,
            "action": self.action,
            "resource": self.resource,
            "security_property": self.security_property.value,
            "evidence_references": list(self.evidence_references),
            "temporal_metadata": list(self.temporal_metadata),
            "boundary_metadata": list(self.boundary_metadata),
        }


@dataclass(frozen=True)
class CrossBatchEdge:
    """Canonical directional correlation edge between two CrossBatchNodes."""

    edge_id: str
    source_node_id: str
    target_node_id: str
    relation: EdgeRelation
    evidence_id: str
    confidence: CorrelationConfidence = CorrelationConfidence.HIGH
    provenance: str = "D4_CORRELATION_ENGINE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_node_id": self.source_node_id,
            "target_node_id": self.target_node_id,
            "relation": self.relation.value,
            "evidence_id": self.evidence_id,
            "confidence": self.confidence.value,
            "provenance": self.provenance,
        }


@dataclass(frozen=True)
class ChainEvidence:
    """Evidence item supporting an exploit chain."""

    evidence_id: str
    source_batch: EvidenceSource
    source_id: str
    proof_present: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_batch": self.source_batch.value,
            "source_id": self.source_id,
            "proof_present": self.proof_present,
        }


@dataclass(frozen=True)
class ChainRootCause:
    """Earliest causally necessary node whose removal breaks the exploit chain."""

    source_batch: EvidenceSource
    source_id: str
    node_id: str
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_batch": self.source_batch.value,
            "source_id": self.source_id,
            "node_id": self.node_id,
            "rationale": self.rationale,
        }


@dataclass(frozen=True)
class ExploitChain:
    """Canonical representation of a correlated multi-stage exploit chain."""

    chain_id: str
    resolution: CorrelationResolution
    severity: CorrelationSeverity
    confidence: CorrelationConfidence
    chain_type: str
    security_property: SecurityProperty
    nodes: tuple[CrossBatchNode, ...]
    edges: tuple[CrossBatchEdge, ...]
    root_cause: ChainRootCause
    evidence_chain: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "resolution": self.resolution.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "chain_type": self.chain_type,
            "security_property": self.security_property.value,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "root_cause": self.root_cause.to_dict(),
            "evidence_chain": list(self.evidence_chain),
        }


@dataclass(frozen=True)
class CrossBatchGraph:
    """Graph structure containing correlated nodes, edges, and discovered exploit chains."""

    nodes: tuple[CrossBatchNode, ...] = field(default_factory=tuple)
    edges: tuple[CrossBatchEdge, ...] = field(default_factory=tuple)
    exploit_chains: tuple[ExploitChain, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "exploit_chains": [c.to_dict() for c in self.exploit_chains],
        }
