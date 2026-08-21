"""Immutable data structures and enums for Batch D5 Security Property Proof & Exploitability Decision Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from karsasec.analysis.correlation.models import SecurityProperty, EvidenceSource


class SecurityPropertyResolution(str, Enum):
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"
    CONFLICT = "CONFLICT"


class ProofConfidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class ProofSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"


class ProofStepType(str, Enum):
    ENTRY = "ENTRY"
    IDENTITY = "IDENTITY"
    AUTHENTICATION = "AUTHENTICATION"
    AUTHORIZATION = "AUTHORIZATION"
    TRUST_BOUNDARY = "TRUST_BOUNDARY"
    PRIVILEGE = "PRIVILEGE"
    TENANT = "TENANT"
    TEMPORAL = "TEMPORAL"
    DISTRIBUTED = "DISTRIBUTED"
    RESOURCE = "RESOURCE"
    CONTROL_FAILURE = "CONTROL_FAILURE"
    IMPACT = "IMPACT"


@dataclass(frozen=True)
class ProofRequirement:
    """Requirement specification for proving a given security property."""

    property: SecurityProperty
    prerequisites: tuple[str, ...] = field(default_factory=tuple)
    required_evidence: tuple[str, ...] = field(default_factory=tuple)
    allowed_transitions: tuple[str, ...] = field(default_factory=tuple)
    forbidden_transitions: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "property": self.property.value,
            "prerequisites": list(self.prerequisites),
            "required_evidence": list(self.required_evidence),
            "allowed_transitions": list(self.allowed_transitions),
            "forbidden_transitions": list(self.forbidden_transitions),
        }


@dataclass(frozen=True)
class ProofEvidence:
    """Individual proof evidence item."""

    evidence_id: str
    source_batch: EvidenceSource
    evidence_type: str
    verified: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_batch": self.source_batch.value,
            "evidence_type": self.evidence_type,
            "verified": self.verified,
        }


@dataclass(frozen=True)
class ProofStep:
    """Single node/step within a formal security property proof path."""

    step_id: str
    step_type: ProofStepType
    source_batch: EvidenceSource
    source_id: str
    description: str
    actor_identity: str = "anonymous"
    tenant_id: str = "tenant_default"
    privilege_level: str = "LOW"

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "step_type": self.step_type.value,
            "source_batch": self.source_batch.value,
            "source_id": self.source_id,
            "description": self.description,
            "actor_identity": self.actor_identity,
            "tenant_id": self.tenant_id,
            "privilege_level": self.privilege_level,
        }


@dataclass(frozen=True)
class ProofEdge:
    """Directional proof edge between two proof steps."""

    edge_id: str
    source_step_id: str
    target_step_id: str
    causal_provenance: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "edge_id": self.edge_id,
            "source_step_id": self.source_step_id,
            "target_step_id": self.target_step_id,
            "causal_provenance": self.causal_provenance,
        }


@dataclass(frozen=True)
class ProofRootCause:
    """Earliest causally necessary node whose removal renders the target property unreachable."""

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
class ProofImpact:
    """Impact binding for a proven security property."""

    property: SecurityProperty
    reachable_resources: tuple[str, ...]
    severity: ProofSeverity

    def to_dict(self) -> dict[str, Any]:
        return {
            "property": self.property.value,
            "reachable_resources": list(self.reachable_resources),
            "severity": self.severity.value,
        }


@dataclass(frozen=True)
class SecurityProof:
    """Formal security property proof representation."""

    proof_id: str
    property: SecurityProperty
    resolution: SecurityPropertyResolution
    severity: ProofSeverity
    confidence: ProofConfidence
    steps: tuple[ProofStep, ...]
    edges: tuple[ProofEdge, ...]
    root_cause: ProofRootCause
    impact: ProofImpact
    evidence_chain: tuple[ProofEvidence, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "proof_id": self.proof_id,
            "property": self.property.value,
            "resolution": self.resolution.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "steps": [s.to_dict() for s in self.steps],
            "edges": [e.to_dict() for e in self.edges],
            "root_cause": self.root_cause.to_dict(),
            "impact": self.impact.to_dict(),
            "evidence_chain": [ev.to_dict() for ev in self.evidence_chain],
        }


@dataclass(frozen=True)
class SecurityProofGraph:
    """Container graph of all security property proofs and verdicts."""

    proofs: tuple[SecurityProof, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "proofs": [p.to_dict() for p in self.proofs],
        }
