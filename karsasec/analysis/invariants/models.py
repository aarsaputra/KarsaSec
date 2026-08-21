"""Data models for KarsaSec Security Invariant Violation Engine (Batch D1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class InvariantType(StrEnum):
    TRUST_BOUNDARY = "TRUST_BOUNDARY"
    PRIVILEGE_BOUNDARY = "PRIVILEGE_BOUNDARY"
    CAPABILITY_OWNERSHIP = "CAPABILITY_OWNERSHIP"
    STATE_TRANSITION = "STATE_TRANSITION"
    TENANT_ISOLATION = "TENANT_ISOLATION"
    AUTHORITY = "AUTHORITY"
    RESOURCE_OWNERSHIP = "RESOURCE_OWNERSHIP"
    DELEGATION = "DELEGATION"
    LIFECYCLE = "LIFECYCLE"
    CONSISTENCY = "CONSISTENCY"
    REACHABILITY = "REACHABILITY"
    SEPARATION_OF_DUTY = "SEPARATION_OF_DUTY"
    DEFENSE_IN_DEPTH = "DEFENSE_IN_DEPTH"
    UNKNOWN = "UNKNOWN"


class ViolationSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class ViolationConfidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class InvariantEvidence:
    """Immutable evidence for security invariant evaluation."""

    evidence_id: str
    invariant_type: InvariantType
    source_boundary: str
    target_boundary: str
    initial_state: str
    resulting_state: str
    evidence_path: tuple[str, ...] = field(default_factory=tuple)
    proof_present: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "invariant_type": self.invariant_type.value,
            "source_boundary": self.source_boundary,
            "target_boundary": self.target_boundary,
            "initial_state": self.initial_state,
            "resulting_state": self.resulting_state,
            "evidence_path": list(self.evidence_path),
            "proof_present": self.proof_present,
        }


@dataclass(frozen=True)
class InvariantViolation:
    """Immutable machine-readable output representing a security invariant violation."""

    violation_id: str
    category: str
    severity: ViolationSeverity
    confidence: ViolationConfidence
    root_cause_chain: tuple[str, ...]
    evidence_chain: tuple[str, ...]
    affected_boundary: str
    resolution: str  # SAFE, VULNERABLE, UNKNOWN
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "violation_id": self.violation_id,
            "category": self.category,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "root_cause_chain": list(self.root_cause_chain),
            "evidence_chain": list(self.evidence_chain),
            "affected_boundary": self.affected_boundary,
            "resolution": self.resolution,
        }


@dataclass(frozen=True)
class InvariantGraph:
    """Immutable collection of evaluated invariant violations."""

    graph_id: str
    violations: tuple[InvariantViolation, ...] = field(default_factory=tuple)
    total_violations: int = 0
    resolution: str = "SAFE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "total_violations": len(self.violations),
            "violations": [v.to_dict() for v in self.violations],
            "resolution": self.resolution,
        }
