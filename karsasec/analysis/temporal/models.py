"""Data models for KarsaSec Temporal & State Consistency Violation Engine (Batch D2)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class TemporalViolationCategory(StrEnum):
    REVOCATION_DRIFT_VIOLATION = "REVOCATION_DRIFT_VIOLATION"
    TOCTOU_VIOLATION = "TOCTOU_VIOLATION"
    STATE_DESYNC_VIOLATION = "STATE_DESYNC_VIOLATION"
    CACHE_AUTHORIZATION_DRIFT = "CACHE_AUTHORIZATION_DRIFT"
    WORKFLOW_BYPASS_VIOLATION = "WORKFLOW_BYPASS_VIOLATION"
    RACE_CONDITION_REACHABILITY = "RACE_CONDITION_REACHABILITY"
    TRANSACTIONAL_INVARIANT_FAILURE = "TRANSACTIONAL_INVARIANT_FAILURE"
    TEMPORAL_AUTHORIZATION_VIOLATION = "TEMPORAL_AUTHORIZATION_VIOLATION"
    CAPABILITY_LIFETIME_ABUSE = "CAPABILITY_LIFETIME_ABUSE"
    REPLAY_ATTACK_VIOLATION = "REPLAY_ATTACK_VIOLATION"
    TEMPORAL_TENANT_ISOLATION_VIOLATION = "TEMPORAL_TENANT_ISOLATION_VIOLATION"
    STATE_MONOTONICITY_VIOLATION = "STATE_MONOTONICITY_VIOLATION"
    UNKNOWN_TEMPORAL_VIOLATION = "UNKNOWN_TEMPORAL_VIOLATION"


class TemporalSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class TemporalConfidence(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class TemporalEvent:
    """Immutable event node within a temporal sequence graph."""

    event_id: str
    timestamp: float
    actor: str
    action: str
    state_before: str
    state_after: str
    capability: str
    resource: str
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "state_before": self.state_before,
            "state_after": self.state_after,
            "capability": self.capability,
            "resource": self.resource,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class TemporalEdge:
    """Immutable directed relationship between temporal events."""

    source: str
    target: str
    relation: str  # PRECEDES, FOLLOWS, ENABLES, INVALIDATES, REVOKES, etc.
    ordering: int
    evidence_ids: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "ordering": self.ordering,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class TemporalEvidence:
    """Immutable evidence for temporal and state consistency evaluation."""

    evidence_id: str
    category: TemporalViolationCategory
    events: tuple[TemporalEvent, ...] = field(default_factory=tuple)
    edges: tuple[TemporalEdge, ...] = field(default_factory=tuple)
    lock_present: bool = False
    cache_invalidated: bool = False
    transaction_boundary_present: bool = False
    proof_present: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "category": self.category.value,
            "events": [e.to_dict() for e in self.events],
            "edges": [e.to_dict() for e in self.edges],
            "lock_present": self.lock_present,
            "cache_invalidated": self.cache_invalidated,
            "transaction_boundary_present": self.transaction_boundary_present,
            "proof_present": self.proof_present,
        }


@dataclass(frozen=True)
class TemporalViolation:
    """Immutable machine-readable temporal consistency violation finding."""

    violation_id: str
    category: TemporalViolationCategory
    severity: TemporalSeverity
    confidence: TemporalConfidence
    resolution: str  # SAFE, VULNERABLE, UNKNOWN
    root_cause_chain: tuple[str, ...]
    evidence_chain: tuple[str, ...]
    temporal_path: tuple[str, ...]
    affected_resource: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "violation_id": self.violation_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "resolution": self.resolution,
            "root_cause_chain": list(self.root_cause_chain),
            "evidence_chain": list(self.evidence_chain),
            "temporal_path": list(self.temporal_path),
            "affected_resource": self.affected_resource,
        }


@dataclass(frozen=True)
class TemporalGraph:
    """Immutable collection of temporal events, edges, and evaluated violations."""

    graph_id: str
    events: tuple[TemporalEvent, ...] = field(default_factory=tuple)
    edges: tuple[TemporalEdge, ...] = field(default_factory=tuple)
    violations: tuple[TemporalViolation, ...] = field(default_factory=tuple)
    resolution: str = "SAFE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "graph_id": self.graph_id,
            "events": [e.to_dict() for e in self.events],
            "edges": [e.to_dict() for e in self.edges],
            "violations": [v.to_dict() for v in self.violations],
            "resolution": self.resolution,
        }
