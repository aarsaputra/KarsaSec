"""Data models for Batch D6 Security Decision Engine.

All models are frozen immutable dataclasses supporting canonical serialization and SHA256 identity.
"""

from dataclasses import dataclass, field
from enum import Enum, StrEnum
import hashlib
import json
from typing import Any

from karsasec.analysis.correlation.models import EvidenceSource, SecurityProperty


class DecisionResolution(StrEnum):
    VULNERABLE = "VULNERABLE"
    SAFE = "SAFE"
    UNKNOWN = "UNKNOWN"
    CONFLICT = "CONFLICT"


class RiskSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class BusinessRisk(StrEnum):
    """Business risk dimension — computed independently from technical severity.

    Invariant: UNKNOWN business risk must NOT collapse to LOW.
    UNKNOWN means insufficient business context, not low risk.
    """

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class ExploitabilityLevel(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class ConfidenceLevel(StrEnum):
    PROVEN = "PROVEN"
    VERY_HIGH = "VERY_HIGH"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


class BlastRadiusScope(StrEnum):
    GLOBAL = "GLOBAL"
    MULTI_TENANT = "MULTI_TENANT"
    TENANT = "TENANT"
    MULTI_SERVICE = "MULTI_SERVICE"
    SERVICE = "SERVICE"
    LOCAL = "LOCAL"
    UNKNOWN = "UNKNOWN"


class RemediationPriority(int, Enum):
    P0 = 0  # Immediate Critical
    P1 = 1  # High Priority
    P2 = 2  # Medium Priority
    P3 = 3  # Low Priority
    P4 = 4  # Informational / Unknown


@dataclass(frozen=True)
class FindingRootCause:
    node_id: str
    component: str
    description: str
    source_batch: EvidenceSource
    file_path: str = ""
    line_number: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "component": self.component,
            "description": self.description,
            "source_batch": self.source_batch.value if isinstance(self.source_batch, Enum) else str(self.source_batch),
            "file_path": self.file_path,
            "line_number": self.line_number,
        }


@dataclass(frozen=True)
class FindingEvidence:
    evidence_id: str
    source_batch: EvidenceSource
    description: str
    details: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "source_batch": self.source_batch.value if isinstance(self.source_batch, Enum) else str(self.source_batch),
            "description": self.description,
            "details": list(self.details),
        }


@dataclass(frozen=True)
class FindingImpact:
    security_properties: tuple[SecurityProperty, ...]
    blast_radius: BlastRadiusScope
    affected_services: tuple[str, ...] = field(default_factory=tuple)
    affected_tenants: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "security_properties": [p.value if isinstance(p, Enum) else str(p) for p in self.security_properties],
            "blast_radius": self.blast_radius.value,
            "affected_services": list(self.affected_services),
            "affected_tenants": list(self.affected_tenants),
        }


@dataclass(frozen=True)
class FindingRisk:
    severity: RiskSeverity           # Technical Severity
    business_risk: BusinessRisk      # Business Risk (independent dimension)
    exploitability: ExploitabilityLevel
    confidence: ConfidenceLevel
    remediation_priority: RemediationPriority

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "business_risk": self.business_risk.value,
            "exploitability": self.exploitability.value,
            "confidence": self.confidence.value,
            "remediation_priority": self.remediation_priority.value,
        }


@dataclass(frozen=True)
class FindingProvenance:
    proof_ids: tuple[str, ...]
    exploit_chain_ids: tuple[str, ...]
    evidence_sources: tuple[EvidenceSource, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "proof_ids": list(self.proof_ids),
            "exploit_chain_ids": list(self.exploit_chain_ids),
            "evidence_sources": [s.value if isinstance(s, Enum) else str(s) for s in self.evidence_sources],
        }


@dataclass(frozen=True)
class FindingDecision:
    resolution: DecisionResolution
    explanation: str
    invariants_evaluated: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolution": self.resolution.value,
            "explanation": self.explanation,
            "invariants_evaluated": list(self.invariants_evaluated),
        }


@dataclass(frozen=True)
class SecurityFinding:
    finding_id: str
    resolution: DecisionResolution
    root_cause: FindingRootCause
    impact: FindingImpact
    risk: FindingRisk
    provenance: FindingProvenance
    decision: FindingDecision
    evidence: tuple[FindingEvidence, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "resolution": self.resolution.value,
            "root_cause": self.root_cause.to_dict(),
            "impact": self.impact.to_dict(),
            "risk": self.risk.to_dict(),
            "provenance": self.provenance.to_dict(),
            "decision": self.decision.to_dict(),
            "evidence": [e.to_dict() for e in self.evidence],
        }


@dataclass(frozen=True)
class SecurityDecisionGraph:
    findings: tuple[SecurityFinding, ...] = field(default_factory=tuple)
    summary: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "summary": list(self.summary),
        }


def compute_canonical_finding_id(
    root_cause_id: str,
    security_properties: tuple[SecurityProperty, ...],
    resolution: DecisionResolution,
    proof_ids: tuple[str, ...],
) -> str:
    """Computes a deterministic SHA256 finding_id independent of input order."""
    sorted_props = sorted([p.value if isinstance(p, Enum) else str(p) for p in security_properties])
    sorted_proofs = sorted(list(proof_ids))

    canonical_data = {
        "resolution": resolution.value,
        "root_cause_id": root_cause_id,
        "security_properties": sorted_props,
        "proof_ids": sorted_proofs,
    }
    encoded = json.dumps(canonical_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    digest = hashlib.sha256(encoded).hexdigest()[:16]
    return f"FINDING_{digest.upper()}"
