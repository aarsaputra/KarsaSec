"""Data models for KarsaSec Full Multi-Step Breach Simulation & Business Risk Engine (Batch C15)."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class SimulationStatus(StrEnum):
    SAFE = "SAFE"
    VULNERABLE = "VULNERABLE"
    UNKNOWN = "UNKNOWN"
    INVALID = "INVALID"


class ScenarioType(StrEnum):
    SINGLE_HOP = "SINGLE_HOP"
    MULTI_HOP = "MULTI_HOP"
    CREDENTIAL_BREACH = "CREDENTIAL_BREACH"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    TENANT_BOUNDARY_BREACH = "TENANT_BOUNDARY_BREACH"
    INTERNAL_NETWORK_BREACH = "INTERNAL_NETWORK_BREACH"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    DESTRUCTIVE_BREACH = "DESTRUCTIVE_BREACH"
    FULL_COMPROMISE = "FULL_COMPROMISE"
    BUSINESS_CRITICAL_BREACH = "BUSINESS_CRITICAL_BREACH"
    UNKNOWN_SCENARIO = "UNKNOWN_SCENARIO"


class RiskLevel(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class ConfidenceLevel(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class RiskFactor:
    """Explaining contribution of an evidence-backed security risk factor."""

    name: str
    value: float
    weight: float
    contribution: float
    evidence: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "value": round(self.value, 4),
            "weight": round(self.weight, 4),
            "contribution": round(self.contribution, 4),
            "evidence": list(self.evidence),
        }


@dataclass(frozen=True)
class BreachStep:
    """Individual capability transition step within a breach scenario."""

    step_id: str
    source_node: str
    capability: str
    target_node: str
    edge_type: str
    resolution: SimulationStatus
    evidence_path: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "source_node": self.source_node,
            "capability": self.capability,
            "target_node": self.target_node,
            "edge_type": self.edge_type,
            "resolution": self.resolution.value if isinstance(self.resolution, SimulationStatus) else str(self.resolution),
            "evidence_path": list(self.evidence_path),
        }


@dataclass(frozen=True)
class BreachScenario:
    """Canonical multi-step breach scenario and risk evaluation output."""

    scenario_id: str
    scenario_type: ScenarioType
    root_causes: tuple[str, ...]
    capabilities: tuple[str, ...]
    impacts: tuple[str, ...]
    steps: tuple[BreachStep, ...]
    privilege_transition: tuple[str, str] | None
    business_impact: tuple[str, ...]
    risk_factors: tuple[RiskFactor, ...]
    risk_score: float | None
    risk_level: RiskLevel
    confidence: ConfidenceLevel
    resolution: SimulationStatus
    evidence_ids: tuple[str, ...]
    evidence_path: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "scenario_type": self.scenario_type.value if isinstance(self.scenario_type, ScenarioType) else str(self.scenario_type),
            "resolution": self.resolution.value if isinstance(self.resolution, SimulationStatus) else str(self.resolution),
            "root_causes": list(self.root_causes),
            "capabilities": list(self.capabilities),
            "impacts": list(self.impacts),
            "steps": [step.to_dict() for step in self.steps],
            "privilege_transition": {
                "initial": self.privilege_transition[0],
                "resulting": self.privilege_transition[1],
            } if self.privilege_transition else None,
            "business_impact": list(self.business_impact),
            "risk": {
                "score": round(self.risk_score, 2) if self.risk_score is not None else None,
                "level": self.risk_level.value if isinstance(self.risk_level, RiskLevel) else str(self.risk_level),
                "factors": [rf.to_dict() for rf in self.risk_factors],
            },
            "confidence": self.confidence.value if isinstance(self.confidence, ConfidenceLevel) else str(self.confidence),
            "evidence_ids": list(self.evidence_ids),
            "evidence_path": list(self.evidence_path),
        }
