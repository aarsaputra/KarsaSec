"""Contracts and data models for Flask Semantic Graph Correlation (Sprint E10-3C)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from karsasec.framework.semantic_models import SemanticEdgeType


class ResolutionStatus(StrEnum):
    """Status resulting from relationship resolution."""
    RESOLVED = "RESOLVED"
    AMBIGUOUS = "AMBIGUOUS"
    UNRESOLVED = "UNRESOLVED"


class ResolutionMethod(StrEnum):
    """5-Tier deterministic resolution hierarchy method."""
    TIER1_EXPLICIT_REFERENCE = "TIER1_EXPLICIT_REFERENCE"
    TIER2_EXACT_SEMANTIC_ID = "TIER2_EXACT_SEMANTIC_ID"
    TIER3_EXACT_QUALIFIED_NAME = "TIER3_EXACT_QUALIFIED_NAME"
    TIER4_EXACT_MODULE_SYMBOL = "TIER4_EXACT_MODULE_SYMBOL"
    TIER5_EXPLICIT_METADATA = "TIER5_EXPLICIT_METADATA"
    UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class RelationshipCandidate:
    """Candidate edge relationship generated during semantic correlation."""
    source_id: str
    target_id: str
    edge_type: SemanticEdgeType
    status: ResolutionStatus = ResolutionStatus.RESOLVED
    resolution_method: ResolutionMethod = ResolutionMethod.UNRESOLVED
    confidence: float = 1.0
    evidence: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "status": self.status.value,
            "resolution_method": self.resolution_method.value,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "attributes": self.attributes,
        }
