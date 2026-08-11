"""Immutable Graph Security Rule models for Framework Semantic Layer."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from karsasec.framework.semantic_models import SemanticNodeType
from karsasec.rules.enums import Confidence, Severity


@dataclass(frozen=True)
class GraphRuleTraversal:
    """Resource bounds and depth limits for graph rule traversal."""
    max_depth: int = 1
    max_nodes_visited: int = 100
    max_edges_examined: int = 200


@dataclass(frozen=True)
class GraphRuleMatch:
    """Result of evaluating a GraphSecurityRule against a target node."""
    matched: bool
    primary_node_id: str
    evidence_node_ids: tuple[str, ...] = ()
    evidence_edge_ids: tuple[str, ...] = ()
    matched_predicate: str = ""


@dataclass(frozen=True)
class GraphRuleOutput:
    """Finding metadata produced when a graph rule matches."""
    severity: Severity
    confidence: Confidence
    message: str
    remediation: str


@dataclass(frozen=True)
class GraphSecurityRule:
    """Immutable declarative security rule evaluated against FrameworkSemanticGraph."""
    id: str
    version: str
    framework: str
    metadata: dict[str, Any]
    target_node_type: SemanticNodeType
    conditions: dict[str, Any]
    traversal: GraphRuleTraversal
    output: GraphRuleOutput

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "framework": self.framework,
            "metadata": self.metadata,
            "target": {"node_type": self.target_node_type.value},
            "conditions": self.conditions,
            "traversal": {
                "max_depth": self.traversal.max_depth,
                "max_nodes_visited": self.traversal.max_nodes_visited,
                "max_edges_examined": self.traversal.max_edges_examined,
            },
            "output": {
                "severity": self.output.severity.value,
                "confidence": self.output.confidence.value,
                "message": self.output.message,
                "remediation": self.output.remediation,
            },
        }
