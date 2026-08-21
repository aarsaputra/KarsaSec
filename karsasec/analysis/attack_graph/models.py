"""Data models for KarsaSec Attack Graph Construction Engine (Batch C13)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class NodeType(StrEnum):
    ROOT_CAUSE = "ROOT_CAUSE"
    CAPABILITY = "CAPABILITY"
    IMPACT = "IMPACT"
    TRUST_BOUNDARY = "TRUST_BOUNDARY"
    UNKNOWN = "UNKNOWN"


class EdgeType(StrEnum):
    ENABLES = "ENABLES"
    REQUIRES = "REQUIRES"
    ESCALATES_TO = "ESCALATES_TO"
    EXPOSES = "EXPOSES"
    EXECUTES = "EXECUTES"
    DESTROYS = "DESTROYS"


@dataclass
class AttackNode:
    """Represents a node in the attack graph."""

    node_id: str
    node_type: NodeType
    label: str
    symbol: str
    boundary: str = "DEFAULT"
    resolution: str = "VULNERABLE"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackEdge:
    """Represents a directed edge connecting two attack nodes."""

    edge_id: str
    source_id: str
    target_id: str
    edge_type: EdgeType
    label: str = ""


@dataclass
class CapabilityNode(AttackNode):
    """Specialized node representing an intermediate attack capability."""

    def __post_init__(self) -> None:
        self.node_type = NodeType.CAPABILITY


@dataclass
class ImpactNode(AttackNode):
    """Specialized node representing terminal operational or business impact."""

    root_cause_chain: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.node_type = NodeType.IMPACT


@dataclass
class TrustBoundaryNode(AttackNode):
    """Specialized node representing a trust boundary crossing."""

    def __post_init__(self) -> None:
        self.node_type = NodeType.TRUST_BOUNDARY


@dataclass
class AttackGraph:
    """Directed Acyclic Graph (DAG) of exploit primitives, capabilities, and impacts."""

    graph_id: str
    nodes: list[AttackNode] = field(default_factory=list)
    edges: list[AttackEdge] = field(default_factory=list)
    root_causes: list[str] = field(default_factory=list)
    capabilities: list[str] = field(default_factory=list)
    impacts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "attack_graph_id": self.graph_id,
            "root_cause": self.root_causes,
            "capabilities": self.capabilities,
            "impacts": self.impacts,
            "nodes_count": len(self.nodes),
            "edges_count": len(self.edges),
            "path_length": len(self.edges),
            "confidence": "HIGH" if self.nodes and all(n.resolution == "VULNERABLE" for n in self.nodes) else "UNKNOWN",
            "resolution": "VULNERABLE" if any(n.node_type == NodeType.IMPACT for n in self.nodes) else ("UNKNOWN" if any(n.resolution == "UNKNOWN" for n in self.nodes) else "SAFE"),
        }
