"""ResourceGraph Engine: Inter-file dependency and evaluation-order-aware resource tracking (E12-14).

Design Principles & Guardrails:
  - Models inter-file dependencies (INCLUDES, DEFINES, INVOKES, DEPENDS_ON).
  - Explicitly tracks EvaluationOrder (DEFINED_BEFORE_USE, DEFINED_AFTER_USE, CONDITIONAL_DEFINITION, UNKNOWN_ORDER).
  - Resource Resolution classification (STATIC_RESOURCE, TAINTED_RESOURCE, DYNAMIC_RESOURCE, UNKNOWN).
  - Facts are NOT final security decisions: STATIC_RESOURCE is a provenance fact, NOT an automatic SAFE flip.
  - Anti-hardcoding: Pure structural graph and static relationship builder. Zero rule-ID or benchmark strings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class EvaluationOrder(StrEnum):
    """Program-point relative evaluation order of symbol definition vs usage."""

    DEFINED_BEFORE_USE = "DEFINED_BEFORE_USE"
    DEFINED_AFTER_USE = "DEFINED_AFTER_USE"
    CONDITIONAL_DEFINITION = "CONDITIONAL_DEFINITION"
    UNKNOWN_ORDER = "UNKNOWN_ORDER"


class ResourceKind(StrEnum):
    """Categorization of nodes in the Resource Graph."""

    FILE = "FILE"
    MODULE = "MODULE"
    CONSTANT = "CONSTANT"
    FUNCTION = "FUNCTION"
    SINK = "SINK"


class ResourceEdgeKind(StrEnum):
    """Types of directional edges connecting resource nodes."""

    INCLUDES = "INCLUDES"
    DEFINES = "DEFINES"
    INVOKES = "INVOKES"
    DEPENDS_ON = "DEPENDS_ON"


class ResourceResolutionKind(StrEnum):
    """Value/path provenance classification for resource targets."""

    UNKNOWN = "UNKNOWN"
    STATIC_RESOURCE = "STATIC_RESOURCE"
    TAINTED_RESOURCE = "TAINTED_RESOURCE"
    DYNAMIC_RESOURCE = "DYNAMIC_RESOURCE"


@dataclass(frozen=True)
class ResourceNode:
    """A node representing a file, constant, module, or sink in the project graph."""

    node_id: str
    kind: ResourceKind
    path: str = ""
    name: str = ""
    metadata: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ResourceEdge:
    """A directed relationship between two resource nodes."""

    source_id: str
    target_id: str
    kind: ResourceEdgeKind
    evaluation_order: EvaluationOrder = EvaluationOrder.DEFINED_BEFORE_USE
    condition: str = ""


@dataclass(frozen=True)
class ResourceResolution:
    """Result of resolving a resource reference or inclusion target."""

    target: str
    resolution_kind: ResourceResolutionKind
    resolved_path: str = ""
    evaluation_order: EvaluationOrder = EvaluationOrder.DEFINED_BEFORE_USE
    provenance: str = ""


class ResourceGraph:
    """Directed, evaluation-order-aware inter-file resource graph."""

    def __init__(self) -> None:
        self.nodes: dict[str, ResourceNode] = {}
        self.edges: list[ResourceEdge] = []
        self._outgoing: dict[str, list[ResourceEdge]] = {}
        self._incoming: dict[str, list[ResourceEdge]] = {}

    def add_node(self, node: ResourceNode) -> None:
        """Add a resource node to the graph."""
        self.nodes[node.node_id] = node

    def add_edge(self, edge: ResourceEdge) -> None:
        """Add a directed resource edge and index directional maps."""
        self.edges.append(edge)
        self._outgoing.setdefault(edge.source_id, []).append(edge)
        self._incoming.setdefault(edge.target_id, []).append(edge)

    def get_node(self, node_id: str) -> ResourceNode | None:
        """Retrieve a node by its ID."""
        return self.nodes.get(node_id)

    def get_outgoing(self, source_id: str) -> list[ResourceEdge]:
        """Get outgoing edges from source node."""
        return self._outgoing.get(source_id, [])

    def get_incoming(self, target_id: str) -> list[ResourceEdge]:
        """Get incoming edges to target node."""
        return self._incoming.get(target_id, [])

    def find_include_chain(
        self, start_file: str, target_file: str, _visited: set[str] | None = None
    ) -> list[str] | None:
        """Find inclusion path between start_file and target_file with cycle protection."""
        visited = _visited or set()
        if start_file in visited:
            return None
        visited.add(start_file)

        if start_file == target_file:
            return [start_file]

        for edge in self.get_outgoing(start_file):
            if edge.kind == ResourceEdgeKind.INCLUDES:
                sub_path = self.find_include_chain(edge.target_id, target_file, visited.copy())
                if sub_path is not None:
                    return [start_file] + sub_path

        return None
