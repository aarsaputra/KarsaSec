"""Code Property Graph (CPG) Core Data Models, Node/Edge Types, and Metadata."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class NodeType(str, Enum):
    """Core Node Types in Code Property Graph."""

    AST = "AST"
    IR = "IR"
    CFG = "CFG"
    SSA = "SSA"
    DATAFLOW = "DATAFLOW"
    TAINT = "TAINT"
    SYMBOL = "SYMBOL"
    FUNCTION = "FUNCTION"
    CALLSITE = "CALLSITE"


class EdgeType(str, Enum):
    """Core Edge Types linking representations across the CPG."""

    REPRESENTS = "REPRESENTS"
    LOWERED_TO = "LOWERED_TO"
    SSA_VERSION = "SSA_VERSION"
    CFG_FLOW = "CFG_FLOW"
    CALL = "CALL"
    RETURN = "RETURN"
    DATAFLOW = "DATAFLOW"
    DOMINATE = "DOMINATE"
    POST_DOMINATE = "POST_DOMINATE"
    TAINT = "TAINT"
    IMPORT = "IMPORT"
    SYMBOL = "SYMBOL"


def generate_stable_node_id(
    file_path: str,
    qualified_name: str,
    line_number: int,
    column: int,
    node_type: str | NodeType,
) -> str:
    """Generates a deterministic SHA256 node ID based on code location and type."""
    raw = f"{file_path}:{qualified_name}:{line_number}:{column}:{str(node_type)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class CPGNode:
    """Immutable Node representation in Code Property Graph."""

    id: str
    node_type: NodeType
    label: str
    file_path: str = ""
    line_number: int = 1
    column: int = 0
    language: str = "Generic"
    labels: tuple[str, ...] = field(default_factory=tuple)
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "node_type": self.node_type.value,
            "label": self.label,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "column": self.column,
            "language": self.language,
            "labels": list(self.labels),
            "attributes": self.attributes,
        }


@dataclass(frozen=True)
class CPGEdge:
    """Immutable Edge representation linking two nodes in CPG."""

    source_id: str
    target_id: str
    edge_type: EdgeType
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "metadata": self.metadata,
        }


@dataclass
class CPGMetadata:
    """Metadata tracking CPG schema versioning and graph statistics."""

    schema_version: int = 1
    engine_version: str = "1.0.0"
    generated_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    project_name: str = "KarsaSecProject"
    languages: list[str] = field(default_factory=list)
    node_count: int = 0
    edge_count: int = 0
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "engine_version": self.engine_version,
            "generated_at": self.generated_at,
            "project_name": self.project_name,
            "languages": self.languages,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "duration_seconds": self.duration_seconds,
        }


class CPGGraph:
    """Main Graph container for Code Property Graph holding nodes, edges, and metadata."""

    def __init__(self, metadata: CPGMetadata | None = None) -> None:
        self.metadata: CPGMetadata = metadata or CPGMetadata()
        self.nodes: dict[str, CPGNode] = {}
        self.edges: list[CPGEdge] = []
        self._adjacency_out: dict[str, list[CPGEdge]] = {}
        self._adjacency_in: dict[str, list[CPGEdge]] = {}

    def add_node(self, node: CPGNode) -> None:
        self.nodes[node.id] = node
        if node.id not in self._adjacency_out:
            self._adjacency_out[node.id] = []
        if node.id not in self._adjacency_in:
            self._adjacency_in[node.id] = []
        self.metadata.node_count = len(self.nodes)

    def add_edge(self, edge: CPGEdge) -> None:
        self.edges.append(edge)
        if edge.source_id not in self._adjacency_out:
            self._adjacency_out[edge.source_id] = []
        if edge.target_id not in self._adjacency_in:
            self._adjacency_in[edge.target_id] = []

        self._adjacency_out[edge.source_id].append(edge)
        self._adjacency_in[edge.target_id].append(edge)
        self.metadata.edge_count = len(self.edges)

    def get_outgoing_edges(self, node_id: str) -> list[CPGEdge]:
        return self._adjacency_out.get(node_id, [])

    def get_incoming_edges(self, node_id: str) -> list[CPGEdge]:
        return self._adjacency_in.get(node_id, [])

    def to_dict(self) -> dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
