"""Semantic Graph Data Models for Framework Semantic Layer."""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from karsasec.framework.origin import OriginMetadata


class SemanticNodeType(StrEnum):
    """Supported semantic node types in FrameworkSemanticGraph."""

    FRAMEWORK = "FRAMEWORK"
    ROUTE = "ROUTE"
    ENDPOINT = "ENDPOINT"
    CONTROLLER = "CONTROLLER"
    HANDLER = "HANDLER"
    SERVICE = "SERVICE"
    MIDDLEWARE = "MIDDLEWARE"
    CONFIG = "CONFIG"
    ORM = "ORM"
    MODEL = "MODEL"
    AUTH = "AUTH"
    TEMPLATE = "TEMPLATE"
    SESSION = "SESSION"
    COOKIE = "COOKIE"
    FLOW = "FLOW"


class SemanticEdgeType(StrEnum):
    """Supported semantic edge types linking nodes in FrameworkSemanticGraph."""

    DECLARES = "DECLARES"
    CALLS = "CALLS"
    USES = "USES"
    IMPORTS = "IMPORTS"
    HANDLES = "HANDLES"
    PROTECTS = "PROTECTS"
    CONFIGURES = "CONFIGURES"
    OWNS = "OWNS"
    RETURNS = "RETURNS"
    FLOWS_TO = "FLOWS_TO"
    PROPAGATES_TO = "PROPAGATES_TO"
    SINKS_TO = "SINKS_TO"


@dataclass(frozen=True)
class FrameworkSemanticNode:
    """Immutable Node representation in FrameworkSemanticGraph."""

    id: str
    node_type: SemanticNodeType
    name: str
    language: str = "Generic"
    cpg_node_id: str | None = None
    labels: tuple[str, ...] = ()
    attributes: dict[str, Any] = field(default_factory=dict)
    origin: OriginMetadata = field(default_factory=OriginMetadata)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "node_type": self.node_type.value,
            "name": self.name,
            "language": self.language,
            "cpg_node_id": self.cpg_node_id,
            "labels": list(self.labels),
            "attributes": self.attributes,
            "origin": self.origin.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FrameworkSemanticNode:
        return cls(
            id=data["id"],
            node_type=SemanticNodeType(data["node_type"]),
            name=data["name"],
            language=data.get("language", "Generic"),
            cpg_node_id=data.get("cpg_node_id"),
            labels=tuple(data.get("labels", [])),
            attributes=data.get("attributes", {}),
            origin=OriginMetadata.from_dict(data.get("origin", {})),
        )


@dataclass(frozen=True)
class FrameworkSemanticEdge:
    """Immutable Edge representation linking semantic nodes."""

    source_id: str
    target_id: str
    edge_type: SemanticEdgeType
    attributes: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "attributes": self.attributes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FrameworkSemanticEdge:
        return cls(
            source_id=data["source_id"],
            target_id=data["target_id"],
            edge_type=SemanticEdgeType(data["edge_type"]),
            attributes=data.get("attributes", {}),
        )


class FrameworkSemanticGraph:
    """Immutable Graph container holding FrameworkSemanticNode and FrameworkSemanticEdge items."""

    def __init__(
        self,
        schema_version: str = "1.0",
        generator_version: str = "1.0.0",
        compatibility_version: str = "1.0",
        nodes: dict[str, FrameworkSemanticNode] | None = None,
        edges: tuple[FrameworkSemanticEdge, ...] | None = None,
    ) -> None:
        self.schema_version: str = schema_version
        self.generator_version: str = generator_version
        self.compatibility_version: str = compatibility_version
        self._nodes: dict[str, FrameworkSemanticNode] = dict(nodes) if nodes else {}
        self._edges: list[FrameworkSemanticEdge] = list(edges) if edges else []

        self._outgoing_edges: dict[str, list[FrameworkSemanticEdge]] = {}
        self._incoming_edges: dict[str, list[FrameworkSemanticEdge]] = {}
        self._outgoing_index: dict[str, tuple[FrameworkSemanticEdge, ...]] = {}
        self._incoming_index: dict[str, tuple[FrameworkSemanticEdge, ...]] = {}
        self._rebuild_adjacency()

    def _rebuild_adjacency(self) -> None:
        self._outgoing_edges.clear()
        self._incoming_edges.clear()
        self._outgoing_index.clear()
        self._incoming_index.clear()
        for nid in self._nodes:
            self._outgoing_edges[nid] = []
            self._incoming_edges[nid] = []

        for e in self._edges:
            if e.source_id in self._outgoing_edges:
                self._outgoing_edges[e.source_id].append(e)
            if e.target_id in self._incoming_edges:
                self._incoming_edges[e.target_id].append(e)

        for nid, e_list in self._outgoing_edges.items():
            self._outgoing_index[nid] = tuple(
                sorted(e_list, key=lambda x: (x.source_id, x.target_id, x.edge_type.value))
            )
        for nid, e_list in self._incoming_edges.items():
            self._incoming_index[nid] = tuple(
                sorted(e_list, key=lambda x: (x.source_id, x.target_id, x.edge_type.value))
            )

    def add_node(self, node: FrameworkSemanticNode) -> FrameworkSemanticGraph:
        """Returns a new FrameworkSemanticGraph instance containing the added node."""
        new_nodes = dict(self._nodes)
        new_nodes[node.id] = node
        return FrameworkSemanticGraph(
            schema_version=self.schema_version,
            generator_version=self.generator_version,
            compatibility_version=self.compatibility_version,
            nodes=new_nodes,
            edges=tuple(self._edges),
        )

    def remove_node(self, node_id: str) -> FrameworkSemanticGraph:
        """Returns a new FrameworkSemanticGraph instance with the specified node removed."""
        if node_id not in self._nodes:
            return self
        new_nodes = {k: v for k, v in self._nodes.items() if k != node_id}
        new_edges = [e for e in self._edges if e.source_id != node_id and e.target_id != node_id]
        return FrameworkSemanticGraph(
            schema_version=self.schema_version,
            generator_version=self.generator_version,
            compatibility_version=self.compatibility_version,
            nodes=new_nodes,
            edges=tuple(new_edges),
        )

    def add_edge(self, edge: FrameworkSemanticEdge) -> FrameworkSemanticGraph:
        """Returns a new FrameworkSemanticGraph instance containing the added edge."""
        new_edges = list(self._edges)
        new_edges.append(edge)
        return FrameworkSemanticGraph(
            schema_version=self.schema_version,
            generator_version=self.generator_version,
            compatibility_version=self.compatibility_version,
            nodes=dict(self._nodes),
            edges=tuple(new_edges),
        )

    def remove_edge(
        self, source_id: str, target_id: str, edge_type: SemanticEdgeType | None = None
    ) -> FrameworkSemanticGraph:
        """Returns a new FrameworkSemanticGraph instance with matching edge(s) removed."""
        new_edges = [
            e
            for e in self._edges
            if not (
                e.source_id == source_id
                and e.target_id == target_id
                and (edge_type is None or e.edge_type == edge_type)
            )
        ]
        return FrameworkSemanticGraph(
            schema_version=self.schema_version,
            generator_version=self.generator_version,
            compatibility_version=self.compatibility_version,
            nodes=dict(self._nodes),
            edges=tuple(new_edges),
        )

    def node(self, node_id: str) -> FrameworkSemanticNode | None:
        """Retrieves node by ID."""
        return self._nodes.get(node_id)

    def get_nodes_dict(self) -> dict[str, FrameworkSemanticNode]:
        """Returns dictionary of node_id -> FrameworkSemanticNode."""
        return dict(self._nodes)

    def get_incoming_edges(self, node_id: str) -> tuple[FrameworkSemanticEdge, ...]:
        """Returns O(1) indexed tuple of incoming edges for the given node_id."""
        return self._incoming_index.get(node_id, ())

    def get_outgoing_edges(self, node_id: str) -> tuple[FrameworkSemanticEdge, ...]:
        """Returns O(1) indexed tuple of outgoing edges for the given node_id."""
        return self._outgoing_index.get(node_id, ())

    def edge(self, source_id: str, target_id: str) -> FrameworkSemanticEdge | None:
        """Retrieves first matching edge between source_id and target_id."""
        for e in self._edges:
            if e.source_id == source_id and e.target_id == target_id:
                return e
        return None

    def nodes(self) -> tuple[FrameworkSemanticNode, ...]:
        """Returns tuple of all nodes ordered deterministically by ID."""
        return tuple(sorted(self._nodes.values(), key=lambda n: n.id))

    def edges(self) -> tuple[FrameworkSemanticEdge, ...]:
        """Returns tuple of all edges ordered deterministically by source_id, target_id, edge_type."""
        return tuple(sorted(self._edges, key=lambda e: (e.source_id, e.target_id, e.edge_type.value)))

    def find(self, predicate: Callable[[FrameworkSemanticNode], bool]) -> tuple[FrameworkSemanticNode, ...]:
        """Finds all nodes satisfying a predicate function."""
        return tuple(sorted([n for n in self._nodes.values() if predicate(n)], key=lambda n: n.id))

    def filter(self, node_type: SemanticNodeType | str) -> tuple[FrameworkSemanticNode, ...]:
        """Filters nodes matching a specific SemanticNodeType."""
        target_type = SemanticNodeType(node_type) if isinstance(node_type, str) else node_type
        return tuple(sorted([n for n in self._nodes.values() if n.node_type == target_type], key=lambda n: n.id))

    def statistics(self) -> dict[str, Any]:
        """Returns graph topological statistics."""
        node_counts: dict[str, int] = {}
        for n in self._nodes.values():
            node_counts[n.node_type.value] = node_counts.get(n.node_type.value, 0) + 1

        edge_counts: dict[str, int] = {}
        for e in self._edges:
            edge_counts[e.edge_type.value] = edge_counts.get(e.edge_type.value, 0) + 1

        return {
            "node_count": len(self._nodes),
            "edge_count": len(self._edges),
            "node_types": node_counts,
            "edge_types": edge_counts,
            "schema_version": self.schema_version,
            "generator_version": self.generator_version,
            "compatibility_version": self.compatibility_version,
        }

    def to_dict(self) -> dict[str, Any]:
        """Serializes FrameworkSemanticGraph to dictionary."""
        return {
            "schema_version": self.schema_version,
            "generator_version": self.generator_version,
            "compatibility_version": self.compatibility_version,
            "nodes": [n.to_dict() for n in self.nodes()],
            "edges": [e.to_dict() for e in self.edges()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FrameworkSemanticGraph:
        """Deserializes FrameworkSemanticGraph from dictionary."""
        nodes = {n_data["id"]: FrameworkSemanticNode.from_dict(n_data) for n_data in data.get("nodes", [])}
        edges = tuple(FrameworkSemanticEdge.from_dict(e_data) for e_data in data.get("edges", []))
        return cls(
            schema_version=data.get("schema_version", "1.0"),
            generator_version=data.get("generator_version", "1.0.0"),
            compatibility_version=data.get("compatibility_version", "1.0"),
            nodes=nodes,
            edges=edges,
        )

    def to_json(self, indent: int = 2) -> str:
        """Serializes FrameworkSemanticGraph to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, json_str: str) -> FrameworkSemanticGraph:
        """Deserializes FrameworkSemanticGraph from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)
