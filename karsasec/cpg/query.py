"""CPGQuery foundation API providing fluent query interface for CPG graphs."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from karsasec.cpg.models import CPGEdge, CPGGraph, CPGNode, EdgeType, NodeType


class CPGQuery:
    """Fluent query builder for searching and filtering CPG nodes and edges."""

    def __init__(self, graph: CPGGraph) -> None:
        self.graph: CPGGraph = graph
        self._current_nodes: list[CPGNode] = list(graph.nodes.values())
        self._current_edges: list[CPGEdge] = list(graph.edges)

    def find_nodes(self, node_type: NodeType | str | None = None) -> CPGQuery:
        """Filters current node set by node_type."""
        if node_type:
            target_val = node_type.value if isinstance(node_type, NodeType) else node_type
            self._current_nodes = [n for n in self._current_nodes if n.node_type.value == target_val]
        return self

    def find_edges(self, edge_type: EdgeType | str | None = None) -> CPGQuery:
        """Filters current edge set by edge_type."""
        if edge_type:
            target_val = edge_type.value if isinstance(edge_type, EdgeType) else edge_type
            self._current_edges = [e for e in self._current_edges if e.edge_type.value == target_val]
        return self

    def where(self, **kwargs: Any) -> CPGQuery:
        """Filters nodes matching attribute or property key-value pairs."""
        filtered = []
        for n in self._current_nodes:
            match = True
            for k, v in kwargs.items():
                if k == "label" and n.label != v:
                    match = False
                elif k == "language" and n.language != v:
                    match = False
                elif k == "file_path" and n.file_path != v:
                    match = False
                elif k in n.attributes and n.attributes[k] != v:
                    match = False
                elif k not in ["label", "language", "file_path"] and k not in n.attributes:
                    match = False
            if match:
                filtered.append(n)
        self._current_nodes = filtered
        return self

    def filter(self, predicate: Callable[[CPGNode], bool]) -> CPGQuery:
        """Filters nodes using a custom Python predicate callable."""
        self._current_nodes = [n for n in self._current_nodes if predicate(n)]
        return self

    def outgoing(self, edge_type: EdgeType | str | None = None) -> CPGQuery:
        """Traverses outgoing edges from current nodes to target nodes."""
        next_nodes = []
        for n in self._current_nodes:
            for edge in self.graph.get_outgoing_edges(n.id):
                if not edge_type or edge.edge_type.value == (edge_type.value if isinstance(edge_type, EdgeType) else edge_type):
                    if edge.target_id in self.graph.nodes:
                        next_nodes.append(self.graph.nodes[edge.target_id])
        self._current_nodes = next_nodes
        return self

    def incoming(self, edge_type: EdgeType | str | None = None) -> CPGQuery:
        """Traverses incoming edges to current nodes to source nodes."""
        next_nodes = []
        for n in self._current_nodes:
            for edge in self.graph.get_incoming_edges(n.id):
                if not edge_type or edge.edge_type.value == (edge_type.value if isinstance(edge_type, EdgeType) else edge_type):
                    if edge.source_id in self.graph.nodes:
                        next_nodes.append(self.graph.nodes[edge.source_id])
        self._current_nodes = next_nodes
        return self

    def neighbors(self) -> list[CPGNode]:
        """Returns adjacent neighbor nodes connected via any outgoing or incoming edge."""
        nbrs = set()
        for n in self._current_nodes:
            for e in self.graph.get_outgoing_edges(n.id):
                if e.target_id in self.graph.nodes:
                    nbrs.add(self.graph.nodes[e.target_id])
            for e in self.graph.get_incoming_edges(n.id):
                if e.source_id in self.graph.nodes:
                    nbrs.add(self.graph.nodes[e.source_id])
        return list(nbrs)

    def execute(self) -> list[CPGNode]:
        """Returns matched list of CPGNodes."""
        return self._current_nodes

    def count(self) -> int:
        """Returns count of matched nodes."""
        return len(self._current_nodes)
