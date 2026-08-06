"""CallGraph, CallNode, and CallEdge immutable model definitions."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class CallNode:
    """Represents a function or method declaration in the codebase."""

    id: str
    name: str
    language: str
    file_path: str
    line_number: int
    parameters: list[str] = field(default_factory=list)
    is_method: bool = False
    class_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "language": self.language,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "parameters": self.parameters,
            "is_method": self.is_method,
            "class_name": self.class_name,
        }


@dataclass(frozen=True)
class CallEdge:
    """Represents a call site linking a caller function node to a callee function."""

    caller_id: str
    callee_name: str
    line_number: int
    arguments: list[str] = field(default_factory=list)
    target_node_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "caller_id": self.caller_id,
            "callee_name": self.callee_name,
            "line_number": self.line_number,
            "arguments": self.arguments,
            "target_node_id": self.target_node_id,
        }


class CallGraph:
    """Immutable Call Graph structure linking callers to callees across codebase files."""

    def __init__(self) -> None:
        self._nodes: dict[str, CallNode] = {}
        self._edges: list[CallEdge] = []
        self._name_to_node_ids: dict[str, list[str]] = {}

    def add_node(self, node: CallNode) -> None:
        """Adds a CallNode to the graph."""
        self._nodes[node.id] = node
        if node.name not in self._name_to_node_ids:
            self._name_to_node_ids[node.name] = []
        self._name_to_node_ids[node.name].append(node.id)

    def add_edge(self, edge: CallEdge) -> None:
        """Adds a CallEdge to the graph."""
        self._edges.append(edge)

    @property
    def nodes(self) -> dict[str, CallNode]:
        """Returns map of node ID to CallNode."""
        return dict(self._nodes)

    @property
    def edges(self) -> list[CallEdge]:
        """Returns list of all call edges."""
        return list(self._edges)

    def get_node_by_name(self, name: str) -> list[CallNode]:
        """Retrieves CallNode instances matching a function name."""
        node_ids = self._name_to_node_ids.get(name, [])
        return [self._nodes[nid] for nid in node_ids if nid in self._nodes]

    def get_callees_for_caller(self, caller_id: str) -> list[CallEdge]:
        """Retrieves edges originated by the specified caller node ID."""
        return [e for e in self._edges if e.caller_id == caller_id]

    def get_callers_for_callee(self, callee_name: str) -> list[CallEdge]:
        """Retrieves edges targeting a given callee function name."""
        return [e for e in self._edges if e.callee_name == callee_name]

    def to_dict(self) -> dict[str, Any]:
        """Serializes the CallGraph to a dictionary structure."""
        return {
            "nodes": {nid: node.to_dict() for nid, node in self._nodes.items()},
            "edges": [edge.to_dict() for edge in self._edges],
            "total_nodes": len(self._nodes),
            "total_edges": len(self._edges),
        }

    def to_json(self, indent: int = 2) -> str:
        """Serializes the CallGraph to JSON formatted string."""
        return json.dumps(self.to_dict(), indent=indent)
