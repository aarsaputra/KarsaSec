"""Data Flow Analysis Models, Def-Use / Use-Def Chains, and DataFlowGraph containers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any


@dataclass
class VariableRef:
    """Represents a variable reference at a specific line in source code."""

    name: str
    ssa_version: int = 0
    line_number: int = 1

    @property
    def ssa_name(self) -> str:
        return f"{self.name}_{self.ssa_version}" if self.ssa_version > 0 else self.name

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ssa_version": self.ssa_version,
            "ssa_name": self.ssa_name,
            "line_number": self.line_number,
        }


@dataclass
class DefUseChain:
    """Def-Use Chain: Maps a variable definition to all its downstream usage locations."""

    definition: VariableRef
    uses: list[VariableRef] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "definition": self.definition.to_dict(),
            "uses": [u.to_dict() for u in self.uses],
        }


@dataclass
class UseDefChain:
    """Use-Def Chain: Maps a variable usage location to all reaching definition locations."""

    use: VariableRef
    definitions: list[VariableRef] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "use": self.use.to_dict(),
            "definitions": [d.to_dict() for d in self.definitions],
        }


@dataclass
class DataFlowNode:
    """Node in DataFlowGraph representing a statement's dataflow state."""

    id: str
    statement_id: str
    line_number: int
    definitions: list[VariableRef] = field(default_factory=list)
    uses: list[VariableRef] = field(default_factory=list)
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "statement_id": self.statement_id,
            "line_number": self.line_number,
            "definitions": [d.to_dict() for d in self.definitions],
            "uses": [u.to_dict() for u in self.uses],
            "label": self.label,
        }


@dataclass
class DataFlowEdge:
    """Represents data dependence between a definition node and a usage node."""

    source_id: str
    target_id: str
    var_name: str
    edge_type: str = "DATA_DEPENDENCE"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "var_name": self.var_name,
            "edge_type": self.edge_type,
        }


class DataFlowGraph:
    """DataFlowGraph containing reaching definitions, Def-Use chains, and constant values."""

    def __init__(self, function_name: str, file_path: str = "") -> None:
        self.function_name: str = function_name
        self.file_path: str = file_path
        self.nodes: dict[str, DataFlowNode] = {}
        self.edges: list[DataFlowEdge] = []
        self.def_use_chains: list[DefUseChain] = []
        self.use_def_chains: list[UseDefChain] = []
        self.constant_values: dict[str, Any] = {}

    def add_node(self, node: DataFlowNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, source_id: str, target_id: str, var_name: str) -> None:
        edge = DataFlowEdge(source_id=source_id, target_id=target_id, var_name=var_name)
        self.edges.append(edge)

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "file_path": self.file_path,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
            "def_use_chains": [duc.to_dict() for duc in self.def_use_chains],
            "use_def_chains": [udc.to_dict() for udc in self.use_def_chains],
            "constant_values": self.constant_values,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)
