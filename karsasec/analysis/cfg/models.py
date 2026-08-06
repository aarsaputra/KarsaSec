"""Control Flow Graph (CFG) Models, BasicBlock structures, and Serializers."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from karsasec.ir.nodes import IRStatement


class CFGNodeType(StrEnum):
    ENTRY = "ENTRY"
    STATEMENT = "STATEMENT"
    CONDITION = "CONDITION"
    LOOP = "LOOP"
    RETURN = "RETURN"
    THROW = "THROW"
    EXIT = "EXIT"


class CFGEdgeType(StrEnum):
    NORMAL = "NORMAL"
    TRUE_BRANCH = "TRUE_BRANCH"
    FALSE_BRANCH = "FALSE_BRANCH"
    LOOP_BACK = "LOOP_BACK"
    EXCEPTION = "EXCEPTION"
    RETURN_EDGE = "RETURN_EDGE"


@dataclass
class CFGNode:
    """Represents a node or basic block in the Control Flow Graph."""

    id: str
    node_type: CFGNodeType
    line_number: int = 1
    statements: list[IRStatement] = field(default_factory=list)
    label: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "node_type": self.node_type.value,
            "line_number": self.line_number,
            "label": self.label or self.node_type.value,
            "statements": [s.to_dict() for s in self.statements],
        }


@dataclass
class BasicBlock:
    """Groups contiguous non-branching statements into a single basic block."""

    id: str
    nodes: list[CFGNode] = field(default_factory=list)

    def add_node(self, node: CFGNode) -> None:
        self.nodes.append(node)


@dataclass
class CFGEdge:
    """Represents a control-flow edge between two CFG nodes."""

    source_id: str
    target_id: str
    edge_type: CFGEdgeType = CFGEdgeType.NORMAL
    condition_text: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_id": self.source_id,
            "target_id": self.target_id,
            "edge_type": self.edge_type.value,
            "condition_text": self.condition_text,
        }


class EntryNode(CFGNode):
    def __init__(self, cfg_id: str, line_number: int = 1) -> None:
        super().__init__(
            id=f"{cfg_id}::ENTRY",
            node_type=CFGNodeType.ENTRY,
            line_number=line_number,
            label="ENTRY",
        )


class ExitNode(CFGNode):
    def __init__(self, cfg_id: str, line_number: int = 1) -> None:
        super().__init__(
            id=f"{cfg_id}::EXIT",
            node_type=CFGNodeType.EXIT,
            line_number=line_number,
            label="EXIT",
        )


class CFG:
    """Immutable Control Flow Graph representation for a function."""

    def __init__(self, function_name: str, file_path: str = "") -> None:
        self.function_name: str = function_name
        self.file_path: str = file_path
        self.nodes: dict[str, CFGNode] = {}
        self.edges: list[CFGEdge] = []
        self.entry_node_id: str = ""
        self.exit_node_id: str = ""

    def add_node(self, node: CFGNode) -> None:
        self.nodes[node.id] = node
        if node.node_type == CFGNodeType.ENTRY:
            self.entry_node_id = node.id
        elif node.node_type == CFGNodeType.EXIT:
            self.exit_node_id = node.id

    def add_edge(self, source_id: str, target_id: str, edge_type: CFGEdgeType = CFGEdgeType.NORMAL, condition_text: str = "") -> None:
        edge = CFGEdge(source_id=source_id, target_id=target_id, edge_type=edge_type, condition_text=condition_text)
        self.edges.append(edge)

    def get_successors(self, node_id: str) -> list[str]:
        return [e.target_id for e in self.edges if e.source_id == node_id]

    def get_predecessors(self, node_id: str) -> list[str]:
        return [e.source_id for e in self.edges if e.target_id == node_id]

    def to_dict(self) -> dict[str, Any]:
        return {
            "function_name": self.function_name,
            "file_path": self.file_path,
            "entry_node_id": self.entry_node_id,
            "exit_node_id": self.exit_node_id,
            "total_nodes": len(self.nodes),
            "total_edges": len(self.edges),
            "nodes": {nid: n.to_dict() for nid, n in self.nodes.items()},
            "edges": [e.to_dict() for e in self.edges],
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_mermaid(self) -> str:
        """Exports CFG to Mermaid graph diagram syntax."""
        lines = ["flowchart TD", f"    %% CFG for {self.function_name}"]
        for nid, node in self.nodes.items():
            safe_id = nid.replace("::", "_").replace(".", "_").replace("-", "_")
            label = f"{node.node_type.value}: {node.label}" if node.label else node.node_type.value
            lines.append(f'    {safe_id}["{label}"]')

        for edge in self.edges:
            src = edge.source_id.replace("::", "_").replace(".", "_").replace("-", "_")
            tgt = edge.target_id.replace("::", "_").replace(".", "_").replace("-", "_")
            arrow = "-->"
            if edge.edge_type == CFGEdgeType.TRUE_BRANCH:
                arrow = "-- True -->"
            elif edge.edge_type == CFGEdgeType.FALSE_BRANCH:
                arrow = "-- False -->"
            elif edge.edge_type == CFGEdgeType.LOOP_BACK:
                arrow = "-- Loop -->"
            lines.append(f"    {src} {arrow} {tgt}")

        return "\n".join(lines)

    def to_dot(self) -> str:
        """Exports CFG to Graphviz DOT diagram syntax."""
        lines = [f'digraph "{self.function_name}" {{', '    node [shape=box, fontname="Helvetica"];']
        for nid, node in self.nodes.items():
            safe_id = nid.replace("::", "_").replace(".", "_").replace("-", "_")
            label = f"{node.node_type.value}: {node.label}" if node.label else node.node_type.value
            lines.append(f'    "{safe_id}" [label="{label}"];')

        for edge in self.edges:
            src = edge.source_id.replace("::", "_").replace(".", "_").replace("-", "_")
            tgt = edge.target_id.replace("::", "_").replace(".", "_").replace("-", "_")
            label_attr = f' [label="{edge.condition_text or edge.edge_type.value}"]' if edge.condition_text or edge.edge_type != CFGEdgeType.NORMAL else ""
            lines.append(f'    "{src}" -> "{tgt}"{label_attr};')

        lines.append("}")
        return "\n".join(lines)
