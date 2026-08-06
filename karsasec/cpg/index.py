"""GraphIndex providing O(1) lookup speed for CPG nodes across multiple indexing criteria."""

from __future__ import annotations

from typing import Any

from karsasec.cpg.models import CPGGraph, CPGNode, NodeType


class GraphIndex:
    """O(1) index store for searching CPG nodes by ID, file, function, line, label, and language."""

    def __init__(self, graph: CPGGraph | None = None) -> None:
        self.by_id: dict[str, CPGNode] = {}
        self.by_file: dict[str, list[CPGNode]] = {}
        self.by_function: dict[str, list[CPGNode]] = {}
        self.by_line: dict[tuple[str, int], list[CPGNode]] = {}
        self.by_label: dict[str, list[CPGNode]] = {}
        self.by_language: dict[str, list[CPGNode]] = {}
        self.by_type: dict[NodeType, list[CPGNode]] = {}

        if graph:
            self.build_index(graph)

    def build_index(self, graph: CPGGraph) -> None:
        """Populates all index tables from the target CPGGraph."""
        self.clear()
        for node in graph.nodes.values():
            self.index_node(node)

    def index_node(self, node: CPGNode) -> None:
        """Indexes a single CPGNode into lookup tables."""
        self.by_id[node.id] = node

        if node.file_path:
            self.by_file.setdefault(node.file_path, []).append(node)
            self.by_line.setdefault((node.file_path, node.line_number), []).append(node)

        fn_name = node.attributes.get("function_name")
        if fn_name:
            self.by_function.setdefault(fn_name, []).append(node)

        for label in node.labels:
            self.by_label.setdefault(label, []).append(node)

        if node.language:
            self.by_language.setdefault(node.language, []).append(node)

        self.by_type.setdefault(node.node_type, []).append(node)

    def get_by_id(self, node_id: str) -> CPGNode | None:
        return self.by_id.get(node_id)

    def get_by_file(self, file_path: str) -> list[CPGNode]:
        return self.by_file.get(file_path, [])

    def get_by_function(self, fn_name: str) -> list[CPGNode]:
        return self.by_function.get(fn_name, [])

    def get_by_line(self, file_path: str, line_number: int) -> list[CPGNode]:
        return self.by_line.get((file_path, line_number), [])

    def get_by_label(self, label: str) -> list[CPGNode]:
        return self.by_label.get(label, [])

    def get_by_type(self, node_type: NodeType) -> list[CPGNode]:
        return self.by_type.get(node_type, [])

    def clear(self) -> None:
        self.by_id.clear()
        self.by_file.clear()
        self.by_function.clear()
        self.by_line.clear()
        self.by_label.clear()
        self.by_language.clear()
        self.by_type.clear()

    def to_dict(self) -> dict[str, Any]:
        return {
            "indexed_nodes": len(self.by_id),
            "total_files": len(self.by_file),
            "total_functions": len(self.by_function),
            "total_labels": len(self.by_label),
        }
