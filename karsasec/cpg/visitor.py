"""CPGVisitor abstract class implementing Visitor pattern for CPG node traversal."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from karsasec.cpg.models import CPGGraph, CPGNode


class CPGVisitor(ABC):
    """Abstract Base Class for CPG Graph Visitors."""

    @abstractmethod
    def visit(self, node: CPGNode) -> Any:
        """Invoked when visiting a single CPGNode."""

    def walk(self, graph: CPGGraph) -> None:
        """Walks all nodes in the given CPGGraph."""
        for node in graph.nodes.values():
            self.visit(node)
