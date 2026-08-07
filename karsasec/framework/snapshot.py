"""FrameworkGraphSnapshot for deterministic graph fingerprinting, hashing, and comparison."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any

from karsasec.framework.optimizer import FrameworkGraphOptimizer
from karsasec.framework.semantic_models import FrameworkSemanticGraph
from karsasec.framework.serializer import FrameworkGraphSerializer


@dataclass(frozen=True)
class GraphDiffResult:
    """Dataclass holding comparison results between two FrameworkSemanticGraph snapshots."""
    added_nodes: tuple[str, ...]
    removed_nodes: tuple[str, ...]
    modified_nodes: tuple[str, ...]
    added_edges: tuple[tuple[str, str, str], ...]
    removed_edges: tuple[tuple[str, str, str], ...]
    is_identical: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "added_nodes": list(self.added_nodes),
            "removed_nodes": list(self.removed_nodes),
            "modified_nodes": list(self.modified_nodes),
            "added_edges": [list(e) for e in self.added_edges],
            "removed_edges": [list(e) for e in self.removed_edges],
            "is_identical": self.is_identical,
        }


class FrameworkGraphSnapshot:
    """Snapshot engine providing deterministic fingerprinting, hashing, and graph comparison."""

    def __init__(self, optimizer: FrameworkGraphOptimizer | None = None) -> None:
        self.optimizer: FrameworkGraphOptimizer = optimizer or FrameworkGraphOptimizer()

    def fingerprint(self, graph: FrameworkSemanticGraph) -> str:
        """Returns deterministic JSON string fingerprint of normalized graph."""
        canonical = self.optimizer.optimize(
            graph,
            deduplicate=True,
            normalize_labels=True,
            canonical_ordering=True,
            remove_orphans=False,
        )
        return FrameworkGraphSerializer.to_json(canonical, indent=None)

    def hash(self, graph: FrameworkSemanticGraph) -> str:
        """Computes SHA-256 digest hash of canonical graph fingerprint."""
        fp = self.fingerprint(graph)
        return hashlib.sha256(fp.encode("utf-8")).hexdigest()

    def compare(self, graph1: FrameworkSemanticGraph, graph2: FrameworkSemanticGraph) -> GraphDiffResult:
        """Compares two graph snapshots and returns detailed structural diff."""
        hash1 = self.hash(graph1)
        hash2 = self.hash(graph2)

        if hash1 == hash2:
            return GraphDiffResult(
                added_nodes=(),
                removed_nodes=(),
                modified_nodes=(),
                added_edges=(),
                removed_edges=(),
                is_identical=True,
            )

        nodes1 = graph1.get_nodes_dict()
        nodes2 = graph2.get_nodes_dict()

        ids1 = set(nodes1.keys())
        ids2 = set(nodes2.keys())

        added_nodes = tuple(sorted(list(ids2 - ids1)))
        removed_nodes = tuple(sorted(list(ids1 - ids2)))

        common_ids = ids1 & ids2
        modified_nodes: list[str] = []
        for n_id in common_ids:
            if nodes1[n_id].to_dict() != nodes2[n_id].to_dict():
                modified_nodes.append(n_id)

        edges1 = {(e.source_id, e.target_id, e.edge_type.value) for e in graph1.edges()}
        edges2 = {(e.source_id, e.target_id, e.edge_type.value) for e in graph2.edges()}

        added_edges = tuple(sorted(list(edges2 - edges1)))
        removed_edges = tuple(sorted(list(edges1 - edges2)))

        return GraphDiffResult(
            added_nodes=added_nodes,
            removed_nodes=removed_nodes,
            modified_nodes=tuple(sorted(modified_nodes)),
            added_edges=added_edges,
            removed_edges=removed_edges,
            is_identical=False,
        )
