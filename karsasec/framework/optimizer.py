"""FrameworkGraphOptimizer for optimizing FrameworkSemanticGraph instances."""

from __future__ import annotations

import logging

from karsasec.framework.semantic_models import (
    FrameworkSemanticEdge,
    FrameworkSemanticGraph,
    FrameworkSemanticNode,
)

logger = logging.getLogger("karsasec.framework.optimizer")


class FrameworkGraphOptimizer:
    """Optimizer engine performing graph canonicalization, deduplication, and orphan removal."""

    def optimize(
        self,
        graph: FrameworkSemanticGraph,
        deduplicate: bool = True,
        normalize_labels: bool = True,
        canonical_ordering: bool = True,
        remove_orphans: bool = False,
    ) -> FrameworkSemanticGraph:
        """Runs full optimization pass suite on FrameworkSemanticGraph."""
        result = graph

        if deduplicate:
            result = self.deduplicate_nodes(result)
            result = self.deduplicate_edges(result)

        if normalize_labels:
            result = self.normalize_labels(result)

        if remove_orphans:
            result = self.remove_orphan_nodes(result)

        if canonical_ordering:
            result = self.enforce_canonical_ordering(result)

        return result

    def deduplicate_nodes(self, graph: FrameworkSemanticGraph) -> FrameworkSemanticGraph:
        """Deduplicates nodes with identical IDs."""
        unique_nodes: dict[str, FrameworkSemanticNode] = {}
        for n in graph.nodes():
            if n.id not in unique_nodes:
                unique_nodes[n.id] = n
        return FrameworkSemanticGraph(
            schema_version=graph.schema_version,
            generator_version=graph.generator_version,
            compatibility_version=graph.compatibility_version,
            nodes=unique_nodes,
            edges=graph.edges(),
        )

    def deduplicate_edges(self, graph: FrameworkSemanticGraph) -> FrameworkSemanticGraph:
        """Deduplicates edges with identical source, target, and edge_type."""
        unique_edges: dict[tuple[str, str, str], FrameworkSemanticEdge] = {}
        for e in graph.edges():
            key = (e.source_id, e.target_id, e.edge_type.value)
            if key not in unique_edges:
                unique_edges[key] = e
        return FrameworkSemanticGraph(
            schema_version=graph.schema_version,
            generator_version=graph.generator_version,
            compatibility_version=graph.compatibility_version,
            nodes={n.id: n for n in graph.nodes()},
            edges=tuple(unique_edges.values()),
        )

    def normalize_labels(self, graph: FrameworkSemanticGraph) -> FrameworkSemanticGraph:
        """Normalizes all node labels to uppercase sorted tuples."""
        normalized_nodes: dict[str, FrameworkSemanticNode] = {}
        for n in graph.nodes():
            norm_labels = tuple(sorted({l.upper() for l in n.labels}))
            node = FrameworkSemanticNode(
                id=n.id,
                node_type=n.node_type,
                name=n.name,
                language=n.language,
                cpg_node_id=n.cpg_node_id,
                labels=norm_labels,
                attributes=n.attributes,
                origin=n.origin,
            )
            normalized_nodes[n.id] = node

        return FrameworkSemanticGraph(
            schema_version=graph.schema_version,
            generator_version=graph.generator_version,
            compatibility_version=graph.compatibility_version,
            nodes=normalized_nodes,
            edges=graph.edges(),
        )

    def enforce_canonical_ordering(self, graph: FrameworkSemanticGraph) -> FrameworkSemanticGraph:
        """Ensures nodes and edges are ordered deterministically by ID and signature."""
        sorted_nodes = dict(sorted(graph.get_nodes_dict().items(), key=lambda x: x[0]))
        sorted_edges = tuple(sorted(graph.edges(), key=lambda e: (e.source_id, e.target_id, e.edge_type.value)))

        return FrameworkSemanticGraph(
            schema_version=graph.schema_version,
            generator_version=graph.generator_version,
            compatibility_version=graph.compatibility_version,
            nodes=sorted_nodes,
            edges=sorted_edges,
        )

    def remove_orphan_nodes(self, graph: FrameworkSemanticGraph) -> FrameworkSemanticGraph:
        """Removes non-root nodes that have zero incoming and outgoing edges."""
        active_node_ids: set[str] = set()
        for e in graph.edges():
            active_node_ids.add(e.source_id)
            active_node_ids.add(e.target_id)

        filtered_nodes: dict[str, FrameworkSemanticNode] = {}
        for n in graph.nodes():
            # Keep route or controller nodes even if orphan, remove other orphans
            if n.node_type.value.upper() in ("ROUTE", "CONTROLLER", "AUTH") or n.id in active_node_ids:
                filtered_nodes[n.id] = n

        return FrameworkSemanticGraph(
            schema_version=graph.schema_version,
            generator_version=graph.generator_version,
            compatibility_version=graph.compatibility_version,
            nodes=filtered_nodes,
            edges=graph.edges(),
        )
