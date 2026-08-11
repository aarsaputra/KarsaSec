"""Graph normalizer, attribute canonicalizer, deduplicator, and sorting engine."""

from __future__ import annotations

from typing import Any

from karsasec.framework.framework_semantics.correlation.edge_identity import generate_canonical_edge_id
from karsasec.framework.framework_semantics.correlation.state import CorrelationState
from karsasec.framework.semantic_models import (
    FrameworkSemanticEdge,
    FrameworkSemanticGraph,
    FrameworkSemanticNode,
)


class GraphNormalizer:
    """Normalizes, deduplicates, and sorts semantic graph nodes and edges."""

    @staticmethod
    def normalize(state: CorrelationState) -> FrameworkSemanticGraph:
        """Convert CorrelationState into a canonical, deduplicated, sorted FrameworkSemanticGraph."""
        # 1. Collect and deduplicate nodes (sorted by node.id)
        sorted_nodes: list[FrameworkSemanticNode] = sorted(
            state.nodes.values(),
            key=lambda n: n.id,
        )

        # 2. Build deduplicated edges
        edges_map: dict[str, FrameworkSemanticEdge] = {}
        for candidate in state.candidates:
            edge_attrs: dict[str, Any] = {
                "confidence": candidate.confidence,
                "evidence": list(candidate.evidence),
                "resolution_method": candidate.resolution_method.value,
                **candidate.attributes,
            }
            edge_id = generate_canonical_edge_id(
                source_id=candidate.source_id,
                target_id=candidate.target_id,
                edge_type=candidate.edge_type,
                attributes=edge_attrs,
            )

            if edge_id not in edges_map:
                edge = FrameworkSemanticEdge(
                    source_id=candidate.source_id,
                    target_id=candidate.target_id,
                    edge_type=candidate.edge_type,
                    attributes=edge_attrs,
                )
                edges_map[edge_id] = edge

        # 3. Sort edges deterministically by edge identity string
        sorted_edges: list[FrameworkSemanticEdge] = sorted(
            edges_map.values(),
            key=lambda e: (e.source_id, e.edge_type.value, e.target_id),
        )

        # 4. Construct immutable FrameworkSemanticGraph
        graph = FrameworkSemanticGraph()
        for node in sorted_nodes:
            graph = graph.add_node(node)
        for edge in sorted_edges:
            graph = graph.add_edge(edge)

        return graph
