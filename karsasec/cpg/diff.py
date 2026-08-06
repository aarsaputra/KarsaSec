"""GraphDiff Engine computing NodeDiff, EdgeDiff, and IncrementalPatch between two CPG graphs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from karsasec.cpg.models import CPGEdge, CPGGraph, CPGNode


@dataclass
class IncrementalPatch:
    """Represents changes required to transform old CPG into new CPG."""

    added_nodes: list[CPGNode] = field(default_factory=list)
    removed_node_ids: list[str] = field(default_factory=list)
    modified_nodes: list[CPGNode] = field(default_factory=list)
    added_edges: list[CPGEdge] = field(default_factory=list)
    removed_edges: list[CPGEdge] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "added_nodes_count": len(self.added_nodes),
            "removed_node_ids_count": len(self.removed_node_ids),
            "modified_nodes_count": len(self.modified_nodes),
            "added_edges_count": len(self.added_edges),
            "removed_edges_count": len(self.removed_edges),
        }


class GraphDiff:
    """Computes structural diffs between two CPGGraph instances."""

    def compare(self, old_graph: CPGGraph, new_graph: CPGGraph) -> IncrementalPatch:
        """Returns IncrementalPatch describing node and edge differences."""
        patch = IncrementalPatch()

        old_nodes = old_graph.nodes
        new_nodes = new_graph.nodes

        # Added Nodes
        for nid, node in new_nodes.items():
            if nid not in old_nodes:
                patch.added_nodes.append(node)
            else:
                # Check modified node
                if old_nodes[nid] != node:
                    patch.modified_nodes.append(node)

        # Removed Nodes
        for nid in old_nodes:
            if nid not in new_nodes:
                patch.removed_node_ids.append(nid)

        # Edge Diffs
        old_edges_set = {(e.source_id, e.target_id, e.edge_type.value) for e in old_graph.edges}
        new_edges_set = {(e.source_id, e.target_id, e.edge_type.value) for e in new_graph.edges}

        for e in new_graph.edges:
            key = (e.source_id, e.target_id, e.edge_type.value)
            if key not in old_edges_set:
                patch.added_edges.append(e)

        for e in old_graph.edges:
            key = (e.source_id, e.target_id, e.edge_type.value)
            if key not in new_edges_set:
                patch.removed_edges.append(e)

        return patch
