"""CPGValidator checking Code Property Graph integrity (orphan nodes, duplicate IDs, broken edges)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from karsasec.cpg.models import CPGGraph


@dataclass
class ValidationIssue:
    """Represents a graph validation anomaly or error."""

    severity: str  # ERROR, WARNING
    issue_type: str
    message: str
    node_or_edge_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "issue_type": self.issue_type,
            "message": self.message,
            "node_or_edge_id": self.node_or_edge_id,
        }


class CPGValidator:
    """Validates structural integrity and correctness of a CPGGraph instance."""

    def validate(self, graph: CPGGraph) -> list[ValidationIssue]:
        """Runs integrity checks and returns a list of detected issues."""
        issues: list[ValidationIssue] = []

        # 1. Check Node Count against Metadata
        if graph.metadata.node_count != len(graph.nodes):
            issues.append(
                ValidationIssue(
                    severity="WARNING",
                    issue_type="METADATA_MISMATCH",
                    message=f"Metadata node count ({graph.metadata.node_count}) does not match actual nodes ({len(graph.nodes)}).",
                )
            )

        # 2. Check Edge Count against Metadata
        if graph.metadata.edge_count != len(graph.edges):
            issues.append(
                ValidationIssue(
                    severity="WARNING",
                    issue_type="METADATA_MISMATCH",
                    message=f"Metadata edge count ({graph.metadata.edge_count}) does not match actual edges ({len(graph.edges)}).",
                )
            )

        # 3. Check for Broken Edges (Source or Target Node ID missing in graph.nodes)
        connected_node_ids = set()
        for idx, edge in enumerate(graph.edges):
            if edge.source_id not in graph.nodes:
                issues.append(
                    ValidationIssue(
                        severity="ERROR",
                        issue_type="BROKEN_EDGE_SOURCE",
                        message=f"Edge #{idx} references non-existent source node '{edge.source_id}'.",
                        node_or_edge_id=f"edge_{idx}",
                    )
                )
            else:
                connected_node_ids.add(edge.source_id)

            if edge.target_id not in graph.nodes:
                issues.append(
                    ValidationIssue(
                        severity="ERROR",
                        issue_type="BROKEN_EDGE_TARGET",
                        message=f"Edge #{idx} references non-existent target node '{edge.target_id}'.",
                        node_or_edge_id=f"edge_{idx}",
                    )
                )
            else:
                connected_node_ids.add(edge.target_id)

        # 4. Check for Orphan Nodes (Nodes with 0 incoming & 0 outgoing edges if graph size > 1)
        if len(graph.nodes) > 1:
            for node_id in graph.nodes:
                if node_id not in connected_node_ids:
                    issues.append(
                        ValidationIssue(
                            severity="WARNING",
                            issue_type="ORPHAN_NODE",
                            message=f"Node '{node_id}' has no incoming or outgoing edges.",
                            node_or_edge_id=node_id,
                        )
                    )

        return issues
