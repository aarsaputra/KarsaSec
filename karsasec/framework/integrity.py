"""FrameworkGraphIntegrityChecker for validating graph topology and invariants."""

from __future__ import annotations

import logging
from collections import defaultdict, deque

from karsasec.framework.diagnostics import ErrorCode, SemanticDiagnostic, Severity
from karsasec.framework.semantic_models import FrameworkSemanticGraph

logger = logging.getLogger("karsasec.framework.integrity")


class FrameworkGraphIntegrityChecker:
    """Checker verifying structural integrity, edge connectivity, cycles, and connectivity of graph."""

    def check(self, graph: FrameworkSemanticGraph) -> list[SemanticDiagnostic]:
        """Runs full suite of graph integrity checks."""
        diagnostics: list[SemanticDiagnostic] = []
        nodes = graph.get_nodes_dict()
        edges = graph.edges()

        # 1. Broken / Dangling Edges
        for edge in edges:
            if edge.source_id not in nodes:
                diagnostics.append(
                    SemanticDiagnostic(
                        code=ErrorCode.GENERIC_VALIDATION_ERROR,
                        severity=Severity.ERROR,
                        message=f"Dangling edge source node '{edge.source_id}' does not exist in graph",
                        evidence=f"Edge source: {edge.source_id} -> {edge.target_id}",
                    )
                )
            if edge.target_id not in nodes:
                diagnostics.append(
                    SemanticDiagnostic(
                        code=ErrorCode.GENERIC_VALIDATION_ERROR,
                        severity=Severity.ERROR,
                        message=f"Dangling edge target node '{edge.target_id}' does not exist in graph",
                        evidence=f"Edge target: {edge.source_id} -> {edge.target_id}",
                    )
                )

        # 2. Duplicate Edge Check
        seen_edges: set[tuple[str, str, str]] = set()
        for edge in edges:
            key = (edge.source_id, edge.target_id, edge.edge_type.value)
            if key in seen_edges:
                diagnostics.append(
                    SemanticDiagnostic(
                        code=ErrorCode.GENERIC_VALIDATION_ERROR,
                        severity=Severity.WARNING,
                        message=f"Duplicate edge detected: {edge.source_id} -[{edge.edge_type.value}]-> {edge.target_id}",
                        evidence=f"{edge.source_id} -> {edge.target_id}",
                    )
                )
            else:
                seen_edges.add(key)

        # 3. Cycle Detection (DFS)
        adj: dict[str, list[str]] = defaultdict(list)
        for edge in edges:
            adj[edge.source_id].append(edge.target_id)

        visited: dict[str, int] = {n_id: 0 for n_id in nodes}  # 0=unvisited, 1=visiting, 2=visited

        def dfs(node_id: str) -> bool:
            visited[node_id] = 1
            for neighbor in adj[node_id]:
                if visited.get(neighbor) == 1:
                    return True
                if visited.get(neighbor) == 0:
                    if dfs(neighbor):
                        return True
            visited[node_id] = 2
            return False

        for node_id in nodes:
            if visited[node_id] == 0:
                if dfs(node_id):
                    diagnostics.append(
                        SemanticDiagnostic(
                            code=ErrorCode.GENERIC_VALIDATION_ERROR,
                            severity=Severity.WARNING,
                            message=f"Cycle detected in graph starting at node '{node_id}'",
                            evidence=node_id,
                        )
                    )

        # 4. Disconnected Components Warning
        if nodes and len(nodes) > 1:
            undirected_adj: dict[str, set[str]] = defaultdict(set)
            for edge in edges:
                undirected_adj[edge.source_id].add(edge.target_id)
                undirected_adj[edge.target_id].add(edge.source_id)

            visited_set: set[str] = set()
            components_count = 0

            for node_id in nodes:
                if node_id not in visited_set:
                    components_count += 1
                    queue = deque([node_id])
                    visited_set.add(node_id)
                    while queue:
                        curr = queue.popleft()
                        for neighbor in undirected_adj[curr]:
                            if neighbor not in visited_set:
                                visited_set.add(neighbor)
                                queue.append(neighbor)

            if components_count > 1:
                diagnostics.append(
                    SemanticDiagnostic(
                        code=ErrorCode.GENERIC_VALIDATION_ERROR,
                        severity=Severity.INFO,
                        message=f"Graph contains {components_count} disconnected subcomponents",
                        evidence=f"components={components_count}",
                    )
                )

        return diagnostics
