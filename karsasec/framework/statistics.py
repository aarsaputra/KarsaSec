"""GraphStatistics engine calculating graph metrics, counts, density, depth, and components."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any

from karsasec.framework.semantic_models import FrameworkSemanticGraph, SemanticNodeType


@dataclass(frozen=True)
class GraphStatistics:
    """Dataclass holding semantic graph topology statistics."""

    node_count: int
    edge_count: int
    route_count: int
    controller_count: int
    middleware_count: int
    handler_count: int
    model_count: int
    density: float
    depth: int
    connected_components: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "route_count": self.route_count,
            "controller_count": self.controller_count,
            "middleware_count": self.middleware_count,
            "handler_count": self.handler_count,
            "model_count": self.model_count,
            "density": self.density,
            "depth": self.depth,
            "connected_components": self.connected_components,
        }

    @classmethod
    def compute(cls, graph: FrameworkSemanticGraph) -> GraphStatistics:
        nodes = graph.get_nodes_dict()
        edges = graph.edges()

        node_count = len(nodes)
        edge_count = len(edges)

        route_count = sum(1 for n in nodes.values() if n.node_type == SemanticNodeType.ROUTE)
        controller_count = sum(1 for n in nodes.values() if n.node_type == SemanticNodeType.CONTROLLER)
        middleware_count = sum(1 for n in nodes.values() if n.node_type == SemanticNodeType.MIDDLEWARE)
        handler_count = sum(1 for n in nodes.values() if n.node_type == SemanticNodeType.HANDLER)
        model_count = sum(1 for n in nodes.values() if n.node_type == SemanticNodeType.MODEL)

        # Density: E / (V * (V - 1)) for directed graph
        density = 0.0
        if node_count > 1:
            density = edge_count / (node_count * (node_count - 1))

        # Adjacency for depth & connected components
        adj: dict[str, list[str]] = defaultdict(list)
        undirected_adj: dict[str, set[str]] = defaultdict(set)
        in_degree: dict[str, int] = {n: 0 for n in nodes}

        for e in edges:
            if e.source_id in nodes and e.target_id in nodes:
                adj[e.source_id].append(e.target_id)
                undirected_adj[e.source_id].add(e.target_id)
                undirected_adj[e.target_id].add(e.source_id)
                in_degree[e.target_id] += 1

        # Max depth (longest path in DAG via BFS from root nodes with in_degree == 0)
        roots = [n for n, deg in in_degree.items() if deg == 0]
        max_depth = 0
        if roots:
            for root in roots:
                q = deque([(root, 0)])
                visited_depth: dict[str, int] = {}
                while q:
                    curr, d = q.popleft()
                    if d > max_depth:
                        max_depth = d
                    for nxt in adj[curr]:
                        if nxt not in visited_depth or d + 1 > visited_depth[nxt]:
                            visited_depth[nxt] = d + 1
                            q.append((nxt, d + 1))

        # Connected components (undirected BFS)
        visited_nodes: set[str] = set()
        components = 0
        for n_id in nodes:
            if n_id not in visited_nodes:
                components += 1
                q = deque([n_id])
                visited_nodes.add(n_id)
                while q:
                    curr = q.popleft()
                    for neighbor in undirected_adj[curr]:
                        if neighbor not in visited_nodes:
                            visited_nodes.add(neighbor)
                            q.append(neighbor)

        return cls(
            node_count=node_count,
            edge_count=edge_count,
            route_count=route_count,
            controller_count=controller_count,
            middleware_count=middleware_count,
            handler_count=handler_count,
            model_count=model_count,
            density=round(density, 6),
            depth=max_depth,
            connected_components=components,
        )
