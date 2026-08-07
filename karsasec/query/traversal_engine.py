"""Multi-hop Traversal Engine supporting Bidirectional BFS, Shortest Path, Reachability, Cycle Detection."""

from __future__ import annotations

from collections import deque

from karsasec.cpg.models import CPGGraph, EdgeType


class MultiHopTraversalEngine:
    """Generic Graph Traversal Engine supporting bounded multi-hop paths across CPG edges."""

    def __init__(self, graph: CPGGraph) -> None:
        self.graph = graph

    def reachability(
        self,
        source_id: str,
        target_id: str,
        edge_types: tuple[EdgeType | str, ...] | None = None,
        max_depth: int = 15,
    ) -> bool:
        path = self.shortest_path(source_id, target_id, edge_types, max_depth)
        return len(path) > 0

    def shortest_path(
        self,
        source_id: str,
        target_id: str,
        edge_types: tuple[EdgeType | str, ...] | None = None,
        max_depth: int = 15,
    ) -> list[str]:
        if source_id not in self.graph.nodes or target_id not in self.graph.nodes:
            return []
        if source_id == target_id:
            return [source_id]

        str_edge_types = set(e.value if isinstance(e, EdgeType) else e for e in edge_types) if edge_types else None

        queue: deque[tuple[str, list[str]]] = deque([(source_id, [source_id])])
        visited = {source_id}

        while queue:
            current, path = queue.popleft()
            if len(path) - 1 >= max_depth:
                continue

            for edge in self.graph.get_outgoing_edges(current):
                if str_edge_types and edge.edge_type.value not in str_edge_types:
                    continue
                nxt = edge.target_id
                if nxt == target_id:
                    return path + [nxt]
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append((nxt, path + [nxt]))

        return []

    def bidirectional_bfs(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 15,
    ) -> list[str]:
        if source_id not in self.graph.nodes or target_id not in self.graph.nodes:
            return []
        if source_id == target_id:
            return [source_id]

        forward_visited: dict[str, list[str]] = {source_id: [source_id]}
        backward_visited: dict[str, list[str]] = {target_id: [target_id]}

        forward_queue = deque([source_id])
        backward_queue = deque([target_id])

        for _ in range(max_depth):
            if not forward_queue or not backward_queue:
                break

            # Forward step
            curr_f = forward_queue.popleft()
            path_f = forward_visited[curr_f]
            for edge in self.graph.get_outgoing_edges(curr_f):
                nxt = edge.target_id
                if nxt in backward_visited:
                    return path_f + list(reversed(backward_visited[nxt]))
                if nxt not in forward_visited:
                    forward_visited[nxt] = path_f + [nxt]
                    forward_queue.append(nxt)

            # Backward step
            curr_b = backward_queue.popleft()
            path_b = backward_visited[curr_b]
            for edge in self.graph.get_incoming_edges(curr_b):
                prev = edge.source_id
                if prev in forward_visited:
                    return forward_visited[prev] + list(reversed(path_b))
                if prev not in backward_visited:
                    backward_visited[prev] = path_b + [prev]
                    backward_queue.append(prev)

        return []

    def detect_cycles(self, start_id: str, max_depth: int = 15) -> bool:
        visited: set[str] = set()
        rec_stack: set[str] = set()

        def dfs(curr: str, depth: int) -> bool:
            if depth > max_depth:
                return False
            visited.add(curr)
            rec_stack.add(curr)

            for edge in self.graph.get_outgoing_edges(curr):
                nxt = edge.target_id
                if nxt not in visited:
                    if dfs(nxt, depth + 1):
                        return True
                elif nxt in rec_stack:
                    return True

            rec_stack.remove(curr)
            return False

        return dfs(start_id, 0)

    def all_paths(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 10,
        max_paths: int = 50,
    ) -> list[list[str]]:
        results: list[list[str]] = []

        def dfs(curr: str, path: list[str]) -> None:
            if len(results) >= max_paths or len(path) > max_depth:
                return
            if curr == target_id:
                results.append(list(path))
                return

            for edge in self.graph.get_outgoing_edges(curr):
                nxt = edge.target_id
                if nxt not in path:
                    dfs(nxt, path + [nxt])

        dfs(source_id, [source_id])
        return results
