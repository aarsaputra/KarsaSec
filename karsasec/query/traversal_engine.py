"""Multi-hop Traversal Engine supporting Bidirectional BFS, DFS, Shortest Path, Reachability, and Cycle Detection with State Isolation."""

from __future__ import annotations

from collections import deque

from karsasec.cpg.models import CPGGraph, EdgeType


class MultiHopTraversalEngine:
    """Generic Graph Traversal Engine supporting bounded multi-hop paths across CPG edges with SSA and call context state isolation."""

    MAX_CALL_CONTEXT_DEPTH: int = 32
    MAX_CONTEXT_STRING_LEN: int = 256

    def __init__(self, graph: CPGGraph) -> None:
        self.graph = graph

    def _get_node_state(self, node_id: str) -> tuple[str, str, str]:
        """Extracts immutable state tuple (node_id, ssa_version, call_context) for a given node ID."""
        node = self.graph.nodes.get(node_id)
        if node is None:
            return (node_id, "v0", "global")

        ssa_v = (
            node.attributes.get("ssa_version")
            or node.attributes.get("variable_version")
            or node.attributes.get("version")
            or "v0"
        )
        c_ctx = (
            node.attributes.get("call_context")
            or node.attributes.get("context")
            or node.attributes.get("function_name")
            or "global"
        )

        # Enforce call-context string length bound to prevent memory explosion during deep context growth
        c_ctx_str = str(c_ctx)
        if len(c_ctx_str) > self.MAX_CONTEXT_STRING_LEN:
            c_ctx_str = c_ctx_str[: self.MAX_CONTEXT_STRING_LEN]

        return (node_id, str(ssa_v), c_ctx_str)

    def reachability(
        self,
        source_id: str,
        target_id: str,
        edge_types: tuple[EdgeType | str, ...] | None = None,
        max_depth: int = 15,
    ) -> bool:
        """Determines graph reachability using deterministic BFS."""
        if max_depth < 0:
            return False
        return self.bfs_reachability(source_id, target_id, edge_types, max_depth)

    def bfs_reachability(
        self,
        source_id: str,
        target_id: str,
        edge_types: tuple[EdgeType | str, ...] | None = None,
        max_depth: int = 15,
    ) -> bool:
        """Bounded BFS reachability using (node_id, ssa_version, call_context) visited state tracking."""
        if max_depth < 0:
            return False
        path = self.shortest_path(source_id, target_id, edge_types, max_depth)
        return len(path) > 0

    def dfs_reachability(
        self,
        source_id: str,
        target_id: str,
        edge_types: tuple[EdgeType | str, ...] | None = None,
        max_depth: int = 15,
    ) -> bool:
        """Bounded DFS reachability using (node_id, ssa_version, call_context) visited state tracking."""
        if max_depth < 0:
            return False
        if source_id not in self.graph.nodes or target_id not in self.graph.nodes:
            return False
        if source_id == target_id:
            return True


        str_edge_types = set(e.value if isinstance(e, EdgeType) else e for e in edge_types) if edge_types else None
        visited: set[tuple[str, str, str]] = set()

        def dfs(curr_id: str, depth: int) -> bool:
            if depth > max_depth:
                return False

            state = self._get_node_state(curr_id)
            if state in visited:
                return False
            visited.add(state)

            if curr_id == target_id:
                return True

            for edge in self.graph.get_outgoing_edges(curr_id):
                if str_edge_types and edge.edge_type.value not in str_edge_types:
                    continue
                if dfs(edge.target_id, depth + 1):
                    return True

            return False

        return dfs(source_id, 0)

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
        visited: set[tuple[str, str, str]] = {self._get_node_state(source_id)}

        while queue:
            current, path = queue.popleft()
            if len(path) - 1 >= max_depth:
                continue

            for edge in self.graph.get_outgoing_edges(current):
                if str_edge_types and edge.edge_type.value not in str_edge_types:
                    continue
                nxt = edge.target_id
                nxt_state = self._get_node_state(nxt)

                if nxt == target_id:
                    return path + [nxt]

                if nxt_state not in visited:
                    visited.add(nxt_state)
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

            curr_f = forward_queue.popleft()
            path_f = forward_visited[curr_f]
            for edge in self.graph.get_outgoing_edges(curr_f):
                nxt = edge.target_id
                if nxt in backward_visited:
                    return path_f + list(reversed(backward_visited[nxt]))
                if nxt not in forward_visited:
                    forward_visited[nxt] = path_f + [nxt]
                    forward_queue.append(nxt)

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
        visited: set[tuple[str, str, str]] = set()
        rec_stack: set[tuple[str, str, str]] = set()

        def dfs(curr: str, depth: int) -> bool:
            if depth > max_depth:
                return False

            state = self._get_node_state(curr)
            visited.add(state)
            rec_stack.add(state)

            for edge in self.graph.get_outgoing_edges(curr):
                nxt = edge.target_id
                nxt_state = self._get_node_state(nxt)

                if nxt_state not in visited:
                    if dfs(nxt, depth + 1):
                        return True
                elif nxt_state in rec_stack:
                    return True

            rec_stack.remove(state)
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

