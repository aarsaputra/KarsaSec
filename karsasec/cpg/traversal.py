"""GraphTraversal providing DFS, BFS, Reverse DFS, Reachability, and Shortest Path algorithms for CPGGraph."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable

from karsasec.cpg.models import CPGEdge, CPGGraph, CPGNode


class GraphTraversal:
    """Provides algorithms for traversing CPGGraph nodes and edges."""

    def __init__(self, graph: CPGGraph) -> None:
        self.graph: CPGGraph = graph

    def dfs(self, start_id: str, callback: Callable[[CPGNode], None] | None = None) -> list[CPGNode]:
        """Performs Depth-First Search starting from start_id."""
        visited: set[str] = set()
        result: list[CPGNode] = []
        stack: list[str] = [start_id]

        while stack:
            curr_id = stack.pop()
            if curr_id in visited or curr_id not in self.graph.nodes:
                continue

            visited.add(curr_id)
            node = self.graph.nodes[curr_id]
            result.append(node)
            if callback:
                callback(node)

            for edge in self.graph.get_outgoing_edges(curr_id):
                if edge.target_id not in visited:
                    stack.append(edge.target_id)

        return result

    def bfs(self, start_id: str, callback: Callable[[CPGNode], None] | None = None) -> list[CPGNode]:
        """Performs Breadth-First Search starting from start_id."""
        visited: set[str] = set()
        result: list[CPGNode] = []
        queue: deque[str] = deque([start_id])

        while queue:
            curr_id = queue.popleft()
            if curr_id in visited or curr_id not in self.graph.nodes:
                continue

            visited.add(curr_id)
            node = self.graph.nodes[curr_id]
            result.append(node)
            if callback:
                callback(node)

            for edge in self.graph.get_outgoing_edges(curr_id):
                if edge.target_id not in visited:
                    queue.append(edge.target_id)

        return result

    def reverse_dfs(self, start_id: str) -> list[CPGNode]:
        """Performs Reverse DFS following incoming edges backwards."""
        visited: set[str] = set()
        result: list[CPGNode] = []
        stack: list[str] = [start_id]

        while stack:
            curr_id = stack.pop()
            if curr_id in visited or curr_id not in self.graph.nodes:
                continue

            visited.add(curr_id)
            node = self.graph.nodes[curr_id]
            result.append(node)

            for edge in self.graph.get_incoming_edges(curr_id):
                if edge.source_id not in visited:
                    stack.append(edge.source_id)

        return result

    def reachability(self, start_id: str, target_id: str) -> bool:
        """Returns True if target_id is reachable from start_id."""
        visited: set[str] = set()
        queue: deque[str] = deque([start_id])

        while queue:
            curr_id = queue.popleft()
            if curr_id == target_id:
                return True

            visited.add(curr_id)
            for edge in self.graph.get_outgoing_edges(curr_id):
                if edge.target_id not in visited:
                    queue.append(edge.target_id)

        return False

    def shortest_path(self, start_id: str, target_id: str) -> list[CPGEdge]:
        """Finds the shortest edge path between start_id and target_id using BFS."""
        if start_id == target_id:
            return []

        visited: set[str] = {start_id}
        queue: deque[tuple[str, list[CPGEdge]]] = deque([(start_id, [])])

        while queue:
            curr_id, path = queue.popleft()

            for edge in self.graph.get_outgoing_edges(curr_id):
                if edge.target_id == target_id:
                    return path + [edge]

                if edge.target_id not in visited:
                    visited.add(edge.target_id)
                    queue.append((edge.target_id, path + [edge]))

        return []
