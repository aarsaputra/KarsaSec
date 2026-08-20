"""Graph Query API for querying ProjectGraph structural and behavioral paths."""

from collections import deque

from karsasec.graph.edge import EdgeType, GraphEdge
from karsasec.graph.graph import ProjectGraph
from karsasec.graph.node import GraphNode


class GraphQueryAPI:
    """Standardized API interface for performing graph queries on a ProjectGraph."""

    def __init__(self, graph: ProjectGraph) -> None:
        self.graph = graph

    def find_symbol(self, name: str) -> list[GraphNode]:
        """Finds all GraphNodes matching the given symbol name or qualified name."""
        results: list[GraphNode] = []
        for node in self.graph.nodes.values():
            if node.qualified_name == name or node.qualified_name.endswith("." + name) or name in node.qualified_name:
                results.append(node)
        return results

    def find_definition(self, symbol: str) -> GraphNode | None:
        """Finds the definition node matching a fully qualified or exact symbol name."""
        # Check direct index first
        exact_node = self.graph.get_node_by_qname(symbol)
        if exact_node:
            return exact_node

        # Suffix matching fallback
        for node in self.graph.nodes.values():
            if node.qualified_name.endswith("." + symbol):
                return node
        return None

    def find_calls(self, target_qname: str) -> list[GraphEdge]:
        """Finds all CALLS edges targeting the specified qualified symbol name."""
        results: list[GraphEdge] = []
        for edge in self.graph.edges:
            if edge.edge_type == EdgeType.CALLS:
                if edge.resolved_symbol == target_qname or edge.resolved_symbol.endswith("." + target_qname):
                    results.append(edge)
                else:
                    callee_node = self.graph.get_node(edge.callee_id)
                    if callee_node and (
                        callee_node.qualified_name == target_qname
                        or callee_node.qualified_name.endswith("." + target_qname)
                    ):
                        results.append(edge)
        return results

    def find_reference(self, symbol: str) -> list[GraphNode]:
        """Finds all nodes that call, import, or reference the specified symbol."""
        refs: set[str] = set()
        calls = self.find_calls(symbol)
        for edge in calls:
            refs.add(edge.caller_id)

        target_def = self.find_definition(symbol)
        if target_def:
            for edge in self.graph.get_incoming(target_def.uuid):
                refs.add(edge.caller_id)

        return [self.graph.nodes[node_id] for node_id in refs if node_id in self.graph.nodes]

    def successors(self, node_id: str) -> list[GraphNode]:
        """Returns direct successor nodes reached by outgoing edges from node_id."""
        edges = self.graph.get_outgoing(node_id)
        nodes: list[GraphNode] = []
        for edge in edges:
            target = self.graph.get_node(edge.callee_id)
            if target and target not in nodes:
                nodes.append(target)
        return nodes

    def predecessors(self, node_id: str) -> list[GraphNode]:
        """Returns direct predecessor nodes pointing to node_id."""
        edges = self.graph.get_incoming(node_id)
        nodes: list[GraphNode] = []
        for edge in edges:
            source = self.graph.get_node(edge.caller_id)
            if source and source not in nodes:
                nodes.append(source)
        return nodes

    def reachable(self, start_node_id: str, end_node_id: str) -> bool:
        """Determines if end_node_id is reachable from start_node_id via directed edges."""
        if start_node_id == end_node_id:
            return True
        if start_node_id not in self.graph.nodes or end_node_id not in self.graph.nodes:
            return False

        visited: set[str] = {start_node_id}
        queue: deque[str] = deque([start_node_id])

        while queue:
            curr_id = queue.popleft()
            if curr_id == end_node_id:
                return True

            for edge in self.graph.get_outgoing(curr_id):
                nxt_id = edge.callee_id
                if nxt_id not in visited:
                    visited.add(nxt_id)
                    queue.append(nxt_id)

        return False

    def shortest_path(self, start_node_id: str, end_node_id: str) -> list[GraphEdge]:
        """Returns the shortest sequence of GraphEdges from start_node_id to end_node_id using BFS."""
        if start_node_id not in self.graph.nodes or end_node_id not in self.graph.nodes:
            return []

        visited: set[str] = {start_node_id}
        # Queue stores tuples of (current_node_id, path_of_edges)
        queue: deque[tuple[str, list[GraphEdge]]] = deque([(start_node_id, [])])

        while queue:
            curr_id, path = queue.popleft()
            if curr_id == end_node_id:
                return path

            for edge in self.graph.get_outgoing(curr_id):
                nxt_id = edge.callee_id
                if nxt_id not in visited:
                    visited.add(nxt_id)
                    queue.append((nxt_id, path + [edge]))

        return []
