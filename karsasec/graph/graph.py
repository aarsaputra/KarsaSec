"""Graph representations holding nodes, edges, and index mappings for ProjectGraph and CallGraph."""

from karsasec.graph.edge import GraphEdge
from karsasec.graph.node import GraphNode
from karsasec.graph.types import CallEdge, CallNode


class ProjectGraph:
    """Project-wide Code Property Graph storing structural, call, and dataflow relations."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []

        # Index maps for fast O(1) graph traversal
        self.node_by_qname: dict[str, GraphNode] = {}
        self.call_site_to_edge: dict[str, GraphEdge] = {}
        self.outgoing_edges: dict[str, list[GraphEdge]] = {}
        self.incoming_edges: dict[str, list[GraphEdge]] = {}

    def add_node(self, node: GraphNode) -> None:
        """Adds a GraphNode to the graph and indexes by UUID and qualified name."""
        self.nodes[node.uuid] = node
        if node.qualified_name:
            self.node_by_qname[node.qualified_name] = node

    def add_edge(self, edge: GraphEdge) -> None:
        """Adds a GraphEdge to the graph and updates directional indices."""
        self.edges.append(edge)
        if edge.call_site_id:
            self.call_site_to_edge[edge.call_site_id] = edge

        self.outgoing_edges.setdefault(edge.caller_id, []).append(edge)
        self.incoming_edges.setdefault(edge.callee_id, []).append(edge)

    def get_node(self, uuid: str) -> GraphNode | None:
        """Retrieves a node by its UUID."""
        return self.nodes.get(uuid)

    def get_node_by_qname(self, qualified_name: str) -> GraphNode | None:
        """Retrieves a node by its fully qualified name."""
        return self.node_by_qname.get(qualified_name)

    def get_outgoing(self, node_id: str) -> list[GraphEdge]:
        """Returns outgoing edges from the specified node."""
        return self.outgoing_edges.get(node_id, [])

    def get_incoming(self, node_id: str) -> list[GraphEdge]:
        """Returns incoming edges to the specified node."""
        return self.incoming_edges.get(node_id, [])


class CallGraph:
    """Directed call graph representing invocation relationships in the audited codebase.

    Preserved for backward compatibility with existing CallGraphBuilder and SymbolPredicate.
    """

    def __init__(self) -> None:
        self.nodes: dict[str, CallNode] = {}
        self.edges: list[CallEdge] = []

        # Indexes for fast lookup
        self.call_site_to_edge: dict[str, CallEdge] = {}
        self.caller_to_edges: dict[str, list[CallEdge]] = {}
        self.callee_to_edges: dict[str, list[CallEdge]] = {}

    def add_node(self, node: CallNode) -> None:
        """Adds a CallNode to the graph."""
        self.nodes[node.node_id] = node

    def add_edge(self, edge: CallEdge) -> None:
        """Adds a CallEdge to the graph and indexes it."""
        self.edges.append(edge)
        if edge.call_site_id:
            self.call_site_to_edge[edge.call_site_id] = edge

        self.caller_to_edges.setdefault(edge.caller_id, []).append(edge)
        self.callee_to_edges.setdefault(edge.callee_id, []).append(edge)

    def get_node(self, node_id: str) -> CallNode | None:
        """Retrieves a node by its ID."""
        return self.nodes.get(node_id)

    def get_callers(self, callee_id: str) -> list[CallNode]:
        """Returns the list of nodes that invoke the specified callee."""
        edges = self.callee_to_edges.get(callee_id, [])
        callers = []
        for e in edges:
            caller = self.get_node(e.caller_id)
            if caller:
                callers.append(caller)
        return callers

    def get_callees(self, caller_id: str) -> list[CallNode]:
        """Returns the list of nodes invoked by the specified caller."""
        edges = self.caller_to_edges.get(caller_id, [])
        callees = []
        for e in edges:
            callee = self.get_node(e.callee_id)
            if callee:
                callees.append(callee)
        return callees
