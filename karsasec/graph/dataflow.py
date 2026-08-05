"""Dataflow Engine for tracking variable, assignment, parameter, and return value flows."""

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set
from karsasec.graph.graph import ProjectGraph
from karsasec.graph.node import GraphNode, NodeKind

class DataflowEdgeType(Enum):
    """Types of data flow transfers between program expressions."""
    ASSIGNMENT = "ASSIGNMENT"
    PARAMETER_PASS = "PARAMETER_PASS"
    RETURN_VALUE = "RETURN_VALUE"
    OPERATION = "OPERATION"

@dataclass(slots=True)
class DataflowNode:
    """Represents a dataflow tracking point (variable, expression, parameter, sink/source)."""
    node_id: str
    name: str
    qualified_name: str = ""
    file_path: Optional[Path] = None
    line: int = 1
    column: int = 0
    is_source: bool = False
    is_sink: bool = False

@dataclass(slots=True)
class DataflowEdge:
    """Represents a directional flow of data between two DataflowNodes."""
    source_id: str
    target_id: str
    edge_type: DataflowEdgeType = DataflowEdgeType.ASSIGNMENT
    label: str = ""

@dataclass(slots=True)
class DataflowPath:
    """Complete sequence of DataflowNodes and DataflowEdges connecting a source to a sink."""
    nodes: List[DataflowNode] = field(default_factory=list)
    edges: List[DataflowEdge] = field(default_factory=list)

class DataflowEngine:
    """Tracks variable, parameter, and return flows across AST nodes and ProjectGraph."""

    def __init__(self, project_graph: Optional[ProjectGraph] = None) -> None:
        self.project_graph = project_graph
        self.nodes: Dict[str, DataflowNode] = {}
        self.outgoing_edges: Dict[str, List[DataflowEdge]] = {}
        self.incoming_edges: Dict[str, List[DataflowEdge]] = {}

    def add_node(self, node: DataflowNode) -> None:
        """Registers a DataflowNode in the engine."""
        self.nodes[node.node_id] = node

    def add_flow(
        self,
        source_id: str,
        target_id: str,
        edge_type: DataflowEdgeType = DataflowEdgeType.ASSIGNMENT,
        label: str = "",
    ) -> DataflowEdge:
        """Adds a directional dataflow edge from source_id to target_id."""
        edge = DataflowEdge(
            source_id=source_id,
            target_id=target_id,
            edge_type=edge_type,
            label=label,
        )
        self.outgoing_edges.setdefault(source_id, []).append(edge)
        self.incoming_edges.setdefault(target_id, []).append(edge)
        return edge

    def trace_flow(self, source_id: str, sink_id: str) -> List[DataflowPath]:
        """Traces all reachable dataflow paths from source_id to sink_id."""
        if source_id not in self.nodes or sink_id not in self.nodes:
            return []

        paths: List[DataflowPath] = []
        # Queue stores tuples of (current_node_id, visited_set, node_path, edge_path)
        queue: deque[tuple[str, Set[str], List[str], List[DataflowEdge]]] = deque([
            (source_id, {source_id}, [source_id], [])
        ])

        while queue:
            curr_id, visited, node_path, edge_path = queue.popleft()

            if curr_id == sink_id:
                path_nodes = [self.nodes[nid] for nid in node_path if nid in self.nodes]
                paths.append(DataflowPath(nodes=path_nodes, edges=edge_path))
                continue

            for edge in self.outgoing_edges.get(curr_id, []):
                nxt_id = edge.target_id
                if nxt_id not in visited:
                    queue.append((
                        nxt_id,
                        visited | {nxt_id},
                        node_path + [nxt_id],
                        edge_path + [edge],
                    ))

        return paths

    def find_sources(self, sink_id: str) -> List[DataflowNode]:
        """Finds all origin nodes marked as sources that reach the given sink_id."""
        sources: List[DataflowNode] = []
        if sink_id not in self.nodes:
            return sources

        visited: Set[str] = {sink_id}
        queue: deque[str] = deque([sink_id])

        while queue:
            curr_id = queue.popleft()
            curr_node = self.nodes.get(curr_id)
            if curr_node and curr_node.is_source and curr_node not in sources:
                sources.append(curr_node)

            for edge in self.incoming_edges.get(curr_id, []):
                src_id = edge.source_id
                if src_id not in visited:
                    visited.add(src_id)
                    queue.append(src_id)

        return sources

    def find_sinks(self, source_id: str) -> List[DataflowNode]:
        """Finds all terminal nodes marked as sinks reachable from the given source_id."""
        sinks: List[DataflowNode] = []
        if source_id not in self.nodes:
            return sinks

        visited: Set[str] = {source_id}
        queue: deque[str] = deque([source_id])

        while queue:
            curr_id = queue.popleft()
            curr_node = self.nodes.get(curr_id)
            if curr_node and curr_node.is_sink and curr_node not in sinks:
                sinks.append(curr_node)

            for edge in self.outgoing_edges.get(curr_id, []):
                tgt_id = edge.target_id
                if tgt_id not in visited:
                    visited.add(tgt_id)
                    queue.append(tgt_id)

        return sinks
