"""First-Class Interprocedural Call Graph & Tarjan SCC Engine (E12-16).

Design Principles & Guardrails:
  - Language-agnostic, rule-agnostic call graph abstraction.
  - Deterministic node & edge identities (file_path::function_name).
  - Explicit resolution statuses: RESOLVED, MULTIPLE, UNRESOLVED, DYNAMIC.
  - Deterministic Tarjan Strongly Connected Components (SCC) algorithm for recursion cycles.
  - Anti-hardcoding: Pure graph representation without rule-ID or benchmark strings.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class CallResolutionStatus(StrEnum):
    """Classification of call site symbol resolution."""

    RESOLVED = "RESOLVED"
    MULTIPLE = "MULTIPLE"
    UNRESOLVED = "UNRESOLVED"
    DYNAMIC = "DYNAMIC"


@dataclass(frozen=True, slots=True)
class CallGraphNode:
    """Immutable node representation of a function or method definition in the CallGraph."""

    node_id: str
    file_path: str
    function_name: str
    class_name: str = ""
    namespace: str = ""

    @property
    def qualified_name(self) -> str:
        parts = []
        if self.namespace:
            parts.append(self.namespace)
        if self.class_name:
            parts.append(self.class_name)
        parts.append(self.function_name)
        return "::".join(parts)


@dataclass(frozen=True, slots=True)
class CallGraphEdge:
    """Directed invocation edge between a caller function and a callee function."""

    caller_id: str
    callee_id: str
    call_site_id: str
    source_location: str = ""
    line_number: int = 0
    resolution_status: CallResolutionStatus = CallResolutionStatus.RESOLVED


class CallGraph:
    """Deterministic Interprocedural Call Graph with Tarjan SCC Partitioning."""

    def __init__(self) -> None:
        self._nodes: dict[str, CallGraphNode] = {}
        self._edges: list[CallGraphEdge] = []
        self._outgoing: dict[str, list[CallGraphEdge]] = {}
        self._incoming: dict[str, list[CallGraphEdge]] = {}

    def add_function(self, node: CallGraphNode) -> None:
        """Register a function definition in the call graph."""
        self._nodes[node.node_id] = node

    def add_call(self, edge: CallGraphEdge) -> None:
        """Register a call edge between caller and callee."""
        self._edges.append(edge)
        self._outgoing.setdefault(edge.caller_id, []).append(edge)
        self._incoming.setdefault(edge.callee_id, []).append(edge)

    def get_node(self, node_id: str) -> CallGraphNode | None:
        """Retrieve node by node_id."""
        return self._nodes.get(node_id)

    def nodes(self) -> list[CallGraphNode]:
        """Return list of all registered nodes sorted deterministically by node_id."""
        return [self._nodes[k] for k in sorted(self._nodes.keys())]

    def edges(self) -> list[CallGraphEdge]:
        """Return list of all call edges sorted deterministically."""
        return sorted(self._edges, key=lambda e: (e.caller_id, e.callee_id, e.call_site_id, e.line_number))

    def get_callees(self, caller_id: str) -> list[CallGraphNode]:
        """Return list of callee nodes for a caller_id."""
        callees = []
        for edge in self._outgoing.get(caller_id, []):
            c_node = self._nodes.get(edge.callee_id)
            if c_node and c_node not in callees:
                callees.append(c_node)
        return sorted(callees, key=lambda n: n.node_id)

    def get_callers(self, callee_id: str) -> list[CallGraphNode]:
        """Return list of caller nodes for a callee_id."""
        callers = []
        for edge in self._incoming.get(callee_id, []):
            c_node = self._nodes.get(edge.caller_id)
            if c_node and c_node not in callers:
                callers.append(c_node)
        return sorted(callers, key=lambda n: n.node_id)

    def get_call_sites(self, caller_id: str) -> list[CallGraphEdge]:
        """Return list of outgoing call edges for a caller_id."""
        return sorted(self._outgoing.get(caller_id, []), key=lambda e: (e.callee_id, e.call_site_id, e.line_number))

    def strongly_connected_components(self) -> list[list[str]]:
        """Compute Strongly Connected Components (SCCs) using Tarjan's algorithm.

        Returns:
            List of components, where each component is a list of node_ids sorted deterministically.
            The list of components is sorted in reverse topological order (bottom-up execution order).
        """
        index = 0
        stack: list[str] = []
        on_stack: set[str] = set()
        indices: dict[str, int] = {}
        lowlink: dict[str, int] = {}
        sccs: list[list[str]] = []

        all_node_ids = sorted(self._nodes.keys())

        def strongconnect(v: str) -> None:
            nonlocal index
            indices[v] = index
            lowlink[v] = index
            index += 1
            stack.append(v)
            on_stack.add(v)

            # Direct callees
            callee_ids = sorted({e.callee_id for e in self._outgoing.get(v, []) if e.callee_id in self._nodes})
            for w in callee_ids:
                if w not in indices:
                    strongconnect(w)
                    lowlink[v] = min(lowlink[v], lowlink[w])
                elif w in on_stack:
                    lowlink[v] = min(lowlink[v], indices[w])

            if lowlink[v] == indices[v]:
                scc: list[str] = []
                while True:
                    w = stack.pop()
                    on_stack.remove(w)
                    scc.append(w)
                    if w == v:
                        break
                sccs.append(sorted(scc))

        for v in all_node_ids:
            if v not in indices:
                strongconnect(v)

        return sccs
