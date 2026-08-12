"""Semantic Interprocedural Dataflow Provenance Model (E12-15).

Design Principles & Guardrails:
  - Immutable semantic representation of interprocedural taint flow and evidence provenance.
  - Strict SSA-like variable versioning (var_version: $x#1 vs $x#2) per context.
  - Context-aware call isolation (CallContext) preventing cross-contamination between call sites.
  - Multi-path semantic function summaries (FunctionSummary).
  - Explicit provenance edges (PASSES_PARAMETER, RETURNS, TRANSFORMS, GUARDED_BY, ASSIGNED_FROM, etc.).
  - Anti-hardcoding: Language-agnostic, rule-agnostic, pure semantic graph model.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from karsasec.graph.dataflow.abstract_state import SemanticConstraint, TaintState, join_constraints, join_taint_state


class ProvenanceNodeKind(StrEnum):
    """Categorization of nodes within the Dataflow Provenance Graph."""
    SOURCE = "SOURCE"
    ASSIGNMENT = "ASSIGNMENT"
    TRANSFORMATION = "TRANSFORMATION"
    PARAMETER = "PARAMETER"
    CALL = "CALL"
    GUARD = "GUARD"
    RETURN = "RETURN"
    SINK = "SINK"


class ProvenanceEdgeKind(StrEnum):
    """Semantic relationship types connecting dataflow provenance nodes.

    Edge Vocabulary & Semantic Contracts:
      - DERIVES_FROM: Node value is computed or derived from source node value.
      - ASSIGNED_FROM: Direct assignment ($a = $b) from source to target variable version.
      - PASSES_PARAMETER: Call site argument bound to function parameter context.
      - RETURNS: Function return path value propagated to caller destination variable.
      - CALLS: Function invocation relationship between caller block and callee.
      - TRANSFORMS: Transformation applied to value (e.g., intval, htmlspecialchars).
      - GUARDED_BY: Node state is constrained/gated by a path-sensitive guard condition.
      - SANITY_CHECKED_BY: Input validation check performed on node value.
      - MODIFIED_BY: Variable re-assignment or side-effect modification of existing variable.
      - REACHES: Control/data reachability between statements or nodes.
      - INVALIDATED_BY: Re-assignment kills previous SSA version or constraint.
    """
    DERIVES_FROM = "DERIVES_FROM"
    ASSIGNED_FROM = "ASSIGNED_FROM"
    PASSES_PARAMETER = "PASSES_PARAMETER"
    RETURNS = "RETURNS"
    CALLS = "CALLS"
    TRANSFORMS = "TRANSFORMS"
    GUARDED_BY = "GUARDED_BY"
    SANITY_CHECKED_BY = "SANITY_CHECKED_BY"
    MODIFIED_BY = "MODIFIED_BY"
    REACHES = "REACHES"
    INVALIDATED_BY = "INVALIDATED_BY"


@dataclass(frozen=True, slots=True)
class ProvenanceNode:
    """Immutable dataflow provenance node recording variable versioning and semantic state."""
    node_id: str
    kind: ProvenanceNodeKind
    var_name: str
    var_version: str
    file_path: str = ""
    function_name: str = ""
    block_id: str = ""
    statement: str = ""
    constraints: frozenset[SemanticConstraint] = field(default_factory=frozenset)
    taint_state: TaintState = TaintState.UNKNOWN
    call_site_id: str = ""


@dataclass(frozen=True, slots=True)
class ProvenanceEdge:
    """Directed semantic relationship edge connecting two provenance nodes."""
    src_node_id: str
    target_node_id: str
    kind: ProvenanceEdgeKind
    call_site_id: str = ""
    condition: str = ""


@dataclass(frozen=True, slots=True)
class CallContext:
    """Distinct semantic context for a function invocation at a specific call site."""
    caller_file: str
    caller_function: str
    line_number: int
    callee_function: str
    call_site_id: str
    depth: int = 0
    callee_file: str = ""

    def sub_context(self, sub_callee: str, sub_file: str, line_number: int, call_site_id: str) -> CallContext:
        """Create a nested child call context."""
        return CallContext(
            caller_file=self.callee_file or self.caller_file,
            caller_function=self.callee_function,
            line_number=line_number,
            callee_function=sub_callee,
            call_site_id=call_site_id,
            depth=self.depth + 1,
            callee_file=sub_file,
        )


class SummaryStatus(StrEnum):
    """Semantic confidence / completeness classification of FunctionSummary."""
    PRECISE = "PRECISE"
    PARTIAL = "PARTIAL"
    UNKNOWN = "UNKNOWN"
    NON_CONVERGED = "NON_CONVERGED"


@dataclass(frozen=True, slots=True)
class PathSummary:
    """A single control-flow path summary within a function."""
    path_id: str
    return_expr: str = ""
    return_var: str = ""
    taint_state: TaintState = TaintState.UNKNOWN
    constraints: frozenset[SemanticConstraint] = field(default_factory=frozenset)
    parameter_dependencies: tuple[str, ...] = ()
    param_constraints: tuple[tuple[str, str], ...] = ()
    transformations: tuple[str, ...] = ()
    guards: tuple[str, ...] = ()
    sink_dependencies: tuple[str, ...] = ()
    call_dependencies: tuple[str, ...] = ()
    provenance_node_ids: tuple[str, ...] = ()
    is_guarded: bool = False
    guard_description: str = ""

    def to_canonical_dict(self) -> dict[str, Any]:
        """Convert PathSummary to a canonical dictionary representation for hashing."""
        return {
            "path_id": self.path_id,
            "return_expr": self.return_expr,
            "return_var": self.return_var,
            "taint_state": str(self.taint_state),
            "constraints": sorted([c.value for c in self.constraints]),
            "parameter_dependencies": sorted(self.parameter_dependencies),
            "param_constraints": sorted([(p, c) for p, c in self.param_constraints]),
            "transformations": sorted(self.transformations),
            "guards": sorted(self.guards),
            "sink_dependencies": sorted(self.sink_dependencies),
            "call_dependencies": sorted(self.call_dependencies),
            "provenance_node_ids": sorted(self.provenance_node_ids),
            "is_guarded": self.is_guarded,
            "guard_description": self.guard_description,
        }


@dataclass(frozen=True, slots=True)
class FunctionSummary:
    """Formal semantic summary describing interprocedural dataflow effects of a function."""
    function_name: str
    file_path: str
    parameters: tuple[str, ...] = ()
    path_summaries: tuple[PathSummary, ...] = ()
    sink_effects: tuple[dict[str, Any], ...] = ()
    status: SummaryStatus = SummaryStatus.PRECISE
    is_complete: bool = True
    is_recursive: bool = False

    def joined_return_state(self) -> tuple[TaintState, frozenset[SemanticConstraint]]:
        """Compute conservative join of all return paths using lattice semantics."""
        if not self.path_summaries:
            return TaintState.UNKNOWN, frozenset()

        joined_taint = self.path_summaries[0].taint_state
        joined_constraints = set(self.path_summaries[0].constraints)

        for path in self.path_summaries[1:]:
            joined_taint = join_taint_state(joined_taint, path.taint_state)
            joined_constraints = set(join_constraints(joined_constraints, path.constraints))

        return joined_taint, frozenset(joined_constraints)

    def normalize(self) -> FunctionSummary:
        """Return a new FunctionSummary with deterministically sorted path summaries and parameters."""
        sorted_paths = tuple(
            sorted(
                self.path_summaries,
                key=lambda p: (
                    p.path_id,
                    p.return_expr,
                    str(p.taint_state),
                    tuple(sorted([c.value for c in p.constraints])),
                )
            )
        )
        return FunctionSummary(
            function_name=self.function_name,
            file_path=self.file_path,
            parameters=tuple(self.parameters),
            path_summaries=sorted_paths,
            sink_effects=self.sink_effects,
            status=self.status,
            is_complete=self.is_complete,
            is_recursive=self.is_recursive,
        )

    def semantic_fingerprint(self) -> str:
        """Compute a byte-for-byte SHA-256 fingerprint based on canonical representation."""
        norm = self.normalize()
        payload = {
            "function_name": norm.function_name,
            "file_path": norm.file_path,
            "parameters": list(norm.parameters),
            "status": str(norm.status),
            "is_complete": norm.is_complete,
            "is_recursive": norm.is_recursive,
            "path_summaries": [p.to_canonical_dict() for p in norm.path_summaries],
        }
        json_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(json_bytes).hexdigest()



class DataflowProvenanceGraph:
    """Deterministic Directed Semantic Dataflow Provenance Graph.

    Graph Topology & Cycle Semantics:
      - The graph is a directed semantic graph capturing multi-procedural dataflow facts.
      - Cyclic structures (e.g. recursive calls f -> f or A -> B -> A) are permitted in graph topology.
      - Traversal and path-finding routines (e.g. find_paths) utilize active-stack visited tracking
        to guarantee termination and prevent infinite loops during fixpoint analysis.
    """

    def __init__(self) -> None:
        self._nodes: dict[str, ProvenanceNode] = {}
        self._edges: list[ProvenanceEdge] = []
        self._outgoing: dict[str, list[ProvenanceEdge]] = {}
        self._incoming: dict[str, list[ProvenanceEdge]] = {}

    def add_node(self, node: ProvenanceNode) -> None:
        """Add a provenance node deterministically."""
        self._nodes[node.node_id] = node

    def add_edge(self, edge: ProvenanceEdge) -> None:
        """Add a directed provenance edge and index directional lookup maps."""
        self._edges.append(edge)
        self._outgoing.setdefault(edge.src_node_id, []).append(edge)
        self._incoming.setdefault(edge.target_node_id, []).append(edge)

    def get_node(self, node_id: str) -> ProvenanceNode | None:
        """Retrieve a provenance node by node_id."""
        return self._nodes.get(node_id)

    def get_nodes(self) -> list[ProvenanceNode]:
        """Return list of all nodes in insertion order."""
        return list(self._nodes.values())

    def get_edges(self) -> list[ProvenanceEdge]:
        """Return list of all directed edges."""
        return list(self._edges)

    def get_predecessors(self, node_id: str) -> list[ProvenanceNode]:
        """Return list of predecessor nodes for a given node_id."""
        preds = []
        for edge in self._incoming.get(node_id, []):
            p_node = self._nodes.get(edge.src_node_id)
            if p_node:
                preds.append(p_node)
        return preds

    def get_successors(self, node_id: str) -> list[ProvenanceNode]:
        """Return list of successor nodes for a given node_id."""
        succs = []
        for edge in self._outgoing.get(node_id, []):
            s_node = self._nodes.get(edge.target_node_id)
            if s_node:
                succs.append(s_node)
        return succs

    def find_paths(self, start_node_id: str, target_node_id: str, _visited: set[str] | None = None) -> list[list[str]]:
        """Find all deterministic paths from start_node_id to target_node_id with cycle protection."""
        visited = _visited or set()
        if start_node_id in visited:
            return []
        visited.add(start_node_id)

        if start_node_id == target_node_id:
            return [[start_node_id]]

        paths = []
        for edge in self._outgoing.get(start_node_id, []):
            sub_paths = self.find_paths(edge.target_node_id, target_node_id, visited.copy())
            for sp in sub_paths:
                paths.append([start_node_id] + sp)

        return paths

    def find_path(self, start_node_id: str, target_node_id: str) -> list[str] | None:
        """Find a single path from start_node_id to target_node_id."""
        all_p = self.find_paths(start_node_id, target_node_id)
        return all_p[0] if all_p else None
