"""Deterministic Graph Predicate Engine with Resource Bounds Guard and Evidence Tracking."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from karsasec.framework.framework_semantics.rules.taint_evaluator import (
    DANGEROUS_SINKS,
    SinkCompatibility,
    TaintEvaluator,
    evaluate_sink_compatibility,
)
from karsasec.framework.semantic_models import (
    FrameworkSemanticGraph,
    FrameworkSemanticNode,
    SemanticEdgeType,
    SemanticNodeType,
)


@dataclass
class PredicateEvaluationResult:
    """Result of evaluating a predicate on a node."""
    matched: bool
    evidence_node_ids: tuple[str, ...] = ()
    evidence_edge_ids: tuple[str, ...] = ()


@dataclass
class GraphRuleEvaluationContext:
    """Evaluation context enforcing resource bounds and visited-set cycle protection."""
    graph: FrameworkSemanticGraph
    max_depth: int = 1
    max_nodes_visited: int = 100
    max_edges_examined: int = 200
    visited_nodes: set[str] = field(default_factory=set)
    nodes_visited_count: int = 0
    edges_examined_count: int = 0

    def can_visit_node(self, node_id: str, depth: int) -> bool:
        """Returns True if traversal bounds permit visiting node_id at current depth."""
        if depth > self.max_depth:
            return False
        if self.nodes_visited_count >= self.max_nodes_visited:
            return False
        if node_id in self.visited_nodes:
            return False
        return True

    def visit_node(self, node_id: str) -> None:
        """Records a visited node ID and increments visit counter."""
        self.visited_nodes.add(node_id)
        self.nodes_visited_count += 1

    def record_edge_examination(self, count: int = 1) -> bool:
        """Increments examined edge counter and returns True if within limit."""
        self.edges_examined_count += count
        return self.edges_examined_count <= self.max_edges_examined


def evaluate_condition_block(
    node: FrameworkSemanticNode,
    cond: dict[str, Any],
    ctx: GraphRuleEvaluationContext,
    depth: int = 0,
) -> PredicateEvaluationResult:
    """Evaluates a condition dictionary against node in the given evaluation context."""
    if not ctx.can_visit_node(node.id, depth):
        return PredicateEvaluationResult(matched=False)

    all_ev_nodes: list[str] = []
    all_ev_edges: list[str] = []

    for key, val in cond.items():
        res = _evaluate_single_predicate(node, key, val, ctx, depth)
        if not res.matched:
            return PredicateEvaluationResult(matched=False)

        all_ev_nodes.extend(res.evidence_node_ids)
        all_ev_edges.extend(res.evidence_edge_ids)

    # Sort evidence deterministically
    sorted_ev_nodes = tuple(sorted(set(all_ev_nodes)))
    sorted_ev_edges = tuple(sorted(set(all_ev_edges)))
    return PredicateEvaluationResult(matched=True, evidence_node_ids=sorted_ev_nodes, evidence_edge_ids=sorted_ev_edges)


def _evaluate_single_predicate(
    node: FrameworkSemanticNode,
    key: str,
    val: Any,
    ctx: GraphRuleEvaluationContext,
    depth: int,
) -> PredicateEvaluationResult:
    if key == "all":
        ev_nodes: list[str] = []
        ev_edges: list[str] = []
        for sub_cond in val:
            res = evaluate_condition_block(node, sub_cond, ctx, depth)
            if not res.matched:
                return PredicateEvaluationResult(matched=False)
            ev_nodes.extend(res.evidence_node_ids)
            ev_edges.extend(res.evidence_edge_ids)
        return PredicateEvaluationResult(
            matched=True,
            evidence_node_ids=tuple(sorted(set(ev_nodes))),
            evidence_edge_ids=tuple(sorted(set(ev_edges))),
        )

    if key == "any":
        ev_nodes: list[str] = []
        ev_edges: list[str] = []
        any_matched = False
        for sub_cond in val:
            res = evaluate_condition_block(node, sub_cond, ctx, depth)
            if res.matched:
                any_matched = True
                ev_nodes.extend(res.evidence_node_ids)
                ev_edges.extend(res.evidence_edge_ids)

        if any_matched:
            return PredicateEvaluationResult(
                matched=True,
                evidence_node_ids=tuple(sorted(set(ev_nodes))),
                evidence_edge_ids=tuple(sorted(set(ev_edges))),
            )
        return PredicateEvaluationResult(matched=False)

    if key == "not":
        res = evaluate_condition_block(node, val, ctx, depth)
        # Logical NOT: matched if sub-condition evaluated to False
        return PredicateEvaluationResult(matched=not res.matched)

    if key == "node_type_equals":
        target_type = SemanticNodeType(str(val).upper())
        matched = node.node_type == target_type
        return PredicateEvaluationResult(matched=matched)

    if key == "has_attribute":
        matched = str(val) in node.attributes
        return PredicateEvaluationResult(matched=matched)

    if key == "attribute_equals":
        attr_key = val["key"]
        expected_val = val["value"]
        actual_val = node.attributes.get(attr_key)
        matched = actual_val == expected_val
        return PredicateEvaluationResult(matched=matched)

    if key == "attribute_contains":
        attr_key = val["key"]
        expected_val = val["value"]
        actual_val = node.attributes.get(attr_key)
        matched = False
        if actual_val is not None:
            if isinstance(actual_val, (list, tuple, set)):
                matched = expected_val in actual_val
            elif isinstance(actual_val, str):
                matched = str(expected_val) in actual_val
            elif isinstance(actual_val, dict):
                matched = expected_val in actual_val
        return PredicateEvaluationResult(matched=matched)

    if key == "incoming_edge":
        return _evaluate_incoming_edge(node, val, ctx, depth)

    if key == "outgoing_edge":
        return _evaluate_outgoing_edge(node, val, ctx, depth)

    if key == "edge_count":
        return _evaluate_edge_count(node, val, ctx)

    if key == "flow_taint_state_equals":
        derived_state = TaintEvaluator.evaluate_flow_taint_state(node, ctx.graph)
        matched = derived_state == str(val).upper()
        return PredicateEvaluationResult(matched=matched)

    if key == "source_kind_equals":
        matched = str(node.attributes.get("source_kind", "")) == str(val)
        return PredicateEvaluationResult(matched=matched)

    if key == "sink_kind_equals":
        matched = str(node.attributes.get("sink_kind", "")) == str(val)
        return PredicateEvaluationResult(matched=matched)

    if key == "is_sink_compatible":
        trans_sym = str(node.attributes.get("sanitizer_symbols", [None])[0] if node.attributes.get("sanitizer_symbols") else "")
        sink_kind = str(node.attributes.get("sink_kind", ""))
        compat = evaluate_sink_compatibility(trans_sym, sink_kind)
        matched = compat == SinkCompatibility(str(val).upper())
        return PredicateEvaluationResult(matched=matched)

    if key == "is_dangerous_sink":
        sink_kind = str(node.attributes.get("sink_kind", ""))
        matched = bool(val) == (sink_kind in DANGEROUS_SINKS)
        return PredicateEvaluationResult(matched=matched)

    return PredicateEvaluationResult(matched=False)


def _evaluate_incoming_edge(
    node: FrameworkSemanticNode,
    spec: dict[str, Any],
    ctx: GraphRuleEvaluationContext,
    depth: int,
) -> PredicateEvaluationResult:
    req_edge_type = SemanticEdgeType(spec["type"].upper()) if "type" in spec else None
    req_source_type = SemanticNodeType(spec["source_type"].upper()) if "source_type" in spec else None
    req_attributes = spec.get("attributes", {})
    req_source_attributes = spec.get("source_attributes", {})

    incoming_edges = ctx.graph.get_incoming_edges(node.id)
    if not ctx.record_edge_examination(len(incoming_edges)):
        return PredicateEvaluationResult(matched=False)

    ev_nodes: list[str] = []
    ev_edges: list[str] = []
    matched = False

    for edge in incoming_edges:
        if req_edge_type and edge.edge_type != req_edge_type:
            continue

        source_node = ctx.graph.node(edge.source_id)
        if not source_node:
            continue

        if req_source_type and source_node.node_type != req_source_type:
            continue

        attr_match = True
        for ak, av in req_attributes.items():
            if edge.attributes.get(ak) != av:
                attr_match = False
                break

        if attr_match and req_source_attributes:
            for ak, av in req_source_attributes.items():
                if source_node.attributes.get(ak) != av:
                    attr_match = False
                    break

        if attr_match:
            matched = True
            ev_nodes.append(source_node.id)
            # Edge identity: source_id -> target_id (and edge_type)
            edge_id_str = f"{edge.source_id}:{edge.edge_type.value}:{edge.target_id}"
            ev_edges.append(edge_id_str)

    if matched:
        return PredicateEvaluationResult(
            matched=True,
            evidence_node_ids=tuple(sorted(set(ev_nodes))),
            evidence_edge_ids=tuple(sorted(set(ev_edges))),
        )
    return PredicateEvaluationResult(matched=False)


def _evaluate_outgoing_edge(
    node: FrameworkSemanticNode,
    spec: dict[str, Any],
    ctx: GraphRuleEvaluationContext,
    depth: int,
) -> PredicateEvaluationResult:
    req_edge_type = SemanticEdgeType(spec["type"].upper()) if "type" in spec else None
    req_target_type = SemanticNodeType(spec["target_type"].upper()) if "target_type" in spec else None
    req_attributes = spec.get("attributes", {})
    req_target_attributes = spec.get("target_attributes", {})

    outgoing_edges = ctx.graph.get_outgoing_edges(node.id)
    if not ctx.record_edge_examination(len(outgoing_edges)):
        return PredicateEvaluationResult(matched=False)

    ev_nodes: list[str] = []
    ev_edges: list[str] = []
    matched = False

    for edge in outgoing_edges:
        if req_edge_type and edge.edge_type != req_edge_type:
            continue

        target_node = ctx.graph.node(edge.target_id)
        if not target_node:
            continue

        if req_target_type and target_node.node_type != req_target_type:
            continue

        attr_match = True
        for ak, av in req_attributes.items():
            if edge.attributes.get(ak) != av:
                attr_match = False
                break

        if attr_match and req_target_attributes:
            for ak, av in req_target_attributes.items():
                if target_node.attributes.get(ak) != av:
                    attr_match = False
                    break

        if attr_match:
            matched = True
            ev_nodes.append(target_node.id)
            edge_id_str = f"{edge.source_id}:{edge.edge_type.value}:{edge.target_id}"
            ev_edges.append(edge_id_str)

    if matched:
        return PredicateEvaluationResult(
            matched=True,
            evidence_node_ids=tuple(sorted(set(ev_nodes))),
            evidence_edge_ids=tuple(sorted(set(ev_edges))),
        )
    return PredicateEvaluationResult(matched=False)


def _evaluate_edge_count(
    node: FrameworkSemanticNode,
    spec: dict[str, Any],
    ctx: GraphRuleEvaluationContext,
) -> PredicateEvaluationResult:
    direction = spec.get("direction", "incoming").lower()
    min_count = int(spec.get("min_count", 0))
    max_count = spec.get("max_count")

    if direction == "incoming":
        edges = ctx.graph.get_incoming_edges(node.id)
    else:
        edges = ctx.graph.get_outgoing_edges(node.id)

    count = len(edges)
    matched = count >= min_count and (max_count is None or count <= int(max_count))
    return PredicateEvaluationResult(matched=matched)
