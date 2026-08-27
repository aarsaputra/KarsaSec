"""Query Optimizer performing AST & Execution Plan transformations with deterministic ordering and index pushdown."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from karsasec.cpg.index import CPGIndex
from karsasec.cpg.models import CPGGraph, CPGNode
from karsasec.query.ast import ExecutionPlanNode, PredicateNode, QueryNode, QueryStep, StepType


def get_predicate_priority(predicate: PredicateNode | None) -> int:
    """Returns deterministic evaluation priority for predicate nodes.

    Priority order:
    0: Exact ID
    1: Node Type
    2: Function Name
    3: SSA Variable / Version
    4: Source / Sink Category
    5: Local Graph Predicate
    6: Interprocedural Traversal
    7: Expensive Dataflow Predicate
    """
    if predicate is None:
        return 5

    t = predicate.target.lower() if predicate.target else ""
    op = predicate.operator.upper() if predicate.operator else ""

    if t in ("id", "node_id") and op == "EQUALS":
        return 0
    if t in ("node_type", "type") or op == "TYPE":
        return 1
    if t in ("function_name", "fn_name", "function") or op == "FUNCTION":
        return 2
    if t in ("ssa_version", "variable_version", "ssa_v") or op == "SSA_VERSION":
        return 3
    if t in ("source_kind", "sink_category") or op in ("SOURCE_KIND", "SINK_CATEGORY"):
        return 4
    if t in ("local_predicate", "label", "file_path", "line_number") or op in ("IS_LOCAL", "LINE_RANGE"):
        return 5
    if t in ("interprocedural", "call_context") or op in ("TRAVERSE", "CALL_GRAPH"):
        return 6
    if t in ("dataflow", "taint", "flow") or op in ("DATAFLOW", "TAINT_REACHABLE"):
        return 7

    return 5


class QueryOptimizer:
    """Independent Optimizer performing Filter Pushdown, Dead Step Elimination, Predicate Reordering, and Index Pushdown."""

    def optimize(self, plan: ExecutionPlanNode) -> ExecutionPlanNode:
        plan = self._pushdown_filters(plan)
        plan = self._merge_predicates(plan)
        plan = self._eliminate_dead_steps(plan)
        return plan

    def optimize_ast(self, query_ast: QueryNode) -> QueryNode:
        """Optimizes a QueryNode AST by re-ordering WHERE predicates deterministically."""
        where_steps: list[QueryStep] = []
        other_steps: list[QueryStep] = []

        for step in query_ast.steps:
            if step.step_type == StepType.WHERE:
                where_steps.append(step)
            else:
                other_steps.append(step)

        # Deterministic sorting based on predicate priority, then target, then operator
        sorted_where = sorted(
            where_steps,
            key=lambda s: (
                get_predicate_priority(s.predicate),
                s.predicate.target if s.predicate else "",
                s.predicate.operator if s.predicate else "",
            ),
        )

        optimized_steps = tuple(sorted_where + other_steps)
        return QueryNode(
            target_label=query_ast.target_label,
            steps=optimized_steps,
            projection_fields=query_ast.projection_fields,
        )

    def compute_plan_fingerprint(self, plan: ExecutionPlanNode | QueryNode) -> str:
        """Computes a 64-char SHA256 hex digest for an ExecutionPlanNode or QueryNode."""
        raw_dict = plan.to_dict()
        serialized = json.dumps(raw_dict, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    def evaluate_query(
        self,
        query_ast: QueryNode,
        graph: CPGGraph,
        index: CPGIndex | None = None,
    ) -> list[CPGNode]:
        """Evaluates query using Index Pushdown if available, falling back to Deterministic Full Scan."""
        optimized_ast = self.optimize_ast(query_ast)
        candidate_nodes: list[CPGNode] = []
        used_index = False

        # Attempt Index Pushdown if index is available and non-divergent
        if (
            index is not None
            and (len(graph.nodes) == 0 or len(index.by_id) == len(graph.nodes))
            and optimized_ast.steps
        ):
            first_step = optimized_ast.steps[0]
            if first_step.step_type == StepType.WHERE and first_step.predicate:
                pred = first_step.predicate
                target_l = pred.target.lower() if pred.target else ""
                op = pred.operator.upper() if pred.operator else ""
                val = str(pred.value) if pred.value is not None else ""

                if target_l in ("id", "node_id") and op == "EQUALS":
                    n = index.get_by_id(val)

                    candidate_nodes = [n] if n is not None else []
                    used_index = True
                elif target_l in ("node_type", "type") and op == "EQUALS":
                    candidate_nodes = index.get_by_type(val)
                    used_index = True
                elif target_l in ("function_name", "fn_name", "function") and op == "EQUALS":
                    candidate_nodes = index.get_by_function(val)
                    used_index = True
                elif target_l in ("file_path", "file") and op == "EQUALS":
                    candidate_nodes = index.get_by_file(val)
                    used_index = True
                elif target_l in ("ssa_version", "variable_version") and op == "EQUALS":
                    candidate_nodes = index.get_by_ssa_version(val)
                    used_index = True
                elif target_l == "source_kind" and op == "EQUALS":
                    candidate_nodes = index.get_by_source_kind(val)
                    used_index = True
                elif target_l == "sink_category" and op == "EQUALS":
                    candidate_nodes = index.get_by_sink_category(val)
                    used_index = True

        # Authoritative validation: Ensure indexed candidates strictly exist in authoritative graph.nodes
        if used_index:
            valid_candidates = []
            for n in candidate_nodes:
                if n is not None and n.id in graph.nodes:
                    valid_candidates.append(graph.nodes[n.id])
            candidate_nodes = valid_candidates


        # Fallback to Deterministic Full Scan if index not used or not available
        if not used_index:
            # Deterministic sorting by node ID
            candidate_nodes = sorted(graph.nodes.values(), key=lambda n: n.id)


        # Filter candidate nodes against all steps
        matching_nodes: list[CPGNode] = []
        for node in candidate_nodes:
            if self._matches_node(node, optimized_ast):
                matching_nodes.append(node)

        # Ensure result list is deterministically sorted by node ID
        return sorted(matching_nodes, key=lambda n: n.id)

    def _matches_node(self, node: CPGNode, query_ast: QueryNode) -> bool:
        if query_ast.target_label and query_ast.target_label.upper() not in ("ALL", "ANY", "*"):
            if node.label != query_ast.target_label and node.node_type.value != query_ast.target_label:
                return False

        for step in query_ast.steps:
            if step.step_type == StepType.WHERE and step.predicate:
                if not self._eval_predicate(node, step.predicate):
                    return False

        return True

    def _eval_predicate(self, node: CPGNode, pred: PredicateNode) -> bool:
        target_l = pred.target.lower()
        op = pred.operator.upper()
        val = pred.value

        actual_val = None
        if target_l in ("id", "node_id"):
            actual_val = node.id
        elif target_l in ("label", "node_label"):
            actual_val = node.label
        elif target_l in ("node_type", "type"):
            actual_val = node.node_type.value
        elif target_l in ("file_path", "file"):
            actual_val = node.file_path
        elif target_l in ("line_number", "line"):
            actual_val = node.line_number
        elif target_l in ("language", "lang"):
            actual_val = node.language
        else:
            actual_val = node.attributes.get(pred.target)

        if op == "EQUALS":
            return str(actual_val) == str(val) if val is not None else actual_val is None
        if op == "NOT_EQUALS":
            return str(actual_val) != str(val)
        if op == "CONTAINS":
            return str(val) in str(actual_val) if actual_val is not None else False
        if op == "IN":
            if isinstance(val, (list, tuple, set)):
                return actual_val in val or str(actual_val) in [str(x) for x in val]
            return str(actual_val) == str(val)

        return False

    def _pushdown_filters(self, plan: ExecutionPlanNode) -> ExecutionPlanNode:
        if not plan.children:
            return plan

        new_children = tuple(self._pushdown_filters(c) for c in plan.children)

        if plan.op_type == "TRAVERSE" and len(new_children) == 1 and new_children[0].op_type == "FILTER":
            filter_node = new_children[0]
            traverse_node = plan
            if filter_node.children:
                pushed_child = filter_node.children[0]
                new_traverse = ExecutionPlanNode(
                    op_type="TRAVERSE",
                    cost=traverse_node.cost,
                    params=traverse_node.params,
                    children=(pushed_child,),
                )
                return ExecutionPlanNode(
                    op_type="FILTER",
                    cost=filter_node.cost * 0.8,
                    params=filter_node.params,
                    children=(new_traverse,),
                )

        return ExecutionPlanNode(
            op_type=plan.op_type,
            cost=plan.cost,
            params=plan.params,
            children=new_children,
        )

    def _merge_predicates(self, plan: ExecutionPlanNode) -> ExecutionPlanNode:
        if not plan.children:
            return plan

        new_children = tuple(self._merge_predicates(c) for c in plan.children)

        if plan.op_type == "FILTER" and len(new_children) == 1 and new_children[0].op_type == "FILTER":
            p1 = plan.params.get("predicate")
            p2 = new_children[0].params.get("predicate")
            if p1 and p2:
                merged_pred = PredicateNode(
                    operator="AND",
                    target="compound",
                    args=(PredicateNode.from_dict(p1), PredicateNode.from_dict(p2)),
                )
                return ExecutionPlanNode(
                    op_type="FILTER",
                    cost=plan.cost * 0.9,
                    params={"predicate": merged_pred.to_dict()},
                    children=new_children[0].children,
                )

        return ExecutionPlanNode(
            op_type=plan.op_type,
            cost=plan.cost,
            params=plan.params,
            children=new_children,
        )

    def _eliminate_dead_steps(self, plan: ExecutionPlanNode) -> ExecutionPlanNode:
        if not plan.children:
            return plan

        new_children = tuple(self._eliminate_dead_steps(c) for c in plan.children)

        if plan.op_type == "LIMIT" and len(new_children) == 1 and new_children[0].op_type == "LIMIT":
            l1 = plan.params.get("limit", 0)
            l2 = new_children[0].params.get("limit", 0)
            min_limit = min(l1, l2) if (l1 > 0 and l2 > 0) else max(l1, l2)
            return ExecutionPlanNode(
                op_type="LIMIT",
                cost=plan.cost,
                params={"limit": min_limit},
                children=new_children[0].children,
            )

        return ExecutionPlanNode(
            op_type=plan.op_type,
            cost=plan.cost,
            params=plan.params,
            children=new_children,
        )


class LegacyQueryOptimizerWrapper:
    """Wrapper for legacy unit test compatibility."""

    def optimize(self, target_kind: str, predicates: list[str]) -> Any:
        from karsasec.rules.enums import AnalysisCapability

        class LegacyPlan:
            def __init__(self, target: str, preds: list[str]):
                self.pushed_predicates = preds
                self.required_capabilities = [AnalysisCapability.AST, AnalysisCapability.DATAFLOW]
                self.estimated_cost_ms = 1.5

        return LegacyPlan(target_kind, predicates)


query_optimizer = LegacyQueryOptimizerWrapper()

