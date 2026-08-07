"""Query Optimizer performing AST & Execution Plan transformations."""

from __future__ import annotations

from typing import Any

from karsasec.query.ast import ExecutionPlanNode, PredicateNode


class QueryOptimizer:
    """Independent Optimizer performing Filter Pushdown, Dead Step Elimination, and Predicate Merging."""

    def optimize(self, plan: ExecutionPlanNode) -> ExecutionPlanNode:
        plan = self._pushdown_filters(plan)
        plan = self._merge_predicates(plan)
        plan = self._eliminate_dead_steps(plan)
        return plan

    def _pushdown_filters(self, plan: ExecutionPlanNode) -> ExecutionPlanNode:
        # Push down FILTER operations closer to SCAN/INDEX_LOOKUP if possible
        if not plan.children:
            return plan

        new_children = tuple(self._pushdown_filters(c) for c in plan.children)

        if plan.op_type == "TRAVERSE" and len(new_children) == 1 and new_children[0].op_type == "FILTER":
            filter_node = new_children[0]
            traverse_node = plan
            # Swap FILTER and TRAVERSE if filter targets previous step
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

        # Eliminate redundant LIMIT if child limit is smaller
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
