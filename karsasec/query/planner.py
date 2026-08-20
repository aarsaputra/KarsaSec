"""Query Planner converting Query AST to Execution Plan Node pure structure."""

from __future__ import annotations

from karsasec.query.ast import ExecutionPlanNode, QueryNode, StepType


class QueryPlanner:
    """Pure Planner transforming Query AST into an Execution Plan without reading CPG."""

    def create_plan(self, query_ast: QueryNode) -> ExecutionPlanNode:
        root_op = "SCAN"
        params: dict[str, str | int | None] = {"target_label": query_ast.target_label}
        cost = 100.0

        # Check if first step is WHERE on indexable attribute (ID, label, type, file_path, function_name)
        initial_steps = list(query_ast.steps)
        if initial_steps and initial_steps[0].step_type == StepType.WHERE and initial_steps[0].predicate:
            pred = initial_steps[0].predicate
            if (
                pred.target in ("id", "label", "node_type", "file_path", "function_name", "variable")
                and pred.operator == "EQUALS"
            ):
                root_op = "INDEX_LOOKUP"
                params["index_field"] = pred.target
                params["index_value"] = str(pred.value)
                cost = 1.0
                initial_steps.pop(0)

        current_node = ExecutionPlanNode(op_type=root_op, cost=cost, params=params)

        for step in initial_steps:
            if step.step_type == StepType.WHERE and step.predicate:
                child = ExecutionPlanNode(
                    op_type="FILTER",
                    cost=current_node.cost * 0.5,
                    params={"predicate": step.predicate.to_dict()},
                    children=(current_node,),
                )
                current_node = child

            elif step.step_type == StepType.TRAVERSE:
                child = ExecutionPlanNode(
                    op_type="TRAVERSE",
                    cost=current_node.cost * 2.0,
                    params={
                        "direction": step.direction,
                        "edge_type": step.edge_type,
                        "target_type": step.target_type,
                    },
                    children=(current_node,),
                )
                current_node = child

            elif step.step_type == StepType.LIMIT:
                child = ExecutionPlanNode(
                    op_type="LIMIT",
                    cost=current_node.cost,
                    params={"limit": step.limit},
                    children=(current_node,),
                )
                current_node = child

        if query_ast.projection_fields:
            current_node = ExecutionPlanNode(
                op_type="PROJECTION",
                cost=current_node.cost,
                params={"fields": list(query_ast.projection_fields)},
                children=(current_node,),
            )

        return current_node
