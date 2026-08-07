"""Multi-stage Rule Compiler (YAML -> Rule AST -> Query AST -> Execution Plan)."""

from __future__ import annotations

from typing import Any

from karsasec.query.ast import ExecutionPlanNode, QueryNode
from karsasec.query.optimizer import QueryOptimizer
from karsasec.query.planner import QueryPlanner
from karsasec.rules.adapter import LegacyRuleAdapter
from karsasec.rules.validator import RuleValidator


class RuleCompiler:
    """Multi-stage Rule Compiler producing optimized Execution Plans from YAML rule dictionaries."""

    def __init__(self) -> None:
        self.validator = RuleValidator()
        self.adapter = LegacyRuleAdapter()
        self.planner = QueryPlanner()
        self.optimizer = QueryOptimizer()

    def compile(self, rule_data: dict[str, Any]) -> tuple[QueryNode, ExecutionPlanNode]:
        # 1. Validate
        self.validator.validate(rule_data)

        # 2. Adapt to Query AST
        query_ast = self.adapter.adapt(rule_data)

        # 3. Create Plan
        raw_plan = self.planner.create_plan(query_ast)

        # 4. Optimize Plan
        optimized_plan = self.optimizer.optimize(raw_plan)

        return query_ast, optimized_plan
