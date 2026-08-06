"""Query Optimizer performing predicate pushdown, capability selection, and logical execution planning."""

from dataclasses import dataclass

from karsasec.rules.enums import AnalysisCapability


@dataclass(frozen=True)
class LogicalPlan:
    target_kind: str
    pushed_predicates: list[str]
    required_capabilities: set[AnalysisCapability]
    estimated_cost_ms: float = 5.0


class QueryOptimizer:
    """Optimizes Query DSL definitions by pushing down predicates and determining minimal capability sets."""

    def optimize(self, target_kind: str, predicates: list[str]) -> LogicalPlan:
        # Predicate pushdown logic: filter out early AST predicates from expensive flow predicates
        pushed = [p for p in predicates if "callee" in p or "node_type" in p]
        pushed.extend([p for p in predicates if p not in pushed])

        req_caps: set[AnalysisCapability] = {AnalysisCapability.AST}
        if any("tainted" in p or "flow" in p for p in predicates):
            req_caps.add(AnalysisCapability.DATAFLOW)
            req_caps.add(AnalysisCapability.SEMANTIC)
        elif any("symbol" in p or "scope" in p for p in predicates):
            req_caps.add(AnalysisCapability.SEMANTIC)

        return LogicalPlan(
            target_kind=target_kind,
            pushed_predicates=pushed,
            required_capabilities=req_caps,
            estimated_cost_ms=len(predicates) * 2.5,
        )


query_optimizer = QueryOptimizer()
