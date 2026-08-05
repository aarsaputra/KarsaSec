"""Runtime Execution Planner and Capability Dependency Scheduler."""

from typing import Dict, List, Set, Tuple
from karsasec.rules.enums import AnalysisCapability
from karsasec.rules.schema import Rule


CAPABILITY_DEPENDENCIES: Dict[AnalysisCapability, List[AnalysisCapability]] = {
    AnalysisCapability.AST: [],
    AnalysisCapability.POSITION: [AnalysisCapability.AST],
    AnalysisCapability.COMMENTS: [AnalysisCapability.AST],
    AnalysisCapability.HIERARCHY: [AnalysisCapability.AST],
    AnalysisCapability.SEMANTIC: [AnalysisCapability.AST, AnalysisCapability.HIERARCHY],
    AnalysisCapability.TYPE_INFO: [AnalysisCapability.SEMANTIC],
    AnalysisCapability.CONTROL_FLOW: [AnalysisCapability.AST],
    AnalysisCapability.CALLGRAPH: [AnalysisCapability.SEMANTIC],
    AnalysisCapability.DATAFLOW: [AnalysisCapability.SEMANTIC, AnalysisCapability.CALLGRAPH],
}


class CapabilityDependencyPlanner:
    """Computes transitive closure and topological execution order of required analysis capabilities."""

    def resolve_execution_order(self, required_capabilities: Set[AnalysisCapability]) -> List[AnalysisCapability]:
        """Resolves required capabilities and their prerequisites into a topologically sorted execution plan."""
        expanded: Set[AnalysisCapability] = set()

        def visit(cap: AnalysisCapability) -> None:
            if cap not in expanded:
                for prereq in CAPABILITY_DEPENDENCIES.get(cap, []):
                    visit(prereq)
                expanded.add(cap)

        for cap in required_capabilities:
            visit(cap)

        # Topological sorting based on capability hierarchy depth
        order_map = {
            AnalysisCapability.AST: 0,
            AnalysisCapability.POSITION: 1,
            AnalysisCapability.COMMENTS: 1,
            AnalysisCapability.HIERARCHY: 1,
            AnalysisCapability.SEMANTIC: 2,
            AnalysisCapability.TYPE_INFO: 3,
            AnalysisCapability.CONTROL_FLOW: 2,
            AnalysisCapability.CALLGRAPH: 3,
            AnalysisCapability.DATAFLOW: 4,
        }

        return sorted(list(expanded), key=lambda c: order_map.get(c, 99))


class ExecutionPlanner:
    """Inspects active rule sets and plans optimal analysis pipeline passes."""

    def __init__(self) -> None:
        self.dep_planner = CapabilityDependencyPlanner()

    def plan_for_rules(self, rules: List[Rule]) -> List[AnalysisCapability]:
        """Analyzes required capabilities declared in active rules and computes minimal DAG execution plan."""
        required: Set[AnalysisCapability] = {AnalysisCapability.AST}

        for rule in rules:
            if rule.analysis and rule.analysis.requires:
                for req_str in rule.analysis.requires:
                    try:
                        cap = AnalysisCapability(req_str.lower())
                        required.add(cap)
                    except ValueError:
                        pass

        return self.dep_planner.resolve_execution_order(required)
