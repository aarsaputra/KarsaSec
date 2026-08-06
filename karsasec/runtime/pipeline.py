"""Runtime Analysis Pipeline orchestrating scan execution, DAG passes, and telemetry."""

from pathlib import Path

from karsasec.rules.enums import AnalysisCapability
from karsasec.rules.schema import Rule
from karsasec.runtime.planner import ExecutionPlanner


class AnalysisPipeline:
    """Orchestrates runtime analysis execution according to the dynamically planned DAG schedule."""

    def __init__(self) -> None:
        self.planner = ExecutionPlanner()

    def run_pipeline(self, target_path: Path, rules: list[Rule]) -> list[AnalysisCapability]:
        """Plans and executes required analysis passes dynamically for the given target and rule set."""
        execution_plan = self.planner.plan_for_rules(rules)
        return execution_plan
