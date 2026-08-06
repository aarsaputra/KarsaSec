"""DataFlowPass compiler pipeline pass executing Data Flow Analysis."""

from __future__ import annotations

from typing import Any

from karsasec.analysis.cfg.models import CFG
from karsasec.analysis.dataflow.builder import DataFlowBuilder
from karsasec.analysis.ssa.models import SSAFunction
from karsasec.core.pipeline.base_pass import AnalysisPass
from karsasec.core.pipeline.context import PassContext


class DataFlowPass(AnalysisPass):
    """Compiler pipeline pass that executes Data Flow Analysis on SSA and CFG artifacts."""

    def __init__(self) -> None:
        self.builder = DataFlowBuilder()

    @property
    def name(self) -> str:
        return "DataFlowPass"

    @property
    def requires(self) -> list[str]:
        return ["SSA", "CFG"]

    @property
    def produces(self) -> list[str]:
        return ["DataFlowGraph"]

    def run(self, context: PassContext) -> dict[str, Any]:
        cfgs = context.artifact_store.get("CFG")
        ssa_map = context.artifact_store.get("SSA")

        if not cfgs or not isinstance(cfgs, dict) or not ssa_map or not isinstance(ssa_map, dict):
            return {}

        dfg_map = {}
        for fn_name, cfg in cfgs.items():
            if isinstance(cfg, CFG) and fn_name in ssa_map:
                ssa_func = ssa_map[fn_name]
                if isinstance(ssa_func, SSAFunction):
                    dfg_map[fn_name] = self.builder.build_dataflow_graph(cfg, ssa_func)

        return dfg_map
