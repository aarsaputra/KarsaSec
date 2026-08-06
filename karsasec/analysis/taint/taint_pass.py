"""TaintPass compiler pipeline pass executing intraprocedural taint analysis."""

from __future__ import annotations

from typing import Any

from karsasec.analysis.cfg.models import CFG
from karsasec.analysis.dataflow.models import DataFlowGraph
from karsasec.analysis.ssa.models import SSAFunction
from karsasec.analysis.taint.engine import IntraproceduralTaintEngine
from karsasec.core.pipeline.base_pass import AnalysisPass
from karsasec.core.pipeline.context import PassContext


class TaintPass(AnalysisPass):
    """Compiler pipeline pass that performs Intraprocedural Taint Analysis."""

    def __init__(self) -> None:
        self.engine = IntraproceduralTaintEngine()

    @property
    def name(self) -> str:
        return "TaintPass"

    @property
    def requires(self) -> list[str]:
        return ["SSA", "CFG", "DataFlowGraph"]

    @property
    def produces(self) -> list[str]:
        return ["TaintGraph"]

    def run(self, context: PassContext) -> dict[str, Any]:
        cfgs = context.artifact_store.get("CFG")
        ssa_map = context.artifact_store.get("SSA")
        dfg_map = context.artifact_store.get("DataFlowGraph")

        if not cfgs or not ssa_map or not dfg_map:
            return {}

        taint_graphs = {}
        for fn_name, cfg in cfgs.items():
            if isinstance(cfg, CFG) and fn_name in ssa_map and fn_name in dfg_map:
                ssa_func = ssa_map[fn_name]
                dfg = dfg_map[fn_name]
                if isinstance(ssa_func, SSAFunction) and isinstance(dfg, DataFlowGraph):
                    taint_graphs[fn_name] = self.engine.analyze_function(cfg, ssa_func, dfg)

        return taint_graphs
