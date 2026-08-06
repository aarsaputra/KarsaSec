"""InterproceduralTaintPass compiler pipeline pass executing cross-function taint analysis."""

from __future__ import annotations

from typing import Any

from karsasec.analysis.callgraph.models import CallGraph
from karsasec.analysis.interprocedural.engine import InterproceduralTaintEngine
from karsasec.analysis.symbol.models import SymbolGraph
from karsasec.core.pipeline.base_pass import AnalysisPass
from karsasec.core.pipeline.context import PassContext


class InterproceduralTaintPass(AnalysisPass):
    """Compiler pipeline pass executing Interprocedural Taint Analysis across multiple functions."""

    def __init__(self) -> None:
        self.engine = InterproceduralTaintEngine()

    @property
    def name(self) -> str:
        return "InterproceduralTaintPass"

    @property
    def requires(self) -> list[str]:
        return ["DataFlowGraph", "TaintGraph"]

    @property
    def produces(self) -> list[str]:
        return ["InterproceduralTaintGraph"]

    def run(self, context: PassContext) -> dict[str, Any]:
        taint_graphs = context.artifact_store.get("TaintGraph")
        dfg_map = context.artifact_store.get("DataFlowGraph")
        callgraph = context.artifact_store.get("CallGraph") if context.artifact_store.has("CallGraph") else None
        symbolgraph = context.artifact_store.get("SymbolGraph") if context.artifact_store.has("SymbolGraph") else None

        if not taint_graphs or not dfg_map or not isinstance(taint_graphs, dict) or not isinstance(dfg_map, dict):
            return {}

        cg_obj = callgraph if isinstance(callgraph, CallGraph) else None
        sg_obj = symbolgraph if isinstance(symbolgraph, SymbolGraph) else None

        itg = self.engine.analyze_program(taint_graphs, dfg_map, cg_obj, sg_obj)
        return {"program": itg}
