"""CPGPass executing Code Property Graph construction as an AnalysisPass in the compiler pipeline."""

from __future__ import annotations

from karsasec.core.pipeline.context import PassContext
from karsasec.core.pipeline.pass_manager import AnalysisPass
from karsasec.cpg.builder import CPGBuilder
from karsasec.cpg.index import GraphIndex
from karsasec.cpg.models import CPGGraph


class CPGPass(AnalysisPass):
    """Compiler pipeline pass fusing AST, IR, CFG, SSA, DataFlow, and Taint into unified CPG artifacts."""

    def __init__(self) -> None:
        self.builder: CPGBuilder = CPGBuilder()

    @property
    def name(self) -> str:
        return "CPGPass"

    @property
    def description(self) -> str:
        return "Constructs unified Code Property Graph (CPGGraph, CPGIndex, CPGMetadata) single source of truth."

    @property
    def requires(self) -> list[str]:
        return ["DataFlowGraph", "TaintGraph"]

    @property
    def produces(self) -> list[str]:
        return ["CPGGraph", "CPGIndex", "CPGMetadata"]

    def run(self, context: PassContext) -> PassContext:
        file_nodes = context.artifact_store.get("AST") if context.artifact_store.has("AST") else None
        ir_functions = context.artifact_store.get("IR") if context.artifact_store.has("IR") else None
        cfgs = context.artifact_store.get("CFG") if context.artifact_store.has("CFG") else None
        ssa_functions = context.artifact_store.get("SSA") if context.artifact_store.has("SSA") else None
        dfg_map = context.artifact_store.get("DataFlowGraph") if context.artifact_store.has("DataFlowGraph") else None
        taint_graphs = context.artifact_store.get("TaintGraph") if context.artifact_store.has("TaintGraph") else None
        itg = context.artifact_store.get("InterproceduralTaintGraph") if context.artifact_store.has("InterproceduralTaintGraph") else None

        cpg: CPGGraph = self.builder.build_cpg(
            file_nodes=file_nodes,
            ir_functions=ir_functions,
            cfgs=cfgs,
            ssa_functions=ssa_functions,
            dfg_map=dfg_map,
            taint_graphs=taint_graphs,
            itg=itg,
        )
        cpg_index = GraphIndex(cpg)

        context.artifact_store.store("CPGGraph", cpg)
        context.artifact_store.store("CPGIndex", cpg_index)
        context.artifact_store.store("CPGMetadata", cpg.metadata)

        return context
