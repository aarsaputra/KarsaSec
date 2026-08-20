"""Intraprocedural Taint Engine performing single-function flow analysis."""

from __future__ import annotations

from karsasec.analysis.cfg.models import CFG
from karsasec.analysis.dataflow.models import DataFlowGraph
from karsasec.analysis.ssa.models import SSAFunction
from karsasec.analysis.taint.models import (
    TaintCategory,
    TaintGraph,
    TaintNode,
    TaintPath,
    TaintState,
)
from karsasec.analysis.taint.propagator import TaintPropagator
from karsasec.analysis.taint.sanitizers import SanitizerRegistry
from karsasec.analysis.taint.sinks import SinkRegistry
from karsasec.analysis.taint.sources import SourceRegistry


class IntraproceduralTaintEngine:
    """Engine executing intraprocedural Source -> Propagation -> Sanitizer -> Sink analysis."""

    def __init__(
        self,
        source_reg: SourceRegistry | None = None,
        sink_reg: SinkRegistry | None = None,
        sanitizer_reg: SanitizerRegistry | None = None,
    ) -> None:
        self.source_reg: SourceRegistry = source_reg or SourceRegistry()
        self.sink_reg: SinkRegistry = sink_reg or SinkRegistry()
        self.sanitizer_reg: SanitizerRegistry = sanitizer_reg or SanitizerRegistry()
        self.propagator: TaintPropagator = TaintPropagator(self.source_reg, self.sink_reg, self.sanitizer_reg)

    def analyze_function(self, cfg: CFG, ssa_func: SSAFunction, dfg: DataFlowGraph) -> TaintGraph:
        """Constructs a TaintGraph for a single function."""
        taint_graph = TaintGraph(function_name=cfg.function_name, file_path=cfg.file_path)

        # Step 1: Propagate taint states across variables
        var_taints = self.propagator.propagate_taint(ssa_func, dfg)
        for tnode in var_taints.values():
            taint_graph.add_node(tnode)

        # Step 2: Connect TaintEdges from DataFlowGraph edges
        for edge in dfg.edges:
            src_node = var_taints.get(edge.source_id) or next(
                (n for n in var_taints.values() if edge.source_id in n.id), None
            )
            tgt_node = var_taints.get(edge.target_id) or next(
                (n for n in var_taints.values() if edge.target_id in n.id), None
            )
            if src_node and tgt_node:
                taint_graph.add_edge(source_id=src_node.id, target_id=tgt_node.id, var_name=edge.var_name)

        # Step 3: Discover Source -> Sink paths
        sources = [n for n in var_taints.values() if n.is_source or n.state == TaintState.TAINTED]

        # Find sinks in SSA statements or CFG nodes
        sinks = [n for n in var_taints.values() if n.is_sink]
        if not sinks:
            for cfg_node in cfg.nodes.values():
                if self.sink_reg.is_sink(cfg_node.label):
                    snk_node = TaintNode(
                        id=f"{cfg_node.id}::sink",
                        var_name="sink",
                        state=TaintState.UNTAINTED,
                        line_number=cfg_node.line_number,
                        is_sink=True,
                        label=cfg_node.label,
                    )
                    sinks.append(snk_node)
                    taint_graph.add_node(snk_node)

        # Step 4: Evaluate vulnerability for paths
        for src in sources:
            for snk in sinks:
                matched_sink = self.sink_reg.match_sink(snk.label)
                category = matched_sink.category if matched_sink else TaintCategory.GENERIC

                # Check if path contains a sanitizer
                sanitizers = [n for n in var_taints.values() if n.is_sanitizer or n.state == TaintState.SANITIZED]

                if sanitizers:
                    # Sanitized -> SAFE
                    safe_path = TaintPath(
                        source_node=src,
                        sink_node=snk,
                        path_nodes=[src] + sanitizers + [snk],
                        sanitizer_nodes=sanitizers,
                        category=category,
                        is_vulnerable=False,
                    )
                    taint_graph.safe_paths.append(safe_path)
                else:
                    # Unsanitized -> UNSAFE
                    vuln_path = TaintPath(
                        source_node=src,
                        sink_node=snk,
                        path_nodes=[src, snk],
                        category=category,
                        is_vulnerable=True,
                    )
                    taint_graph.vulnerable_paths.append(vuln_path)

        return taint_graph
