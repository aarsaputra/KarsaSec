"""Taint Propagation Engine tracking variable taint states across Data Flow Graphs."""

from __future__ import annotations

from karsasec.analysis.dataflow.models import DataFlowGraph
from karsasec.analysis.ssa.models import SSAFunction
from karsasec.analysis.taint.models import TaintNode, TaintState
from karsasec.analysis.taint.sanitizers import SanitizerRegistry
from karsasec.analysis.taint.sinks import SinkRegistry
from karsasec.analysis.taint.sources import SourceRegistry


class TaintPropagator:
    """Propagates taint states across SSA variables and Data Flow Graph nodes."""

    def __init__(
        self,
        source_reg: SourceRegistry | None = None,
        sink_reg: SinkRegistry | None = None,
        sanitizer_reg: SanitizerRegistry | None = None,
    ) -> None:
        self.source_reg: SourceRegistry = source_reg or SourceRegistry()
        self.sink_reg: SinkRegistry = sink_reg or SinkRegistry()
        self.sanitizer_reg: SanitizerRegistry = sanitizer_reg or SanitizerRegistry()

    def propagate_taint(self, ssa_func: SSAFunction, dfg: DataFlowGraph) -> dict[str, TaintNode]:
        """Returns map of ssa_variable_name -> TaintNode with calculated TaintState."""
        taint_nodes: dict[str, TaintNode] = {}

        for snode in ssa_func.nodes:
            if not snode.target:
                continue

            var_name = snode.target.ssa_name
            label = snode.label
            line_num = snode.line_number

            # Check if assignment source is untrusted
            is_src = self.source_reg.is_source(label)
            is_snk = self.sink_reg.is_sink(label)
            is_san = self.sanitizer_reg.is_sanitizer(label)

            # Determine state from uses or source
            state = TaintState.UNTAINTED

            if is_san:
                state = TaintState.SANITIZED
            elif is_src:
                state = TaintState.TAINTED
            else:
                # Check if any used variable is TAINTED
                for uvar in snode.use_vars:
                    if uvar.ssa_name in taint_nodes:
                        parent_state = taint_nodes[uvar.ssa_name].state
                        if parent_state == TaintState.TAINTED:
                            state = TaintState.TAINTED
                            break
                        elif parent_state == TaintState.SANITIZED:
                            state = TaintState.SANITIZED

            tnode = TaintNode(
                id=snode.id,
                var_name=var_name,
                state=state,
                line_number=line_num,
                is_source=is_src,
                is_sink=is_snk,
                is_sanitizer=is_san,
                label=label,
            )
            taint_nodes[var_name] = tnode

        return taint_nodes
