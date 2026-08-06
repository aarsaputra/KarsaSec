"""FunctionSummaryEngine generating compact reusable FunctionSummary contracts."""

from __future__ import annotations

from karsasec.analysis.dataflow.models import DataFlowGraph
from karsasec.analysis.interprocedural.models import FunctionSummary, ReturnSummary
from karsasec.analysis.taint.models import TaintGraph, TaintState


class FunctionSummaryEngine:
    """Generates reusable FunctionSummary contracts from intraprocedural TaintGraph artifacts."""

    def build_summary(self, taint_graph: TaintGraph, dfg: DataFlowGraph) -> FunctionSummary:
        """Constructs FunctionSummary for a single function."""
        summary = FunctionSummary(
            function_name=taint_graph.function_name,
            file_path=taint_graph.file_path,
        )

        has_src = False
        has_snk = False
        has_san = False

        for node in taint_graph.nodes.values():
            if node.is_source or node.state == TaintState.TAINTED:
                has_src = True
            if node.is_sink:
                has_snk = True
            if node.is_sanitizer or node.state == TaintState.SANITIZED:
                has_san = True

        summary.contains_source = has_src
        summary.contains_sink = has_snk
        summary.contains_sanitizer = has_san

        # Check return value propagation
        ret_tainted = False
        sanitized_by = ""
        passthrough: list[int] = []

        for node in taint_graph.nodes.values():
            if "return" in node.label.lower() or "return" in node.id.lower():
                if node.state == TaintState.TAINTED or node.is_source:
                    ret_tainted = True
                elif node.state == TaintState.SANITIZED or node.is_sanitizer:
                    sanitized_by = node.label

        summary.return_summary = ReturnSummary(
            is_tainted=ret_tainted,
            sanitized_by=sanitized_by,
            passthrough_params=passthrough,
        )

        return summary
