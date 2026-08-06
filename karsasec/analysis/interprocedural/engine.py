"""Interprocedural Taint Engine executing 1-call-site context-sensitive analysis across functions."""

from __future__ import annotations

from karsasec.analysis.callgraph.models import CallGraph
from karsasec.analysis.dataflow.models import DataFlowGraph
from karsasec.analysis.interprocedural.cache import SummaryCache
from karsasec.analysis.interprocedural.models import (
    CallContext,
    CallSite,
    InterproceduralTaintGraph,
    InterproceduralTaintPath,
)
from karsasec.analysis.interprocedural.parameter_mapping import ParameterMapper
from karsasec.analysis.interprocedural.resolver import CallResolver
from karsasec.analysis.interprocedural.summary import FunctionSummaryEngine
from karsasec.analysis.symbol.models import SymbolGraph
from karsasec.analysis.taint.models import TaintCategory, TaintGraph, TaintState


class InterproceduralTaintEngine:
    """Performs 1-call-site context-sensitive cross-function taint analysis using Function Summaries."""

    def __init__(self) -> None:
        self.cache: SummaryCache = SummaryCache()
        self.summary_engine: FunctionSummaryEngine = FunctionSummaryEngine()
        self.resolver: CallResolver = CallResolver()
        self.mapper: ParameterMapper = ParameterMapper()

    def analyze_program(
        self,
        taint_graphs: dict[str, TaintGraph],
        dfg_map: dict[str, DataFlowGraph],
        callgraph: CallGraph | None = None,
        symbolgraph: SymbolGraph | None = None,
    ) -> InterproceduralTaintGraph:
        """Analyzes multi-function taint propagation across the entire program."""
        itg = InterproceduralTaintGraph()

        # Step 1: Compile Function Summaries for all functions
        for fn_name, tg in taint_graphs.items():
            dfg = dfg_map.get(fn_name)
            if dfg:
                summary = self.summary_engine.build_summary(tg, dfg)
                self.cache.put(summary)
                itg.add_summary(summary)

        # Step 2: Trace cross-function calls using 1-call-site context
        for fn_name, tg in taint_graphs.items():
            context = CallContext(call_stack=[fn_name])
            self._trace_function_calls(fn_name, tg, taint_graphs, dfg_map, itg, context)

        return itg

    def _trace_function_calls(
        self,
        current_fn: str,
        current_tg: TaintGraph,
        all_tgs: dict[str, TaintGraph],
        dfg_map: dict[str, DataFlowGraph],
        itg: InterproceduralTaintGraph,
        context: CallContext,
    ) -> None:
        sources = [n for n in current_tg.nodes.values() if n.is_source or n.state == TaintState.TAINTED]
        if not sources:
            return

        dfg = itg.function_summaries.get(current_fn)
        # Search labels in taint_graph nodes and dfg_map nodes
        labels_to_check = [n.label for n in current_tg.nodes.values()]
        if dfg_map and current_fn in dfg_map:
            labels_to_check.extend([n.label for n in dfg_map[current_fn].nodes.values()])

        for label in labels_to_check:
            for target_fn, target_tg in all_tgs.items():
                if target_fn == current_fn:
                    continue

                if target_fn in label or f"{target_fn}(" in label:
                    # Recursive call protection
                    if context.contains(target_fn):
                        summary = self.cache.get(target_fn)
                        if summary:
                            summary.has_recursive_calls = True
                        continue

                    # Call site found
                    call_site = CallSite(caller_id=current_fn, callee_name=target_fn, line_number=1)

                    target_summary = self.cache.get(target_fn)
                    has_sanitizer = target_summary.contains_sanitizer if target_summary else False
                    has_sink = target_summary.contains_sink if target_summary else False

                    # Check downstream sinks in target function
                    sink_nodes = [n for n in target_tg.nodes.values() if n.is_sink]

                    if sink_nodes or has_sink:
                        matched_snk = sink_nodes[0] if sink_nodes else None
                        if has_sanitizer:
                            safe_path = InterproceduralTaintPath(
                                source_func=current_fn,
                                sink_func=target_fn,
                                call_chain=[call_site],
                                source_node=sources[0],
                                sink_node=matched_snk,
                                category=TaintCategory.GENERIC,
                                is_vulnerable=False,
                            )
                            itg.safe_paths.append(safe_path)
                        else:
                            vuln_path = InterproceduralTaintPath(
                                source_func=current_fn,
                                sink_func=target_fn,
                                call_chain=[call_site],
                                source_node=sources[0],
                                sink_node=matched_snk,
                                category=TaintCategory.GENERIC,
                                is_vulnerable=True,
                            )
                            itg.vulnerable_paths.append(vuln_path)
