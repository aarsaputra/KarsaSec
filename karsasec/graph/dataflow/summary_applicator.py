"""Summary Applicator Engine (E12-16).

Design Principles & Guardrails:
  - Binds caller arguments to callee parameters preserving isolated SSA versions ($arg#1 vs $param#1).
  - Applies hardened FunctionSummary path summaries into caller AbstractEnvironment.
  - Generates explicit PASSES_PARAMETER and RETURNS provenance edges.
  - Prevents callee-local variable identifier leakage into caller scope.
  - Does NOT decide sink safety directly; enriches evidence for E12-13 SinkCompatibilityMatrix.
  - Anti-hardcoding: Pure dataflow solver. Zero benchmark/rule strings.
"""

from __future__ import annotations

from collections.abc import Sequence

from karsasec.graph.dataflow.abstract_state import AbstractEnvironment, TaintState
from karsasec.graph.dataflow.provenance import (
    CallContext,
    DataflowProvenanceGraph,
    FunctionSummary,
    ProvenanceEdge,
    ProvenanceEdgeKind,
    ProvenanceNode,
    ProvenanceNodeKind,
)


class SummaryApplicator:
    """Applies a FunctionSummary into a caller's AbstractEnvironment and DataflowProvenanceGraph."""

    def __init__(self, provenance_graph: DataflowProvenanceGraph | None = None) -> None:
        self.provenance_graph = provenance_graph or DataflowProvenanceGraph()
        self._node_counter = 0

    def _next_node_id(self, prefix: str = "node") -> str:
        self._node_counter += 1
        return f"{prefix}_{self._node_counter}"

    def apply_summary(
        self,
        context: CallContext,
        summary: FunctionSummary,
        caller_args: Sequence[str],
        caller_dest_var: str,
        caller_env: AbstractEnvironment,
    ) -> AbstractEnvironment:
        """Apply function summary to caller environment without leaking callee internal variables."""
        new_caller_env = caller_env.copy()

        # Step 1: Bind caller arguments to callee parameters
        for idx, callee_param in enumerate(summary.parameters):
            if idx < len(caller_args):
                caller_arg = caller_args[idx]
                arg_val = caller_env.get_value(caller_arg)

                # Create caller call-site provenance node
                call_node_id = self._next_node_id("call_arg")
                call_node = ProvenanceNode(
                    node_id=call_node_id,
                    kind=ProvenanceNodeKind.CALL,
                    var_name=caller_arg,
                    var_version=arg_val.var_version,
                    file_path=context.caller_file,
                    function_name=context.caller_function,
                    statement=f"{context.callee_function}({caller_arg})",
                    constraints=arg_val.all_constraints,
                    taint_state=arg_val.taint,
                    call_site_id=context.call_site_id,
                )
                self.provenance_graph.add_node(call_node)

                if arg_val.provenance_node_id and self.provenance_graph.get_node(arg_val.provenance_node_id):
                    self.provenance_graph.add_edge(
                        ProvenanceEdge(
                            src_node_id=arg_val.provenance_node_id,
                            target_node_id=call_node_id,
                            kind=ProvenanceEdgeKind.DERIVES_FROM,
                            call_site_id=context.call_site_id,
                        )
                    )

                # Callee parameter gets distinct version in callee context
                param_node_id = self._next_node_id("callee_param")
                param_node = ProvenanceNode(
                    node_id=param_node_id,
                    kind=ProvenanceNodeKind.PARAMETER,
                    var_name=callee_param,
                    var_version=f"{callee_param}#{context.call_site_id}",
                    file_path=context.callee_file or summary.file_path,
                    function_name=context.callee_function,
                    statement=f"param ${callee_param}",
                    constraints=arg_val.all_constraints,
                    taint_state=arg_val.taint,
                    call_site_id=context.call_site_id,
                )
                self.provenance_graph.add_node(param_node)

                self.provenance_graph.add_edge(
                    ProvenanceEdge(
                        src_node_id=call_node_id,
                        target_node_id=param_node_id,
                        kind=ProvenanceEdgeKind.PASSES_PARAMETER,
                        call_site_id=context.call_site_id,
                    )
                )

        # Step 2: Compute joined return state from summary
        if caller_dest_var:
            joined_taint, joined_constraints = summary.joined_return_state()

            # If caller argument was UNKNOWN or TAINTED, map parameter dependency taint
            if joined_taint == TaintState.UNKNOWN and summary.path_summaries:
                # Check if all parameter dependencies map to caller args
                param_taints = []
                clean_params = [p.lstrip("$") for p in summary.parameters]
                for p_sum in summary.path_summaries:
                    for p_dep in p_sum.parameter_dependencies:
                        clean_dep = p_dep.lstrip("$")
                        if clean_dep in clean_params:
                            p_idx = clean_params.index(clean_dep)
                            if p_idx < len(caller_args):
                                caller_arg_val = caller_env.get_value(caller_args[p_idx])
                                param_taints.append(caller_arg_val.taint)

                if param_taints:
                    if any(getattr(t, "value", str(t)) in ("TAINTED", "CONSTRAINED") for t in param_taints):
                        joined_taint = TaintState.TAINTED
                    elif all(getattr(t, "value", str(t)) == "UNTAINTED" for t in param_taints):
                        joined_taint = TaintState.UNTAINTED

            new_dest_val = new_caller_env.assignment_kill(
                caller_dest_var,
                new_taint=joined_taint,
                prov_desc=f"Return of {summary.function_name}() at call site {context.call_site_id}",
            )

            if joined_constraints:
                new_dest_val = new_dest_val.with_constraints(set(joined_constraints))
                new_caller_env.set_value(new_dest_val)

            # Step 3: Record return provenance nodes & edges
            ret_node_id = self._next_node_id("ret_src")
            ret_node = ProvenanceNode(
                node_id=ret_node_id,
                kind=ProvenanceNodeKind.RETURN,
                var_name=f"return({summary.function_name})",
                var_version=f"ret#{context.call_site_id}",
                file_path=context.callee_file or summary.file_path,
                function_name=summary.function_name,
                statement=f"return value of {summary.function_name}",
                constraints=joined_constraints,
                taint_state=joined_taint,
                call_site_id=context.call_site_id,
            )
            self.provenance_graph.add_node(ret_node)

            dest_node_id = self._next_node_id("dest_var")
            dest_node = ProvenanceNode(
                node_id=dest_node_id,
                kind=ProvenanceNodeKind.ASSIGNMENT,
                var_name=caller_dest_var,
                var_version=new_dest_val.var_version,
                file_path=context.caller_file,
                function_name=context.caller_function,
                statement=f"{caller_dest_var} = {summary.function_name}()",
                constraints=new_dest_val.all_constraints,
                taint_state=new_dest_val.taint,
                call_site_id=context.call_site_id,
            )
            self.provenance_graph.add_node(dest_node)

            self.provenance_graph.add_edge(
                ProvenanceEdge(
                    src_node_id=ret_node_id,
                    target_node_id=dest_node_id,
                    kind=ProvenanceEdgeKind.RETURNS,
                    call_site_id=context.call_site_id,
                )
            )

        return new_caller_env
