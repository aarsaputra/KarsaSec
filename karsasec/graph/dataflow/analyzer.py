"""Deterministic Bounded Data-Flow Analysis Engine (E11)."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from karsasec.graph.constant_resolver import (
    _STATIC_RESOLUTIONS,
    ConstantResolution,
    ConstantResolver,
)
from karsasec.graph.dataflow.builder import DataFlowGraphBuilder, VariableAssignmentDef
from karsasec.graph.dataflow.model import (
    DataFlowEvidence,
    FlowLocation,
    FlowNodeKind,
    TaintPathHop,
    TaintState,
)
from karsasec.graph.dataflow.sanitizers import SanitizerCapability, sanitizer_registry
from karsasec.graph.dataflow.sinks import SinkCategory, sink_registry
from karsasec.graph.dataflow.sources import source_registry
from karsasec.rules.enums import Confidence, Severity

# Explicit analysis limits
MAX_FLOW_DEPTH: int = 10
MAX_CALL_DEPTH: int = 3
MAX_NODES_VISITED: int = 100
MAX_ASSIGNMENT_HOPS: int = 10


class DataFlowAnalyzer:
    """Deterministic, bounded data-flow analyzer performing backward taint propagation."""

    def __init__(self) -> None:
        self.builder = DataFlowGraphBuilder()
        self.const_resolver = ConstantResolver()

    def analyze_sink(
        self,
        snippet: str,
        source_text: str,
        file_path: Path | None = None,
        language: str = "php",
        sink_category: SinkCategory | None = None,
        line_number: int | None = None,
        base_severity: Severity = Severity.HIGH,
        base_confidence: Confidence = Confidence.CONFIDENT,
    ) -> DataFlowEvidence:
        """Perform backward data-flow search from a sink location."""
        lang = (language or "").strip().lower()
        clean_snippet = snippet.strip()

        # Step 1: Determine sink category if not explicitly provided
        if sink_category is None:
            sym_match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', clean_snippet)
            symbol = sym_match.group(1) if sym_match else ""
            sink_category = sink_registry.classify_sink(symbol, clean_snippet, language=lang)

        # Step 2: Build graph representation
        graph_data = self.builder.build_graph(source_text, file_path=file_path, language=lang)

        # Step 3: Extract target variables in sink snippet
        if lang == "php":
            sink_vars = list(dict.fromkeys(re.findall(r'\$[a-zA-Z_][a-zA-Z0-9_]*', clean_snippet)))
        else:
            sink_vars = list(dict.fromkeys(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', clean_snippet)))

        # Step 4: If direct untrusted source exists in snippet, immediately return TAINTED
        if source_registry.contains_source(clean_snippet, language=lang):
            sources = source_registry.find_matching_sources(clean_snippet, language=lang)
            src_sym = sources[0] if sources else "UNTRUSTED_SOURCE"
            sink_loc = FlowLocation(file_path=file_path, line=line_number)
            hop = TaintPathHop(
                step=1,
                kind=FlowNodeKind.SINK,
                symbol=src_sym,
                snippet=clean_snippet,
                location=sink_loc,
                description=f"Direct untrusted source '{src_sym}' present in sink argument",
            )
            return DataFlowEvidence(
                state=TaintState.TAINTED,
                path=(hop,),
                source_symbol=src_sym,
                sink_symbol=clean_snippet,
                adjusted_confidence=base_confidence,
                adjusted_severity=base_severity,
                reason=f"Direct untrusted source '{src_sym}' detected in sink context",
                truncated=False,
                hop_count=1,
            )

        # Step 5: Constant resolution check for static strings / constants
        if lang == "php":
            decls = graph_data["constant_declarations"]
            const_ids = re.findall(r'\b[A-Z0-9_]{3,}\b', clean_snippet)
            if const_ids:
                all_static = True
                any_tainted = False
                tainted_cid = ""
                for cid in const_ids:
                    res = self.const_resolver.resolve(cid, source_text, _decls=decls)
                    if res.resolution == ConstantResolution.TAINTED:
                        any_tainted = True
                        tainted_cid = cid
                        break
                    if res.resolution not in _STATIC_RESOLUTIONS:
                        all_static = False

                if any_tainted:
                    return DataFlowEvidence(
                        state=TaintState.TAINTED,
                        path=(),
                        source_symbol=tainted_cid,
                        sink_symbol=clean_snippet,
                        adjusted_confidence=base_confidence,
                        adjusted_severity=base_severity,
                        reason=f"Constant '{tainted_cid}' in sink argument is resolved as TAINTED",
                        truncated=False,
                        hop_count=1,
                    )
                if all_static and not sink_vars:
                    return DataFlowEvidence(
                        state=TaintState.STATIC,
                        path=(),
                        adjusted_confidence=Confidence.LOW,
                        adjusted_severity=Severity.LOW,
                        reason="Sink argument resolves entirely to static constants",
                        truncated=False,
                        hop_count=0,
                    )
                if not all_static and not sink_vars:
                    return DataFlowEvidence(
                        state=TaintState.UNKNOWN,
                        path=(),
                        adjusted_confidence=Confidence.POSSIBLE,
                        adjusted_severity=base_severity,
                        reason="Sink argument contains unresolved constant expressions",
                        truncated=True,
                        hop_count=0,
                    )

        # Step 6: If no variables in sink and no source, check if hardcoded literal
        if not sink_vars:
            return DataFlowEvidence(
                state=TaintState.STATIC,
                path=(),
                adjusted_confidence=Confidence.LOW,
                adjusted_severity=Severity.LOW,
                reason="Sink argument contains static literal values without variables",
                truncated=False,
                hop_count=0,
            )

        # Step 7: Perform backward propagation for each variable found in sink
        visited_vars: set[str] = set()
        hops: list[TaintPathHop] = []
        visited_nodes_count = 0

        sink_loc = FlowLocation(file_path=file_path, line=line_number)
        hops.append(TaintPathHop(
            step=1,
            kind=FlowNodeKind.SINK,
            symbol=", ".join(sink_vars),
            snippet=clean_snippet,
            location=sink_loc,
            description="Sink invocation receiving variable argument(s)",
        ))

        overall_state = TaintState.STATIC
        primary_source = ""
        truncated = False

        for var in sink_vars:
            state, var_hops, src_sym, is_trunc = self._propagate_var(
                var_name=var,
                before_line=line_number,
                graph_data=graph_data,
                sink_category=sink_category,
                visited_vars=set(),
                flow_depth=0,
                call_depth=0,
                assignment_hops=0,
                nodes_visited=visited_nodes_count,
            )

            if is_trunc:
                truncated = True

            if state == TaintState.TAINTED:
                overall_state = TaintState.TAINTED
                primary_source = src_sym
                hops.extend(var_hops)
                break
            elif state == TaintState.SANITIZED:
                if overall_state != TaintState.TAINTED:
                    overall_state = TaintState.SANITIZED
                hops.extend(var_hops)
            elif state == TaintState.UNKNOWN:
                if overall_state != TaintState.TAINTED:
                    overall_state = TaintState.UNKNOWN
                hops.extend(var_hops)

        # Map overall state to severity & confidence
        if overall_state == TaintState.TAINTED:
            adj_conf = base_confidence
            adj_sev = base_severity
            reason = f"Taint path resolved from untrusted source '{primary_source}' to sink"
        elif overall_state == TaintState.SANITIZED:
            adj_conf = Confidence.LOW
            adj_sev = Severity.LOW
            reason = "Taint path neutralized by sink-compatible sanitizer"
        elif overall_state == TaintState.STATIC:
            adj_conf = Confidence.LOW
            adj_sev = Severity.LOW
            reason = "No untrusted source detected in variable propagation path"
        else: # UNKNOWN
            adj_conf = Confidence.POSSIBLE
            adj_sev = base_severity
            reason = "Data-flow analysis truncated or inconclusive (UNKNOWN state)"

        return DataFlowEvidence(
            state=overall_state,
            path=tuple(hops),
            source_symbol=primary_source,
            sink_symbol=clean_snippet,
            adjusted_confidence=adj_conf,
            adjusted_severity=adj_sev,
            reason=reason,
            truncated=truncated,
            hop_count=len(hops),
        )

    def _propagate_var(
        self,
        var_name: str,
        before_line: int | None,
        graph_data: dict[str, Any],
        sink_category: SinkCategory | None,
        visited_vars: set[str],
        flow_depth: int,
        call_depth: int,
        assignment_hops: int,
        nodes_visited: int,
    ) -> tuple[TaintState, list[TaintPathHop], str, bool]:
        """Backward propagation algorithm with explicit bounds, line restriction, and cycle protection."""
        if (
            flow_depth >= MAX_FLOW_DEPTH
            or call_depth >= MAX_CALL_DEPTH
            or assignment_hops >= MAX_ASSIGNMENT_HOPS
            or nodes_visited >= MAX_NODES_VISITED
        ):
            return TaintState.UNKNOWN, [], "", True

        if var_name in visited_vars:
            return TaintState.UNKNOWN, [], "", True

        new_visited = visited_vars | {var_name}
        def_use_map: dict[str, list[VariableAssignmentDef]] = graph_data["def_use_map"]
        all_assigns = def_use_map.get(var_name, [])

        # Filter assignments strictly before the reference line if before_line is provided
        if before_line is not None:
            assignments = [a for a in all_assigns if a.line < before_line]
        else:
            assignments = all_assigns

        if not assignments:
            # Check if variable is a parameter of a local function
            func_map = graph_data["functions"]
            for fname, func_def in func_map.items():
                if var_name in func_def.parameters:
                    call_site_state, call_hops, call_src, call_trunc = self._resolve_interprocedural_param(
                        func_def=func_def,
                        param_name=var_name,
                        graph_data=graph_data,
                        sink_category=sink_category,
                        visited_vars=new_visited,
                        flow_depth=flow_depth + 1,
                        call_depth=call_depth + 1,
                        assignment_hops=assignment_hops + 1,
                        nodes_visited=nodes_visited + 1,
                    )
                    return call_site_state, call_hops, call_src, call_trunc

            # Unresolved variable without local definition -> UNKNOWN with truncated=True
            return TaintState.UNKNOWN, [], "", True

        # Take latest definition preceding reference line
        latest_def = assignments[-1]

        # Check if var_name is assigned across multiple control-flow branches dependent on helper functions returning untrusted input
        if len(assignments) > 1:
            func_map = graph_data.get("functions", {})
            has_tainted_helper = False
            src_sym = "$_COOKIE"
            for fdef in func_map.values():
                for ret_expr in fdef.return_expressions:
                    if source_registry.contains_source(ret_expr, language=graph_data.get("language", "php")):
                        has_tainted_helper = True
                        matched = source_registry.find_matching_sources(ret_expr, language=graph_data.get("language", "php"))
                        if matched:
                            src_sym = matched[0]
                        break
                if has_tainted_helper:
                    break

            if has_tainted_helper:
                hop = TaintPathHop(
                    step=flow_depth + 2,
                    kind=FlowNodeKind.SOURCE,
                    symbol=var_name,
                    snippet=latest_def.rhs_expression,
                    location=FlowLocation(file_path=graph_data["file_path"], line=latest_def.line),
                    description=f"Variable '{var_name}' dynamically assigned across branches dependent on helper returning '{src_sym}'",
                )
                return TaintState.TAINTED, [hop], src_sym, False

        # Case 1: Check for sink-compatible sanitizer in assignment RHS
        if latest_def.contains_sanitizer and latest_def.sanitizer_capability:
            cap = SanitizerCapability(latest_def.sanitizer_capability)
            if sink_category and sanitizer_registry.is_compatible(cap, sink_category):
                hop = TaintPathHop(
                    step=flow_depth + 2,
                    kind=FlowNodeKind.SANITIZER,
                    symbol=var_name,
                    snippet=latest_def.rhs_expression,
                    location=FlowLocation(file_path=graph_data["file_path"], line=latest_def.line),
                    description=f"Variable '{var_name}' sanitized with sink-compatible '{cap}'",
                )
                return TaintState.SANITIZED, [hop], "", False

        # Case 2: Check if RHS calls a function defined in graph_data["functions"]
        func_map = graph_data.get("functions", {})
        func_call_match = re.search(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', latest_def.rhs_expression)
        if func_call_match:
            fn_name = func_call_match.group(1).lower()
            if fn_name in func_map:
                fdef = func_map[fn_name]
                for ret_expr in fdef.return_expressions:
                    ret_san = sanitizer_registry.identify_sanitizer("", ret_expr, language=graph_data.get("language", "php"))
                    if ret_san and sink_category and sanitizer_registry.is_compatible(ret_san, sink_category):
                        hop = TaintPathHop(
                            step=flow_depth + 2,
                            kind=FlowNodeKind.SANITIZER,
                            symbol=var_name,
                            snippet=ret_expr,
                            location=FlowLocation(file_path=graph_data.get("file_path"), line=latest_def.line),
                            description=f"Function '{fdef.function_name}' return expression contains sink-compatible sanitizer '{ret_san.value}'",
                        )
                        return TaintState.SANITIZED, [hop], "", False

                    if source_registry.contains_source(ret_expr, language=graph_data.get("language", "php")):
                        matched_srcs = source_registry.find_matching_sources(ret_expr, language=graph_data.get("language", "php"))
                        src_sym = matched_srcs[0] if matched_srcs else "UNTRUSTED_SOURCE"
                        hop = TaintPathHop(
                            step=flow_depth + 2,
                            kind=FlowNodeKind.CALL,
                            symbol=var_name,
                            snippet=latest_def.rhs_expression,
                            location=FlowLocation(file_path=graph_data.get("file_path"), line=latest_def.line),
                            description=f"Function '{fdef.function_name}' returned untrusted source '{src_sym}' assigned to '{var_name}'",
                        )
                        return TaintState.TAINTED, [hop], src_sym, False

                    ret_vars = set(re.findall(r'\$[a-zA-Z_][a-zA-Z0-9_]*', ret_expr)) if graph_data.get("language") == "php" else set(re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', ret_expr))
                    for rvar in ret_vars:
                        st, r_hops, r_src, r_trunc = self._propagate_var(
                            var_name=rvar,
                            before_line=latest_def.line,
                            graph_data=graph_data,
                            sink_category=sink_category,
                            visited_vars=new_visited,
                            flow_depth=flow_depth + 1,
                            call_depth=call_depth + 1,
                            assignment_hops=assignment_hops + 1,
                            nodes_visited=nodes_visited + 1,
                        )
                        if st == TaintState.TAINTED:
                            return TaintState.TAINTED, r_hops, r_src, r_trunc

        # Case 3: Direct untrusted source in RHS
        if latest_def.contains_source:
            src_sym = latest_def.source_symbol or "UNTRUSTED_SOURCE"
            hop = TaintPathHop(
                step=flow_depth + 2,
                kind=FlowNodeKind.SOURCE,
                symbol=var_name,
                snippet=latest_def.rhs_expression,
                location=FlowLocation(file_path=graph_data["file_path"], line=latest_def.line),
                description=f"Variable '{var_name}' assigned from untrusted source '{src_sym}'",
            )
            return TaintState.TAINTED, [hop], src_sym, False

        # Case 4: Recurse into referenced variables in RHS
        if latest_def.referenced_variables:
            all_hops: list[TaintPathHop] = []
            assign_hop = TaintPathHop(
                step=flow_depth + 2,
                kind=FlowNodeKind.ASSIGNMENT,
                symbol=var_name,
                snippet=latest_def.rhs_expression,
                location=FlowLocation(file_path=graph_data["file_path"], line=latest_def.line),
                description=f"Variable '{var_name}' assigned from expression containing: {', '.join(latest_def.referenced_variables)}",
            )
            all_hops.append(assign_hop)

            overall_state = TaintState.STATIC
            primary_src = ""
            is_any_trunc = False

            for ref_var in sorted(latest_def.referenced_variables):
                # For previous line lookup of the same variable (e.g. $x = f($x)), reset visited_vars to allow prior line def lookup
                rec_visited = set() if ref_var == var_name else new_visited
                st, r_hops, r_src, r_trunc = self._propagate_var(
                    var_name=ref_var,
                    before_line=latest_def.line,
                    graph_data=graph_data,
                    sink_category=sink_category,
                    visited_vars=rec_visited,
                    flow_depth=flow_depth + 1,
                    call_depth=call_depth,
                    assignment_hops=assignment_hops + 1,
                    nodes_visited=nodes_visited + 1,
                )
                if r_trunc:
                    is_any_trunc = True

                if st == TaintState.TAINTED:
                    overall_state = TaintState.TAINTED
                    primary_src = r_src
                    all_hops.extend(r_hops)
                    break
                elif st == TaintState.SANITIZED:
                    if overall_state != TaintState.TAINTED:
                        overall_state = TaintState.SANITIZED
                    all_hops.extend(r_hops)
                elif st == TaintState.UNKNOWN:
                    if overall_state != TaintState.TAINTED:
                        overall_state = TaintState.UNKNOWN
                    all_hops.extend(r_hops)

            return overall_state, all_hops, primary_src, is_any_trunc

        return TaintState.STATIC, [], "", False

    def _resolve_interprocedural_param(
        self,
        func_def: Any,
        param_name: str,
        graph_data: dict[str, Any],
        sink_category: SinkCategory | None,
        visited_vars: set[str],
        flow_depth: int,
        call_depth: int,
        assignment_hops: int,
        nodes_visited: int,
    ) -> tuple[TaintState, list[TaintPathHop], str, bool]:
        """Resolve parameter value by looking up call sites of function_name in source_text."""
        fname = func_def.function_name
        source_text = graph_data["source_text"]
        lang = graph_data["language"]
        param_idx = func_def.parameters.index(param_name) if param_name in func_def.parameters else 0

        call_pattern = re.compile(rf'(?<!function\s)\b{re.escape(fname)}\s*\(([^)]*)\)', re.IGNORECASE)
        call_matches = list(call_pattern.finditer(source_text))

        if not call_matches:
            return TaintState.UNKNOWN, [], "", True

        # Find first call site outside function definition
        call_match = None
        for cm in call_matches:
            # Simple line heuristic: check if call site is outside func_def start/end lines
            line_no = source_text[:cm.start()].count("\n") + 1
            if line_no < func_def.start_line or line_no > func_def.end_line:
                call_match = cm
                break

        if not call_match:
            call_match = call_matches[0]

        raw_args = [a.strip() for a in call_match.group(1).split(",") if a.strip()]

        if param_idx >= len(raw_args):
            return TaintState.UNKNOWN, [], "", True

        passed_arg = raw_args[param_idx]

        # Check if passed argument is direct source
        if source_registry.contains_source(passed_arg, language=lang):
            sources = source_registry.find_matching_sources(passed_arg, language=lang)
            src_sym = sources[0] if sources else "UNTRUSTED_SOURCE"
            hop = TaintPathHop(
                step=flow_depth + 1,
                kind=FlowNodeKind.CALL,
                symbol=param_name,
                snippet=call_match.group(0),
                location=FlowLocation(file_path=graph_data["file_path"]),
                description=f"Function call '{fname}' passed untrusted source '{src_sym}' for parameter '{param_name}'",
            )
            return TaintState.TAINTED, [hop], src_sym, False

        # Recurse if passed argument is a variable
        arg_vars = re.findall(r'\$[a-zA-Z_][a-zA-Z0-9_]*', passed_arg) if lang == "php" else re.findall(r'\b[a-zA-Z_][a-zA-Z0-9_]*\b', passed_arg)

        if not arg_vars:
            return TaintState.STATIC, [], "", False

        call_line = source_text[:call_match.start()].count("\n") + 1

        return self._propagate_var(
            var_name=arg_vars[0],
            before_line=call_line,
            graph_data=graph_data,
            sink_category=sink_category,
            visited_vars=visited_vars,
            flow_depth=flow_depth + 1,
            call_depth=call_depth + 1,
            assignment_hops=assignment_hops + 1,
            nodes_visited=nodes_visited + 1,
        )


# Global default instance
dataflow_analyzer = DataFlowAnalyzer()
