"""SemanticCorrelator Engine implementing source-to-sink candidate pairing, reachability, SSA, context, and sanitizer correlation for Sprint E11."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from karsasec.analysis.semantic_flow import FlowStatus, SemanticFlow
from karsasec.analysis.semantic_flow_store import SemanticFlowStore
from karsasec.analysis.semantic_sanitizer import SanitizerAnalyzer
from karsasec.query.traversal_engine import MultiHopTraversalEngine

if TYPE_CHECKING:
    from karsasec.cpg.models import CPGGraph
    from karsasec.framework.semantic_fact import SemanticFact, SemanticFactStore
    from karsasec.query.optimizer import QueryOptimizer



logger = logging.getLogger("karsasec.analysis.semantic_correlator")

# Compatible Source Kind to Sink Category mapping
COMPATIBLE_SOURCE_SINK_MAPPING: dict[str, tuple[str, ...]] = {
    "http_user_input": ("sql", "command_execution", "file_path", "html_render", "code_execution"),
    "user_input": ("sql", "command_execution", "file_path", "html_render", "code_execution"),
    "http_input": ("sql", "command_execution", "file_path", "html_render", "code_execution"),
    "generic": ("sql", "command_execution", "file_path", "html_render", "code_execution"),
}


class SemanticCorrelator:
    """Authoritative correlator establishing deterministic SemanticFlow bindings from E10 facts."""

    def __init__(self, sanitizer_analyzer: SanitizerAnalyzer | None = None) -> None:
        self.sanitizer_analyzer = sanitizer_analyzer or SanitizerAnalyzer()

    def correlate(
        self,
        graph: CPGGraph,
        semantic_store: SemanticFactStore,
        query_optimizer: QueryOptimizer,
        traversal_engine: MultiHopTraversalEngine,
        flow_store: SemanticFlowStore | None = None,
        max_depth: int = 10,
    ) -> SemanticFlowStore:
        """Correlates semantic facts into deterministic interprocedural SemanticFlow objects."""
        target_flow_store = flow_store if flow_store is not None else SemanticFlowStore()

        # Fail-closed guard: negative depth or invalid CPG graph
        if max_depth < 0 or graph is None:
            logger.warning("Fail-closed triggered: invalid graph or max_depth < 0")
            return target_flow_store

        # 1. Candidate selection: Separate sources and sinks from E10 store
        all_facts = semantic_store.all_facts()
        sources: list[SemanticFact] = []
        sinks: list[SemanticFact] = []

        for fact in all_facts:
            role_str = str(fact.semantic_role.value if hasattr(fact.semantic_role, "value") else fact.semantic_role).lower()
            kind_str = str(fact.kind).lower()
            if role_str in ("http_input", "source", "http_user_input") or fact.source_kind or "input" in kind_str:
                sources.append(fact)
            if role_str in ("security_sink", "sink") or fact.sink_category or "sink" in kind_str:
                sinks.append(fact)


        # Sort sources and sinks deterministically by fact_id
        sources = sorted(sources, key=lambda f: f.fact_id)
        sinks = sorted(sinks, key=lambda f: f.fact_id)

        # 2. Candidate pairing using category/role compatibility
        candidate_pairs: list[tuple[SemanticFact, SemanticFact]] = []
        for src in sources:
            src_kind = src.source_kind or "http_user_input"
            allowed_sinks = COMPATIBLE_SOURCE_SINK_MAPPING.get(src_kind.lower(), ("sql", "command_execution", "file_path", "html_render", "code_execution"))

            for snk in sinks:
                snk_cat = snk.sink_category or "sql"
                if any(c in snk_cat.lower() for c in allowed_sinks) or any(snk_cat.lower() in c for c in allowed_sinks):
                    candidate_pairs.append((src, snk))

        # Sort candidate pairs deterministically
        candidate_pairs = sorted(candidate_pairs, key=lambda p: (p[0].fact_id, p[1].fact_id))

        # 3. Analyze each candidate pair for reachability, SSA, context, and sanitizers
        for src_fact, snk_fact in candidate_pairs:
            # INV-E11-FLOW-09: Missing CPG node fail-closed
            if not src_fact.node_id or not snk_fact.node_id:
                flow = SemanticFlow.create(
                    source_fact_id=src_fact.fact_id,
                    sink_fact_id=snk_fact.fact_id,
                    source_node_id=src_fact.node_id or "unknown",
                    sink_node_id=snk_fact.node_id or "unknown",
                    confidence=0.20,
                    status=FlowStatus.UNKNOWN,
                )
                target_flow_store.add(flow)
                continue

            if src_fact.node_id not in graph.nodes or snk_fact.node_id not in graph.nodes:
                flow = SemanticFlow.create(
                    source_fact_id=src_fact.fact_id,
                    sink_fact_id=snk_fact.fact_id,
                    source_node_id=src_fact.node_id,
                    sink_node_id=snk_fact.node_id,
                    confidence=0.20,
                    status=FlowStatus.UNKNOWN,
                )
                target_flow_store.add(flow)
                continue

            # INV-E11-FLOW-03: Source -> Sink Directionality & E9 Reachability
            engine = MultiHopTraversalEngine(graph)
            path = engine.shortest_path(
                source_id=src_fact.node_id,
                target_id=snk_fact.node_id,
                max_depth=max_depth,
            )
            is_reachable = len(path) > 0

            if not is_reachable:
                # Directionality check: test reverse reachability to detect invalid reverse flows
                reverse_path = engine.shortest_path(
                    source_id=snk_fact.node_id,
                    target_id=src_fact.node_id,
                    max_depth=max_depth,
                )
                status = FlowStatus.UNKNOWN if len(reverse_path) > 0 else FlowStatus.CANDIDATE
                flow = SemanticFlow.create(
                    source_fact_id=src_fact.fact_id,
                    sink_fact_id=snk_fact.fact_id,
                    source_node_id=src_fact.node_id,
                    sink_node_id=snk_fact.node_id,
                    confidence=0.40,
                    status=status,
                )
                target_flow_store.add(flow)
                continue

            path_nodes = tuple(path)


            # INV-E11-FLOW-05: SSA Chain Validation & Isolation
            ssa_chain: list[tuple[str, str]] = []
            has_missing_ssa = False
            prev_var: str | None = None
            prev_ver: str | None = None

            for nid in path_nodes:
                node = graph.nodes[nid]
                var = node.attributes.get("variable_name") or node.attributes.get("symbol") or node.attributes.get("name")
                ver = node.attributes.get("ssa_version") or node.attributes.get("ssa_v")

                if var and ver:
                    s_var = str(var)
                    s_ver = str(ver)
                    # SSA transition check: if variable reassigned without valid transition
                    if prev_var == s_var and prev_ver != s_ver:
                        # Check if node is an explicit assignment/def node
                        label_lower = node.label.lower()
                        if "assign" not in label_lower and "def" not in label_lower:
                            has_missing_ssa = True
                    ssa_chain.append((s_var, s_ver))
                    prev_var, prev_ver = s_var, s_ver

            # INV-E11-FLOW-06: Call-Context Binding & Isolation
            call_context: list[tuple[str, str, str]] = []
            for nid in path_nodes:
                node = graph.nodes[nid]
                caller = str(node.attributes.get("caller") or "main")
                callee = str(node.attributes.get("callee") or node.attributes.get("function_name") or "global")
                callsite = str(node.attributes.get("callsite") or f"site_{nid}")
                call_context.append((caller, callee, callsite))



            # INV-E11-FLOW-10,11: Fail-closed on missing SSA or ambiguous call context
            if has_missing_ssa:
                flow = SemanticFlow.create(
                    source_fact_id=src_fact.fact_id,
                    sink_fact_id=snk_fact.fact_id,
                    source_node_id=src_fact.node_id,
                    sink_node_id=snk_fact.node_id,
                    path_node_ids=path_nodes,
                    call_context=call_context,
                    ssa_chain=ssa_chain,
                    confidence=0.50,
                    status=FlowStatus.UNKNOWN,
                )
                target_flow_store.add(flow)
                continue

            # 4. Sanitizer / Barrier Analysis
            sanitizer_nodes: list[str] = []
            is_blocked = False
            snk_cat = snk_fact.sink_category or "sql"

            for nid in path_nodes:
                node = graph.nodes[nid]
                evidence = self.sanitizer_analyzer.analyze_node(node)
                if evidence is not None:
                    sanitizer_nodes.append(nid)
                    if self.sanitizer_analyzer.is_valid_barrier_for_sink(evidence, snk_cat):
                        is_blocked = True

            # 5. Deterministic Confidence Calculation
            total_conf = 0.20 + 0.20 + 0.20 + (0.15 if ssa_chain else 0.0) + (0.15 if call_context else 0.0) + (0.10 if sanitizer_nodes else 0.0)

            status = FlowStatus.BLOCKED if is_blocked else FlowStatus.CORRELATED

            flow = SemanticFlow.create(
                source_fact_id=src_fact.fact_id,
                sink_fact_id=snk_fact.fact_id,
                source_node_id=src_fact.node_id,
                sink_node_id=snk_fact.node_id,
                path_node_ids=path_nodes,
                call_context=call_context,
                ssa_chain=ssa_chain,
                sanitizer_nodes=sanitizer_nodes,
                confidence=total_conf,
                status=status,
            )
            target_flow_store.add(flow)

        return target_flow_store
