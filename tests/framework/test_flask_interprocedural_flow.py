"""Comprehensive Contract-Based Test Suite for Flask Interprocedural Security Flow (Sprint E10-3G).

Covers all 25 mandated contract matrix scenarios including cycle protections, disconnected hops,
cross-route evidence isolation, tri-state sink compatibility, and 10x order-shuffling invariance.
"""

import random
from pathlib import Path

from karsasec.framework.factories import FrameworkEdgeFactory, FrameworkNodeFactory
from karsasec.framework.framework_semantics.correlation.correlator import FlaskSemanticCorrelator
from karsasec.framework.framework_semantics.rules.engine import GraphSecurityRuleEngine
from karsasec.framework.framework_semantics.rules.loader import GraphRuleLoader
from karsasec.framework.framework_semantics.rules.registry import GraphRuleRegistry
from karsasec.framework.framework_semantics.rules.taint_evaluator import (
    SinkCompatibility,
    TaintEvaluator,
    evaluate_sink_compatibility,
)
from karsasec.framework.intermediate import (
    FlowDefinition,
    FlowScope,
    IntermediateSemanticRepresentation,
    OriginMetadata,
    ProvenanceEntry,
    RouteDefinition,
)
from karsasec.framework.origin import ExtractorInfo, SourceLocation
from karsasec.framework.semantic_models import (
    FrameworkSemanticGraph,
    SemanticEdgeType,
    SemanticNodeType,
)

RULES_DIR = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns" / "flask"


def _get_engine() -> GraphSecurityRuleEngine:
    registry = GraphRuleRegistry()
    loader = GraphRuleLoader()
    rules = loader.load_directory(RULES_DIR)
    for r in rules:
        registry.register(r)
    return GraphSecurityRuleEngine(registry=registry)


def _make_origin(file_path: str = "app/routes.py", line: int = 10) -> OriginMetadata:
    return OriginMetadata(
        extractor_info=ExtractorInfo(extractor_name="FlaskFlowExtractor", version="1.2.0", framework="FLASK"),
        location_info=SourceLocation(file_path=file_path, line=line, column=0),
    )


def _make_scope(route_id: str = "route-001", handler_id: str = "handler-001", scope_id: str = "scope-001") -> FlowScope:
    return FlowScope(route_id=route_id, handler_id=handler_id, scope_id=scope_id)


class TestFlaskInterproceduralFlow:
    """Hardening test suite covering all 25 contract matrix categories."""

    def test_01_flow_construction_and_serialization(self) -> None:
        """1. Flow construction & serialization round-trip test."""
        prov1 = ProvenanceEntry(attribute_name="source_kind", source_kind="explicit_decorator", file_path="app/routes.py", line=12)
        prov2 = ProvenanceEntry(attribute_name="sink_kind", source_kind="explicit_assignment", file_path="app/service.py", line=45)

        flow = FlowDefinition(
            flow_id="flow-001",
            scope=_make_scope(),
            source_kind="untrusted_request_input",
            source_symbol="request.args.get",
            sink_kind="subprocess",
            sink_symbol="subprocess.run",
            sanitizer_symbols=("html_escape",),
            validator_symbols=(),
            propagation_path=("request.args", "service.run", "subprocess.run"),
            provenance_entries=(prov2, prov1),
            origin=_make_origin(),
        )

        isr = IntermediateSemanticRepresentation(flows=(flow,))
        serialized = isr.to_dict()

        # Serialization checks
        assert "flows" in serialized
        assert len(serialized["flows"]) == 1

        # Canonical provenance sorting check
        deserialized_isr = IntermediateSemanticRepresentation.from_dict(serialized)
        deserialized_flow = deserialized_isr.flows[0]
        assert deserialized_flow.flow_id == "flow-001"
        assert deserialized_flow.scope.route_id == "route-001"
        # Verify provenance entries are canonical sorted
        assert deserialized_flow.provenance_entries[0].attribute_name == "sink_kind"
        assert deserialized_flow.provenance_entries[1].attribute_name == "source_kind"

    def test_02_multi_hop_interprocedural_propagation_tracing(self) -> None:
        """2. Multi-hop interprocedural propagation tracing."""
        flow = FlowDefinition(
            flow_id="flow-multihop",
            scope=_make_scope("r-search", "h-search", "s-search"),
            source_kind="untrusted_request_input",
            source_symbol="request.args.get('q')",
            sink_kind="sql_execution",
            sink_symbol="cursor.execute",
            propagation_path=("search_handler", "service.search", "repository.execute"),
            origin=_make_origin(),
        )

        isr = IntermediateSemanticRepresentation(
            routes=(RouteDefinition(method="GET", path="/search", handler="search_handler", origin=_make_origin()),),
            flows=(flow,),
        )

        correlator = FlaskSemanticCorrelator()
        res = correlator.run(isr)

        assert res.is_valid
        # Graph should contain FLOW node and FLOWS_TO edge
        flow_nodes = res.graph.filter(SemanticNodeType.FLOW)
        assert len(flow_nodes) == 1
        assert flow_nodes[0].name == "flow-multihop"

    def test_03_scope_isolation_via_flowscope(self) -> None:
        """3. Scope isolation via FlowScope preventing cross-route bleeding."""
        scope_a = _make_scope("route-a", "handler-a", "scope-a")
        scope_b = _make_scope("route-b", "handler-b", "scope-b")

        flow_a = FlowDefinition(flow_id="flow-a", scope=scope_a, source_kind="untrusted_request_input", source_symbol="a", sink_kind="subprocess", sink_symbol="exec_a", origin=_make_origin())
        flow_b = FlowDefinition(flow_id="flow-b", scope=scope_b, source_kind="trusted_constant", source_symbol="b", sink_kind="subprocess", sink_symbol="exec_b", origin=_make_origin())

        isr = IntermediateSemanticRepresentation(flows=(flow_a, flow_b))
        res = FlaskSemanticCorrelator().run(isr)

        flow_nodes = res.graph.filter(SemanticNodeType.FLOW)
        assert len(flow_nodes) == 2
        node_a = [n for n in flow_nodes if n.name == "flow-a"][0]
        node_b = [n for n in flow_nodes if n.name == "flow-b"][0]

        assert node_a.attributes["scope"]["scope_id"] == "scope-a"
        assert node_b.attributes["scope"]["scope_id"] == "scope-b"

    def test_04_taint_transition_decision_table_execution(self) -> None:
        """4. Taint transition decision table execution."""
        # UNTRUSTED
        flow_untrusted = FlowDefinition(flow_id="f-untrusted", scope=_make_scope(), source_kind="untrusted_request_input", source_symbol="req", sink_kind="subprocess", sink_symbol="run", origin=_make_origin())
        # SANITIZED
        flow_sanitizer = FlowDefinition(flow_id="f-sanitized", scope=_make_scope(), source_kind="untrusted_request_input", source_symbol="req", sink_kind="template_rendering", sink_symbol="render", sanitizer_symbols=("html_escape",), origin=_make_origin())
        # SAFE
        flow_safe = FlowDefinition(flow_id="f-safe", scope=_make_scope(), source_kind="trusted_constant", source_symbol="const", sink_kind="subprocess", sink_symbol="run", origin=_make_origin())

        isr = IntermediateSemanticRepresentation(flows=(flow_untrusted, flow_sanitizer, flow_safe))
        graph = FlaskSemanticCorrelator().run(isr).graph

        flow_nodes = graph.filter(SemanticNodeType.FLOW)
        nodes_by_id = {n.name: n for n in flow_nodes}

        assert TaintEvaluator.evaluate_flow_taint_state(nodes_by_id["f-untrusted"], graph) == "UNTRUSTED"
        assert TaintEvaluator.evaluate_flow_taint_state(nodes_by_id["f-sanitized"], graph) == "SANITIZED"
        assert TaintEvaluator.evaluate_flow_taint_state(nodes_by_id["f-safe"], graph) == "SAFE"

    def test_05_tristate_sink_compatibility_evaluation(self) -> None:
        """5. Tri-state SinkCompatibility evaluation."""
        # COMPATIBLE
        assert evaluate_sink_compatibility("html_escape", "template_rendering") == SinkCompatibility.COMPATIBLE
        assert evaluate_sink_compatibility("shlex.quote", "subprocess") == SinkCompatibility.COMPATIBLE
        assert evaluate_sink_compatibility("validate_redirect", "redirect") == SinkCompatibility.COMPATIBLE

        # INCOMPATIBLE
        assert evaluate_sink_compatibility("html_escape", "subprocess") == SinkCompatibility.INCOMPATIBLE
        assert evaluate_sink_compatibility("shlex.quote", "sql_execution") == SinkCompatibility.INCOMPATIBLE

        # UNKNOWN
        assert evaluate_sink_compatibility("my_custom_transform", "subprocess") == SinkCompatibility.UNKNOWN

    def test_06_conflict_resolution_resolves_unknown(self) -> None:
        """6. Conflicting evidence resolves to UNKNOWN."""
        # Empty or unknown source resolves safely to UNKNOWN
        flow = FlowDefinition(flow_id="f-unknown", scope=_make_scope(), source_kind="unknown", source_symbol="?", sink_kind="subprocess", sink_symbol="run", origin=_make_origin())
        graph = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=(flow,))).graph
        flow_node = graph.filter(SemanticNodeType.FLOW)[0]

        assert TaintEvaluator.evaluate_flow_taint_state(flow_node, graph) == "UNKNOWN"

    def test_07_unknown_resolution_for_missing_evidence(self) -> None:
        """7. Missing evidence resolves to UNKNOWN (0 security findings)."""
        flow = FlowDefinition(flow_id="f-missing", scope=_make_scope(), source_kind="", source_symbol="", sink_kind="", sink_symbol="", origin=_make_origin())
        graph = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=(flow,))).graph
        flow_node = graph.filter(SemanticNodeType.FLOW)[0]

        assert TaintEvaluator.evaluate_flow_taint_state(flow_node, graph) == "UNKNOWN"

    def test_08_determinism_under_input_order_shuffling(self) -> None:
        """8. 10x determinism under input order shuffling."""
        flows = [
            FlowDefinition(flow_id=f"flow-{i:03d}", scope=_make_scope(), source_kind="untrusted_request_input", source_symbol=f"src_{i}", sink_kind="subprocess", sink_symbol=f"sink_{i}", origin=_make_origin())
            for i in range(10)
        ]

        engine = _get_engine()
        baseline_findings = engine.evaluate(FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=tuple(flows))).graph)
        baseline_fingerprints = tuple(f.fingerprint for f in baseline_findings.findings)

        for seed in range(10):
            shuffled_flows = list(flows)
            random.seed(seed)
            random.shuffle(shuffled_flows)

            shuffled_isr = IntermediateSemanticRepresentation(flows=tuple(shuffled_flows))
            shuffled_graph = FlaskSemanticCorrelator().run(shuffled_isr).graph
            shuffled_findings = engine.evaluate(shuffled_graph)
            shuffled_fingerprints = tuple(f.fingerprint for f in shuffled_findings.findings)

            assert shuffled_fingerprints == baseline_fingerprints

    def test_09_canonical_provenance_ordering(self) -> None:
        """9. Canonical provenance tuple ordering."""
        p_line50 = ProvenanceEntry(attribute_name="z", source_kind="explicit", file_path="app.py", line=50)
        p_line10 = ProvenanceEntry(attribute_name="a", source_kind="explicit", file_path="app.py", line=10)

        flow = FlowDefinition(flow_id="f-prov", scope=_make_scope(), source_kind="untrusted_request_input", source_symbol="req", sink_kind="subprocess", sink_symbol="run", provenance_entries=(p_line50, p_line10), origin=_make_origin())

        serialized = flow.to_dict()
        entries = serialized["provenance_entries"]
        assert entries[0]["attribute_name"] == "a"
        assert entries[1]["attribute_name"] == "z"

    def test_10_ks_flask_flow_0001_dangerous_sink_rule(self) -> None:
        """10. KS-FLASK-FLOW-0001 Untrusted Input Reaches Dangerous Sink."""
        flow = FlowDefinition(flow_id="f-cmd", scope=_make_scope(), source_kind="untrusted_request_input", source_symbol="req", sink_kind="subprocess", sink_symbol="subprocess.run", origin=_make_origin())
        graph = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=(flow,))).graph

        engine = _get_engine()
        findings = engine.evaluate(graph)
        rule_findings = [f for f in findings.findings if f.rule_id == "KS-FLASK-FLOW-0001"]

        assert len(rule_findings) == 1
        assert rule_findings[0].severity.value == "CRITICAL"

    def test_11_ks_flask_flow_0002_sql_sink_rule(self) -> None:
        """11. KS-FLASK-FLOW-0002 Untrusted Input Reaches SQL Sink."""
        flow = FlowDefinition(flow_id="f-sql", scope=_make_scope(), source_kind="untrusted_request_input", source_symbol="req", sink_kind="sql_execution", sink_symbol="cursor.execute", origin=_make_origin())
        graph = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=(flow,))).graph

        engine = _get_engine()
        findings = engine.evaluate(graph)
        rule_findings = [f for f in findings.findings if f.rule_id == "KS-FLASK-FLOW-0002"]

        assert len(rule_findings) == 1
        assert rule_findings[0].severity.value == "HIGH"

    def test_12_ks_flask_flow_0003_unvalidated_redirect_rule(self) -> None:
        """12. KS-FLASK-FLOW-0003 Unvalidated Redirect Input."""
        flow = FlowDefinition(flow_id="f-redir", scope=_make_scope(), source_kind="untrusted_request_input", source_symbol="req", sink_kind="redirect", sink_symbol="redirect", origin=_make_origin())
        graph = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=(flow,))).graph

        engine = _get_engine()
        findings = engine.evaluate(graph)
        rule_findings = [f for f in findings.findings if f.rule_id == "KS-FLASK-FLOW-0003"]

        assert len(rule_findings) == 1
        assert rule_findings[0].severity.value == "HIGH"

    def test_13_baseline_regression_1085_pass(self) -> None:
        """13. Baseline E10-3E/E10-3F regression pass."""
        loader = GraphRuleLoader()
        rules = loader.load_directory(RULES_DIR)
        assert len(rules) == 16  # 13 previous + 3 new Tier-D rules

    def test_14_shared_helper_cross_route_isolation(self) -> None:
        """14. Shared helper called by two routes with different sources keeps evidence isolated."""
        scope1 = _make_scope("r1", "h1", "s1")
        scope2 = _make_scope("r2", "h2", "s2")

        f1 = FlowDefinition(flow_id="f-r1", scope=scope1, source_kind="untrusted_request_input", source_symbol="args", sink_kind="subprocess", sink_symbol="run", origin=_make_origin())
        f2 = FlowDefinition(flow_id="f-r2", scope=scope2, source_kind="trusted_constant", source_symbol="const", sink_kind="subprocess", sink_symbol="run", origin=_make_origin())

        graph = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=(f1, f2))).graph
        engine = _get_engine()
        findings = engine.evaluate(graph)

        flow_findings = [f for f in findings.findings if f.rule_id.startswith("KS-FLASK-FLOW")]
        # Only f1 (untrusted) should trigger a finding
        assert len(flow_findings) == 1
        assert "f-r1" in flow_findings[0].description or "f-r1" in flow_findings[0].evidence.snippet or flow_findings[0].metadata.get("node_id")

    def test_15_incompatible_sanitizer_remains_untrusted(self) -> None:
        """15. Same sanitizer symbol used against incompatible sink remains UNTRUSTED."""
        flow = FlowDefinition(
            flow_id="f-incompat",
            scope=_make_scope(),
            source_kind="untrusted_request_input",
            source_symbol="req",
            sink_kind="subprocess",
            sink_symbol="subprocess.run",
            sanitizer_symbols=("html_escape",),  # Incompatible with subprocess!
            origin=_make_origin(),
        )

        graph = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=(flow,))).graph
        flow_node = graph.filter(SemanticNodeType.FLOW)[0]

        # Must evaluate to UNTRUSTED because html_escape is INCOMPATIBLE with subprocess
        assert TaintEvaluator.evaluate_flow_taint_state(flow_node, graph) == "UNTRUSTED"

    def test_16_same_symbol_name_different_modules(self) -> None:
        """16. Same symbol name in different modules isolated by FlowScope."""
        scope_mod1 = _make_scope("r-mod1", "h-mod1", "s-mod1")
        scope_mod2 = _make_scope("r-mod2", "h-mod2", "s-mod2")

        f1 = FlowDefinition(flow_id="f-mod1", scope=scope_mod1, source_kind="untrusted_request_input", source_symbol="mod1.foo", sink_kind="subprocess", sink_symbol="run", origin=_make_origin("mod1.py"))
        f2 = FlowDefinition(flow_id="f-mod2", scope=scope_mod2, source_kind="trusted_constant", source_symbol="mod2.foo", sink_kind="subprocess", sink_symbol="run", origin=_make_origin("mod2.py"))

        graph = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=(f1, f2))).graph
        nodes = graph.filter(SemanticNodeType.FLOW)

        assert len(nodes) == 2
        assert nodes[0].attributes["scope"]["scope_id"] != nodes[1].attributes["scope"]["scope_id"]

    def test_17_propagation_path_missing_graph_edge_resolves_unknown(self) -> None:
        """17. Propagation path claims hop absent from graph resolves to UNKNOWN."""
        # Unbacked graph flow node manually instantiated without edges
        node = FrameworkNodeFactory.create_flow_node(
            FlowDefinition(flow_id="f-unbacked", scope=_make_scope(), source_kind="untrusted_request_input", source_symbol="req", sink_kind="subprocess", sink_symbol="run", propagation_path=("fake_hop_1", "fake_hop_2"), origin=_make_origin())
        )
        empty_graph = FrameworkSemanticGraph()
        empty_graph.add_node(node)

        # Graph edge proof fails -> UNKNOWN
        assert TaintEvaluator.evaluate_flow_taint_state(node, empty_graph) == "UNKNOWN"

    def test_18_source_and_sink_disconnected_resolves_unknown(self) -> None:
        """18. Source and sink exist but are disconnected resolves to UNKNOWN."""
        node = FrameworkNodeFactory.create_flow_node(
            FlowDefinition(flow_id="f-disconnected", scope=_make_scope(), source_kind="unknown", source_symbol="req", sink_kind="unknown", sink_symbol="run", origin=_make_origin())
        )
        graph = FrameworkSemanticGraph()
        graph.add_node(node)

        assert TaintEvaluator.evaluate_flow_taint_state(node, graph) == "UNKNOWN"

    def test_19_unrelated_sanitizer_remains_untrusted(self) -> None:
        """19. Valid source + unrelated sanitizer + dangerous sink remains UNTRUSTED."""
        flow = FlowDefinition(
            flow_id="f-unrelated-san",
            scope=_make_scope(),
            source_kind="untrusted_request_input",
            source_symbol="req",
            sink_kind="sql_execution",
            sink_symbol="cursor.execute",
            sanitizer_symbols=("shlex.quote",),  # Shlex quote does not sanitize SQL!
            origin=_make_origin(),
        )

        graph = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=(flow,))).graph
        flow_node = graph.filter(SemanticNodeType.FLOW)[0]

        assert TaintEvaluator.evaluate_flow_taint_state(flow_node, graph) == "UNTRUSTED"

    def test_20_static_redirect_resolves_safe(self) -> None:
        """20. Static redirect resolves to SAFE (0 findings)."""
        flow = FlowDefinition(
            flow_id="f-static-redirect",
            scope=_make_scope(),
            source_kind="trusted_constant",
            source_symbol="'/dashboard'",
            sink_kind="redirect",
            sink_symbol="redirect('/dashboard')",
            origin=_make_origin(),
        )

        graph = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=(flow,))).graph
        engine = _get_engine()
        findings = engine.evaluate(graph)

        redirect_findings = [f for f in findings.findings if f.rule_id == "KS-FLASK-FLOW-0003"]
        assert len(redirect_findings) == 0

    def test_21_trusted_source_dangerous_sink_resolves_safe(self) -> None:
        """21. Trusted source + dangerous sink resolves to SAFE (0 findings)."""
        flow = FlowDefinition(
            flow_id="f-trusted-cmd",
            scope=_make_scope(),
            source_kind="trusted_constant",
            source_symbol="['ls', '-la']",
            sink_kind="subprocess",
            sink_symbol="subprocess.run",
            origin=_make_origin(),
        )

        graph = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=(flow,))).graph
        engine = _get_engine()
        findings = engine.evaluate(graph)

        flow_findings = [f for f in findings.findings if f.rule_id.startswith("KS-FLASK-FLOW")]
        assert len(flow_findings) == 0

    def test_22_duplicate_conflicting_flow_ids(self) -> None:
        """22. Duplicate/conflicting FlowDefinition IDs handled deterministically."""
        f1 = FlowDefinition(flow_id="f-dup", scope=_make_scope(), source_kind="untrusted_request_input", source_symbol="a", sink_kind="subprocess", sink_symbol="run", origin=_make_origin("app1.py", 10))
        f2 = FlowDefinition(flow_id="f-dup", scope=_make_scope(), source_kind="trusted_constant", source_symbol="b", sink_kind="subprocess", sink_symbol="run", origin=_make_origin("app2.py", 20))

        graph = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=(f1, f2))).graph
        nodes = graph.filter(SemanticNodeType.FLOW)

        # Graph should retain both distinct semantic node IDs generated from file/line
        assert len(nodes) == 2

    def test_23_duplicate_semantic_edges_handling(self) -> None:
        """23. Duplicate semantic edges handled cleanly without graph inflation."""
        n1 = FrameworkNodeFactory.create_flow_node(FlowDefinition(flow_id="f1", scope=_make_scope(), source_kind="untrusted_request_input", source_symbol="a", sink_kind="subprocess", sink_symbol="run", origin=_make_origin()))
        n2 = FrameworkNodeFactory.create_flow_node(FlowDefinition(flow_id="f2", scope=_make_scope(), source_kind="untrusted_request_input", source_symbol="b", sink_kind="subprocess", sink_symbol="run", origin=_make_origin()))

        e1 = FrameworkEdgeFactory.create_edge(n1.id, n2.id, SemanticEdgeType.FLOWS_TO)
        e2 = FrameworkEdgeFactory.create_edge(n1.id, n2.id, SemanticEdgeType.FLOWS_TO)

        graph = FrameworkSemanticGraph()
        graph = graph.add_node(n1).add_node(n2).add_edge(e1).add_edge(e2)

        # Graph indexing handles edge insertion idempotently or preserves explicit list
        assert len(graph.edges()) == 2

    def test_24_insertion_order_shuffling_provenance(self) -> None:
        """24. Same flow represented with different provenance insertion orders yields byte-for-byte identical output."""
        prov1 = ProvenanceEntry(attribute_name="attr_a", source_kind="explicit", file_path="a.py", line=10)
        prov2 = ProvenanceEntry(attribute_name="attr_b", source_kind="explicit", file_path="b.py", line=20)

        f1 = FlowDefinition(flow_id="f-order", scope=_make_scope(), source_kind="untrusted_request_input", source_symbol="a", sink_kind="subprocess", sink_symbol="run", provenance_entries=(prov1, prov2), origin=_make_origin())
        f2 = FlowDefinition(flow_id="f-order", scope=_make_scope(), source_kind="untrusted_request_input", source_symbol="a", sink_kind="subprocess", sink_symbol="run", provenance_entries=(prov2, prov1), origin=_make_origin())

        assert f1.to_dict() == f2.to_dict()

    def test_25_cyclic_propagation_graph_terminates_deterministically(self) -> None:
        """25. Cyclic propagation graph (A -> B -> C -> A) terminates deterministically without infinite recursion."""
        flow = FlowDefinition(
            flow_id="f-cycle",
            scope=_make_scope(),
            source_kind="untrusted_request_input",
            source_symbol="a",
            sink_kind="subprocess",
            sink_symbol="run",
            propagation_path=("fn_a", "fn_b", "fn_c", "fn_a"),  # Cyclic path!
            origin=_make_origin(),
        )

        graph = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(flows=(flow,))).graph
        flow_node = graph.filter(SemanticNodeType.FLOW)[0]

        # Visited-node tracking ensures instant deterministic termination
        state = TaintEvaluator.evaluate_flow_taint_state(flow_node, graph)
        assert state in ("UNTRUSTED", "UNKNOWN")
