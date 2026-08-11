"""Comprehensive test suite for Sprint E10-3F: Flask Semantic Correlation Hardening & Tier-C Rules."""

from __future__ import annotations

import hashlib
import importlib
import inspect
import random
from pathlib import Path

from karsasec.framework.extractors.flask.config.normalizer import FlaskConfigNormalizer
from karsasec.framework.extractors.flask.config.state import ConfigCandidate, FlaskConfigState
from karsasec.framework.extractors.flask.normalizer import FlaskRouteNormalizer
from karsasec.framework.extractors.flask.state import FlaskSemanticState, RawRouteRecord
from karsasec.framework.factories import FrameworkEdgeFactory, FrameworkNodeFactory
from karsasec.framework.framework_semantics.correlation.correlator import FlaskSemanticCorrelator
from karsasec.framework.framework_semantics.rules import GraphRuleLoader, GraphSecurityRuleEngine
from karsasec.framework.intermediate import (
    AuthDefinition,
    ConfigDefinition,
    IntermediateSemanticRepresentation,
    RouteDefinition,
)
from karsasec.framework.origin import EvidenceProvenance
from karsasec.framework.semantic_models import FrameworkSemanticGraph, SemanticEdgeType, SemanticNodeType


def test_evidence_provenance_dataclass_and_confidence_mapping() -> None:
    """Phase 1: Test EvidenceProvenance immutability, dict serialization, and deterministic confidence map."""
    p1 = EvidenceProvenance(
        value="HIGH",
        source_kind="explicit_decorator",
        file_path="app.py",
        line=42,
        origin_id="route:GET:/admin",
    )
    assert p1.confidence == "HIGH"
    assert p1.value == "HIGH"

    p2 = EvidenceProvenance(
        value="PROTECTS",
        source_kind="derived_relation",
        file_path="app.py",
        line=50,
    )
    assert p2.confidence == "MEDIUM"

    p3 = EvidenceProvenance(
        value="UNKNOWN",
        source_kind="unknown",
    )
    assert p3.confidence == "UNKNOWN"

    d = p1.to_dict()
    p1_deser = EvidenceProvenance.from_dict(d)
    assert p1_deser == p1


def test_isr_to_graph_provenance_traceability() -> None:
    """Phase 2 & 3: Test provenance_map propagation from ISR definitions to node attributes."""
    prov = EvidenceProvenance(
        value="HIGH",
        source_kind="explicit_decorator",
        file_path="routes/admin.py",
        line=15,
        origin_id="route:GET:/admin",
    )
    r = RouteDefinition(
        path="/admin",
        method="GET",
        handler="admin_view",
        sensitivity="HIGH",
        exposure="INTERNAL",
        provenance_map={"sensitivity": prov},
    )

    node = FrameworkNodeFactory.create_route_node(r)
    assert "_provenance" in node.attributes
    assert node.attributes["_provenance"]["sensitivity"]["confidence"] == "HIGH"
    assert node.attributes["_provenance"]["sensitivity"]["file_path"] == "routes/admin.py"


def test_route_conflict_resolution_conflict_to_unknown() -> None:
    """Phase 4: Test conflicting route decorators resolve sensitivity and exposure to UNKNOWN."""
    state = FlaskSemanticState()
    normalizer = FlaskRouteNormalizer(state)

    # Conflicting sensitivity: @sensitive AND @low_sensitivity
    rec_conflict_sens = RawRouteRecord(
        path="/admin",
        endpoint="admin_fn",
        file_path="app.py",
        line=10,
        decorators=("sensitive", "low_sensitivity"),
    )
    routes = normalizer.normalize([rec_conflict_sens])
    assert routes[0].sensitivity == "UNKNOWN"
    assert routes[0].provenance_map["sensitivity"].source_kind == "unknown"

    # Conflicting exposure: @internal AND @public
    rec_conflict_exp = RawRouteRecord(
        path="/api",
        endpoint="api_fn",
        file_path="app.py",
        line=20,
        decorators=("internal", "public"),
    )
    routes_exp = normalizer.normalize([rec_conflict_exp])
    assert routes_exp[0].exposure == "UNKNOWN"
    assert routes_exp[0].provenance_map["exposure"].source_kind == "unknown"


def test_config_environment_conflict_and_normalization() -> None:
    """Phase 4 & 5: Test environment conflict resolution and canonical normalization."""
    # 1. Canonical Normalization ("prod" -> "PRODUCTION")
    cfg_state1 = FlaskConfigState()
    cfg_state1.add_config(ConfigCandidate(key="ENV", value="prod", source_type="assignment", file_path="config.py", line=1))
    normalizer1 = FlaskConfigNormalizer(cfg_state1)
    configs1 = normalizer1.normalize()
    assert configs1[0].environment == "PRODUCTION"

    # 2. Environment Conflict ("production" AND "development") -> UNKNOWN
    cfg_state2 = FlaskConfigState()
    cfg_state2.add_config(ConfigCandidate(key="ENV", value="production", source_type="assignment", file_path="prod.py", line=1))
    cfg_state2.add_config(ConfigCandidate(key="FLASK_ENV", value="development", source_type="assignment", file_path="dev.py", line=2))
    normalizer2 = FlaskConfigNormalizer(cfg_state2)
    configs2 = normalizer2.normalize()
    assert configs2[0].environment == "UNKNOWN"


def test_tier_c_rule_auth_0004_positive_and_negative() -> None:
    """Phase 6 & 7: Test KS-FLASK-AUTH-0004 (Sensitive Endpoint Protected by Weak Auth)."""
    loader = GraphRuleLoader()
    rules = loader.load_directory(Path("karsasec/rules/patterns/flask"))
    rule_0004 = next(r for r in rules if r.id == "KS-FLASK-AUTH-0004")

    # Positive case: HIGH route protected by WEAK auth
    r_high = RouteDefinition(path="/admin/delete", method="POST", handler="delete_user", sensitivity="HIGH")
    a_weak = AuthDefinition(auth_type="BASIC", auth_strength="WEAK")

    isr_pos = IntermediateSemanticRepresentation(routes=(r_high,), auths=(a_weak,))
    correlator = FlaskSemanticCorrelator()
    c_res_pos = correlator.run(isr_pos)

    # Manually attach PROTECTS edge
    r_node_id = [n for n in c_res_pos.graph.nodes() if n.node_type == SemanticNodeType.ROUTE][0].id
    a_node_id = [n for n in c_res_pos.graph.nodes() if n.node_type == SemanticNodeType.AUTH][0].id
    edge = FrameworkEdgeFactory.create_edge(a_node_id, r_node_id, SemanticEdgeType.PROTECTS)

    nodes_dict = {n.id: n for n in c_res_pos.graph.nodes()}
    edges_tuple = c_res_pos.graph.edges() + (edge,)
    graph_pos = FrameworkSemanticGraph(nodes=nodes_dict, edges=edges_tuple)

    engine = GraphSecurityRuleEngine()
    findings_pos = engine.evaluate(graph_pos, [rule_0004])
    assert len(findings_pos.findings) == 1
    assert findings_pos.findings[0].rule_id == "KS-FLASK-AUTH-0004"

    # Negative case: HIGH route protected by STRONG auth
    a_strong = AuthDefinition(auth_type="JWT", auth_strength="STRONG")
    isr_neg = IntermediateSemanticRepresentation(routes=(r_high,), auths=(a_strong,))
    c_res_neg = correlator.run(isr_neg)
    r_node_id2 = [n for n in c_res_neg.graph.nodes() if n.node_type == SemanticNodeType.ROUTE][0].id
    a_node_id2 = [n for n in c_res_neg.graph.nodes() if n.node_type == SemanticNodeType.AUTH][0].id
    edge_strong = FrameworkEdgeFactory.create_edge(a_node_id2, r_node_id2, SemanticEdgeType.PROTECTS)
    graph_neg = FrameworkSemanticGraph(nodes={n.id: n for n in c_res_neg.graph.nodes()}, edges=c_res_neg.graph.edges() + (edge_strong,))

    findings_neg = engine.evaluate(graph_neg, [rule_0004])
    assert len(findings_neg.findings) == 0


def test_tier_c_rule_conf_0004_positive_and_negative() -> None:
    """Phase 6 & 7: Test KS-FLASK-CONF-0004 (Hardcoded Secret Key Assignment)."""
    loader = GraphRuleLoader()
    rules = loader.load_directory(Path("karsasec/rules/patterns/flask"))
    rule_conf = next(r for r in rules if r.id == "KS-FLASK-CONF-0004")
    engine = GraphSecurityRuleEngine()

    # Positive case: literal assignment
    cfg_pos = ConfigDefinition(key="SECRET_KEY", value="supersecret", source_kind="literal", provenance_type="assignment")
    isr_pos = IntermediateSemanticRepresentation(configs=(cfg_pos,))
    g_pos = FlaskSemanticCorrelator().run(isr_pos).graph
    findings_pos = engine.evaluate(g_pos, [rule_conf])
    assert len(findings_pos.findings) == 1

    # Negative case: env_var source_kind
    cfg_neg = ConfigDefinition(key="SECRET_KEY", value="MY_ENV_SECRET", source_kind="env_var", provenance_type="assignment")
    isr_neg = IntermediateSemanticRepresentation(configs=(cfg_neg,))
    g_neg = FlaskSemanticCorrelator().run(isr_neg).graph
    findings_neg = engine.evaluate(g_neg, [rule_conf])
    assert len(findings_neg.findings) == 0


def test_tier_c_rule_jwt_0002_positive_and_negative() -> None:
    """Phase 6 & 7: Test KS-FLASK-JWT-0002 (Insecure JWT Signing Policy Violation)."""
    loader = GraphRuleLoader()
    rules = loader.load_directory(Path("karsasec/rules/patterns/flask"))
    rule_jwt = next(r for r in rules if r.id == "KS-FLASK-JWT-0002")
    engine = GraphSecurityRuleEngine()

    # Positive case: jwt_algorithm == "none"
    auth_pos = AuthDefinition(auth_type="JWT", jwt_algorithm="none")
    g_pos = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(auths=(auth_pos,))).graph
    findings_pos = engine.evaluate(g_pos, [rule_jwt])
    assert len(findings_pos.findings) == 1

    # Negative case: jwt_algorithm == "RS256"
    auth_neg = AuthDefinition(auth_type="JWT", jwt_algorithm="RS256")
    g_neg = FlaskSemanticCorrelator().run(IntermediateSemanticRepresentation(auths=(auth_neg,))).graph
    findings_neg = engine.evaluate(g_neg, [rule_jwt])
    assert len(findings_neg.findings) == 0


def test_cross_node_evidence_isolation() -> None:
    """Phase 7: Test that evidence from node A does not leak onto node B during rule evaluation."""
    r_a = RouteDefinition(path="/admin", method="GET", handler="admin", sensitivity="HIGH")
    r_b = RouteDefinition(path="/public", method="GET", handler="pub", sensitivity="UNKNOWN")

    a_a = AuthDefinition(auth_type="BASIC", auth_strength="WEAK")
    a_b = AuthDefinition(auth_type="JWT", auth_strength="STRONG")

    correlator = FlaskSemanticCorrelator()
    graph = correlator.run(IntermediateSemanticRepresentation(routes=(r_a, r_b), auths=(a_a, a_b))).graph

    # Explicitly connect Auth B (STRONG) -> Route A (HIGH) and Auth A (WEAK) -> Route B (UNKNOWN)
    r_a_id = next(n.id for n in graph.nodes() if n.attributes.get("path") == "/admin")
    r_b_id = next(n.id for n in graph.nodes() if n.attributes.get("path") == "/public")
    a_a_id = next(n.id for n in graph.nodes() if n.attributes.get("auth_strength") == "WEAK")
    a_b_id = next(n.id for n in graph.nodes() if n.attributes.get("auth_strength") == "STRONG")

    e1 = FrameworkEdgeFactory.create_edge(a_b_id, r_a_id, SemanticEdgeType.PROTECTS)
    e2 = FrameworkEdgeFactory.create_edge(a_a_id, r_b_id, SemanticEdgeType.PROTECTS)

    nodes_dict = {n.id: n for n in graph.nodes()}
    edges_tuple = graph.edges() + (e1, e2)
    isolated_graph = FrameworkSemanticGraph(nodes=nodes_dict, edges=edges_tuple)

    loader = GraphRuleLoader()
    rules = loader.load_directory(Path("karsasec/rules/patterns/flask"))
    rule_0004 = next(r for r in rules if r.id == "KS-FLASK-AUTH-0004")
    engine = GraphSecurityRuleEngine()

    findings = engine.evaluate(isolated_graph, [rule_0004])
    # Route A has STRONG auth -> 0. Route B has UNKNOWN sensitivity -> 0. Total = 0.
    assert len(findings.findings) == 0


def test_determinism_and_shuffled_order_invariance() -> None:
    """Phase 8: Test 10x repeated execution and order shuffling invariance."""
    loader = GraphRuleLoader()
    rules = list(loader.load_directory(Path("karsasec/rules/patterns/flask")))

    # Build complex test graph
    r1 = RouteDefinition(path="/admin", method="GET", handler="admin", sensitivity="HIGH")
    r2 = RouteDefinition(path="/public", method="GET", handler="pub", sensitivity="UNKNOWN")
    a1 = AuthDefinition(auth_type="BASIC", auth_strength="WEAK")
    cfg1 = ConfigDefinition(key="SECRET_KEY", value="supersecret", source_kind="literal", provenance_type="assignment")

    base_isr = IntermediateSemanticRepresentation(routes=(r1, r2), auths=(a1,), configs=(cfg1,))
    base_graph = FlaskSemanticCorrelator().run(base_isr).graph

    # Add edge
    r1_id = next(n.id for n in base_graph.nodes() if n.attributes.get("path") == "/admin")
    a1_id = next(n.id for n in base_graph.nodes() if n.attributes.get("auth_strength") == "WEAK")
    edge = FrameworkEdgeFactory.create_edge(a1_id, r1_id, SemanticEdgeType.PROTECTS)
    full_graph = FrameworkSemanticGraph(
        nodes={n.id: n for n in base_graph.nodes()},
        edges=base_graph.edges() + (edge,),
    )

    fingerprints: list[str] = []

    for seed in range(10):
        rng = random.Random(seed)
        shuffled_rules = list(rules)
        rng.shuffle(shuffled_rules)

        shuffled_nodes_list = list(full_graph.nodes())
        rng.shuffle(shuffled_nodes_list)
        shuffled_nodes_dict = {n.id: n for n in shuffled_nodes_list}

        shuffled_edges = list(full_graph.edges())
        rng.shuffle(shuffled_edges)

        shuffled_g = FrameworkSemanticGraph(nodes=shuffled_nodes_dict, edges=tuple(shuffled_edges))

        engine = GraphSecurityRuleEngine()
        findings = engine.evaluate(shuffled_g, shuffled_rules)

        f_summary = ";".join(sorted(f"{f.rule_id}:{f.metadata.get('node_id')}" for f in findings.findings))
        fp = hashlib.sha256(f_summary.encode("utf-8")).hexdigest()
        fingerprints.append(fp)

    assert len(set(fingerprints)) == 1, "Order shuffling resulted in non-deterministic finding fingerprints!"


def test_security_boundary_static_analysis() -> None:
    """Phase 9: Verify rule engine and correlation modules do NOT import prohibited dynamic/AST modules."""
    prohibited_modules = {"ast", "subprocess", "requests", "socket", "urllib", "httpx", "importlib"}

    modules_to_check = [
        "karsasec.framework.framework_semantics.correlation.correlator",
        "karsasec.framework.framework_semantics.rules.engine",
        "karsasec.framework.framework_semantics.rules.predicates",
    ]

    for mod_name in modules_to_check:
        mod = importlib.import_module(mod_name)
        source = inspect.getsource(mod)
        for prohibited in prohibited_modules:
            assert f"import {prohibited}" not in source, f"Module {mod_name} imports prohibited module '{prohibited}'"
            assert f"from {prohibited}" not in source, f"Module {mod_name} imports from prohibited module '{prohibited}'"


def test_performance_scaling_benchmark() -> None:
    """Phase 10: Benchmark graph evaluation on 100, 1,000, 10,000 node synthetic graphs."""
    loader = GraphRuleLoader()
    rules = loader.load_directory(Path("karsasec/rules/patterns/flask"))
    engine = GraphSecurityRuleEngine()

    for node_count in (100, 1000, 10000):
        nodes_dict = {}
        for i in range(node_count):
            n = FrameworkNodeFactory.create_route_node(
                RouteDefinition(path=f"/path/{i}", method="GET", handler=f"fn_{i}", sensitivity="HIGH" if i == 0 else "UNKNOWN")
            )
            nodes_dict[n.id] = n

        synth_graph = FrameworkSemanticGraph(nodes=nodes_dict, edges=())
        findings = engine.evaluate(synth_graph, rules)
        assert findings is not None
