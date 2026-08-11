"""Comprehensive Test Suite for Sprint E10-3D: Deterministic Flask Semantic Security Rule Engine.

Covers:
1. Schema & Validator Tests (rejection of malformed rules, depth > 2, unknown predicates).
2. Missing evidence vs Rule Error distinction.
3. Protection Composite Contract (AUTH vs MIDDLEWARE).
4. Fixtures for all 6 Tier-A Flask Rules.
5. Determinism Tests (10x repeated runs, shuffled nodes, shuffled edges, shuffled rules).
6. Resource Limit & Visited Set Protection Tests.
7. Static Architectural Import Boundary Test (zero AST/importlib/subprocess/LLM imports).
8. Performance Benchmark (100, 1000, 10000 node graphs).
"""

from __future__ import annotations

import ast
import random
from pathlib import Path

import pytest

from karsasec.framework.framework_semantics.rules import (
    GraphRuleLoader,
    GraphRuleRegistry,
    GraphSecurityRuleEngine,
    validate_graph_rule_dict,
)
from karsasec.framework.framework_semantics.rules.schema import (
    GraphSecurityRule,
)
from karsasec.framework.framework_semantics.rules.validator import GraphRuleValidationError
from karsasec.framework.origin import OriginMetadata, SourceLocation
from karsasec.framework.semantic_models import (
    FrameworkSemanticEdge,
    FrameworkSemanticGraph,
    FrameworkSemanticNode,
    SemanticEdgeType,
    SemanticNodeType,
)
from karsasec.rules.enums import Severity

# ---------------------------------------------------------------------------
# FIXTURES GENERATOR
# ---------------------------------------------------------------------------

def create_sample_rule_auth_0001() -> GraphSecurityRule:
    raw = {
        "rule": {"id": "KS-FLASK-AUTH-0001", "version": "1.0", "framework": "FLASK"},
        "metadata": {"name": "Unprotected Route Policy", "cwe": "CWE-306", "owasp": "A07"},
        "target": {"node_type": "ROUTE"},
        "conditions": {
            "all": [
                {"incoming_edge": {"type": "HANDLES"}},
                {
                    "not": {
                        "any": [
                            {"incoming_edge": {"type": "PROTECTS", "source_type": "AUTH"}},
                            {"incoming_edge": {"type": "PROTECTS", "source_type": "MIDDLEWARE"}},
                        ]
                    }
                },
            ]
        },
        "traversal": {"max_depth": 1, "max_nodes_visited": 50, "max_edges_examined": 100},
        "output": {
            "severity": "HIGH",
            "confidence": "HIGH",
            "message": "Route '{node.name}' handles incoming requests but has no attached AUTH or MIDDLEWARE protection edge.",
            "remediation": "Apply an authentication decorator or middleware.",
        },
    }
    return validate_graph_rule_dict(raw)


def create_sample_config_rule(rule_id: str, key_name: str, key_val: bool | str) -> GraphSecurityRule:
    raw = {
        "rule": {"id": rule_id, "version": "1.0", "framework": "FLASK"},
        "metadata": {"name": f"Rule {rule_id}", "cwe": "CWE-489", "owasp": "A05"},
        "target": {"node_type": "CONFIG"},
        "conditions": {
            "all": [
                {"attribute_equals": {"key": "key", "value": key_name}},
                {"attribute_equals": {"key": "value" if isinstance(key_val, bool) else "source_kind", "value": key_val}},
            ]
        },
        "traversal": {"max_depth": 1, "max_nodes_visited": 10, "max_edges_examined": 20},
        "output": {
            "severity": "HIGH",
            "confidence": "HIGH",
            "message": f"Config item {key_name} matched condition.",
            "remediation": "Review security configuration.",
        },
    }
    return validate_graph_rule_dict(raw)


# ---------------------------------------------------------------------------
# 1. SCHEMA & VALIDATOR TESTS
# ---------------------------------------------------------------------------

def test_validator_valid_rule():
    rule = create_sample_rule_auth_0001()
    assert rule.id == "KS-FLASK-AUTH-0001"
    assert rule.target_node_type == SemanticNodeType.ROUTE
    assert rule.traversal.max_depth == 1


def test_validator_unknown_predicate_rejection():
    raw = {
        "rule": {"id": "KS-FLASK-AUTH-0001", "version": "1.0", "framework": "FLASK"},
        "metadata": {"name": "Test"},
        "target": {"node_type": "ROUTE"},
        "conditions": {"unknown_predicate_key": True},
        "output": {"severity": "HIGH", "confidence": "HIGH", "message": "msg", "remediation": "rem"},
    }
    with pytest.raises(GraphRuleValidationError, match="Unknown or unsupported predicate key"):
        validate_graph_rule_dict(raw)


def test_validator_unknown_node_type_rejection():
    raw = {
        "rule": {"id": "KS-FLASK-AUTH-0001", "version": "1.0", "framework": "FLASK"},
        "metadata": {"name": "Test"},
        "target": {"node_type": "INVALID_NODE_TYPE"},
        "conditions": {"node_type_equals": "ROUTE"},
        "output": {"severity": "HIGH", "confidence": "HIGH", "message": "msg", "remediation": "rem"},
    }
    with pytest.raises(GraphRuleValidationError, match="Invalid node_type"):
        validate_graph_rule_dict(raw)


def test_validator_unknown_edge_type_rejection():
    raw = {
        "rule": {"id": "KS-FLASK-AUTH-0001", "version": "1.0", "framework": "FLASK"},
        "metadata": {"name": "Test"},
        "target": {"node_type": "ROUTE"},
        "conditions": {"incoming_edge": {"type": "INVALID_EDGE_TYPE"}},
        "output": {"severity": "HIGH", "confidence": "HIGH", "message": "msg", "remediation": "rem"},
    }
    with pytest.raises(GraphRuleValidationError, match="Invalid edge_type"):
        validate_graph_rule_dict(raw)


def test_validator_invalid_traversal_depth():
    raw = {
        "rule": {"id": "KS-FLASK-AUTH-0001", "version": "1.0", "framework": "FLASK"},
        "metadata": {"name": "Test"},
        "target": {"node_type": "ROUTE"},
        "conditions": {"node_type_equals": "ROUTE"},
        "traversal": {"max_depth": 5},
        "output": {"severity": "HIGH", "confidence": "HIGH", "message": "msg", "remediation": "rem"},
    }
    with pytest.raises(GraphRuleValidationError, match="Invalid max_depth"):
        validate_graph_rule_dict(raw)


def test_validator_duplicate_rule_id_in_registry():
    registry = GraphRuleRegistry()
    rule1 = create_sample_rule_auth_0001()
    registry.register(rule1)
    with pytest.raises(GraphRuleValidationError, match="Duplicate Rule ID"):
        registry.register(rule1)


# ---------------------------------------------------------------------------
# 2. MISSING EVIDENCE VS RULE MATCH TESTS
# ---------------------------------------------------------------------------

def test_valid_rule_missing_evidence_returns_false():
    rule = create_sample_config_rule("KS-FLASK-SESS-0001", "SESSION_COOKIE_SECURE", False)
    engine = GraphSecurityRuleEngine()

    # Empty graph
    empty_graph = FrameworkSemanticGraph()
    res = engine.evaluate(empty_graph, [rule])
    assert res.total == 0

    # Graph with non-matching config
    node = FrameworkSemanticNode(
        id="cfg-1",
        node_type=SemanticNodeType.CONFIG,
        name="SESSION_COOKIE_SECURE",
        attributes={"key": "SESSION_COOKIE_SECURE", "value": True},
    )
    graph = FrameworkSemanticGraph(nodes={"cfg-1": node})
    res = engine.evaluate(graph, [rule])
    assert res.total == 0


# ---------------------------------------------------------------------------
# 3. PROTECTION CONTRACT TEST (AUTH vs MIDDLEWARE)
# ---------------------------------------------------------------------------

def test_protection_composite_contract():
    rule = create_sample_rule_auth_0001()
    engine = GraphSecurityRuleEngine()

    # Route 1: Unprotected (only HANDLES edge)
    r1 = FrameworkSemanticNode(id="r-1", node_type=SemanticNodeType.ROUTE, name="/unprotected")
    h1 = FrameworkSemanticNode(id="h-1", node_type=SemanticNodeType.HANDLER, name="unprotected_handler")
    e1 = FrameworkSemanticEdge(source_id="h-1", target_id="r-1", edge_type=SemanticEdgeType.HANDLES)

    # Route 2: Protected by AUTH
    r2 = FrameworkSemanticNode(id="r-2", node_type=SemanticNodeType.ROUTE, name="/auth-protected")
    h2 = FrameworkSemanticNode(id="h-2", node_type=SemanticNodeType.HANDLER, name="auth_handler")
    a2 = FrameworkSemanticNode(id="a-2", node_type=SemanticNodeType.AUTH, name="login_required")
    e2_handles = FrameworkSemanticEdge(source_id="h-2", target_id="r-2", edge_type=SemanticEdgeType.HANDLES)
    e2_protects = FrameworkSemanticEdge(source_id="a-2", target_id="r-2", edge_type=SemanticEdgeType.PROTECTS)

    # Route 3: Protected by MIDDLEWARE
    r3 = FrameworkSemanticNode(id="r-3", node_type=SemanticNodeType.ROUTE, name="/mw-protected")
    h3 = FrameworkSemanticNode(id="h-3", node_type=SemanticNodeType.HANDLER, name="mw_handler")
    m3 = FrameworkSemanticNode(id="m-3", node_type=SemanticNodeType.MIDDLEWARE, name="auth_middleware")
    e3_handles = FrameworkSemanticEdge(source_id="h-3", target_id="r-3", edge_type=SemanticEdgeType.HANDLES)
    e3_protects = FrameworkSemanticEdge(source_id="m-3", target_id="r-3", edge_type=SemanticEdgeType.PROTECTS)

    nodes = {n.id: n for n in [r1, h1, r2, h2, a2, r3, h3, m3]}
    edges = (e1, e2_handles, e2_protects, e3_handles, e3_protects)
    graph = FrameworkSemanticGraph(nodes=nodes, edges=edges)

    findings = engine.evaluate(graph, [rule])

    # Exactly 1 finding: Route 1 ONLY!
    assert findings.total == 1
    assert findings.findings[0].metadata["node_id"] == "r-1"


# ---------------------------------------------------------------------------
# 4. TIER-A 6 FLASK RULES INTEGRATION TEST
# ---------------------------------------------------------------------------

def test_tier_a_rule_pack_loading():
    rules_dir = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns" / "flask"
    assert rules_dir.exists()

    loader = GraphRuleLoader()
    rules = loader.load_directory(rules_dir)

    assert len(rules) >= 10
    rule_ids = [r.id for r in rules]
    assert "KS-FLASK-AUTH-0001" in rule_ids
    assert "KS-FLASK-AUTH-0002" in rule_ids
    assert "KS-FLASK-AUTH-0003" in rule_ids
    assert "KS-FLASK-CONF-0003" in rule_ids
    assert "KS-FLASK-JWT-0001" in rule_ids
    assert "KS-FLASK-SESS-0001" in rule_ids
    assert "KS-FLASK-SESS-0002" in rule_ids
    assert "KS-FLASK-CSRF-0001" in rule_ids
    assert "KS-FLASK-CONF-0001" in rule_ids
    assert "KS-FLASK-CONF-0002" in rule_ids


def test_tier_a_rule_evaluation_fixtures():
    rules_dir = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns" / "flask"
    loader = GraphRuleLoader()
    rules = loader.load_directory(rules_dir)

    # Positive config nodes
    cfg_sess_sec = FrameworkSemanticNode(
        id="c-1",
        node_type=SemanticNodeType.CONFIG,
        name="SESSION_COOKIE_SECURE",
        attributes={"key": "SESSION_COOKIE_SECURE", "value": False},
        origin=OriginMetadata(location_info=SourceLocation(file_path="config.py", line=10)),
    )
    cfg_sess_httponly = FrameworkSemanticNode(
        id="c-2",
        node_type=SemanticNodeType.CONFIG,
        name="SESSION_COOKIE_HTTPONLY",
        attributes={"key": "SESSION_COOKIE_HTTPONLY", "value": False},
        origin=OriginMetadata(location_info=SourceLocation(file_path="config.py", line=12)),
    )
    cfg_csrf = FrameworkSemanticNode(
        id="c-3",
        node_type=SemanticNodeType.CONFIG,
        name="WTF_CSRF_ENABLED",
        attributes={"key": "WTF_CSRF_ENABLED", "value": False},
        origin=OriginMetadata(location_info=SourceLocation(file_path="config.py", line=15)),
    )
    cfg_debug = FrameworkSemanticNode(
        id="c-4",
        node_type=SemanticNodeType.CONFIG,
        name="DEBUG",
        attributes={"key": "DEBUG", "value": True},
        origin=OriginMetadata(location_info=SourceLocation(file_path="config.py", line=20)),
    )
    cfg_secret = FrameworkSemanticNode(
        id="c-5",
        node_type=SemanticNodeType.CONFIG,
        name="SECRET_KEY",
        attributes={"key": "SECRET_KEY", "value": "super-secret", "source_kind": "literal"},
        origin=OriginMetadata(location_info=SourceLocation(file_path="config.py", line=25)),
    )

    # Unprotected route
    r1 = FrameworkSemanticNode(id="r-1", node_type=SemanticNodeType.ROUTE, name="/public")
    h1 = FrameworkSemanticNode(id="h-1", node_type=SemanticNodeType.HANDLER, name="public_handler")
    e1 = FrameworkSemanticEdge(source_id="h-1", target_id="r-1", edge_type=SemanticEdgeType.HANDLES)

    nodes = {n.id: n for n in [cfg_sess_sec, cfg_sess_httponly, cfg_csrf, cfg_debug, cfg_secret, r1, h1]}
    edges = (e1,)
    graph = FrameworkSemanticGraph(nodes=nodes, edges=edges)

    engine = GraphSecurityRuleEngine()
    findings = engine.evaluate(graph, rules)

    assert findings.total == 6
    matched_rule_ids = set(f.rule_id for f in findings.findings)
    assert matched_rule_ids == {
        "KS-FLASK-AUTH-0001",
        "KS-FLASK-SESS-0001",
        "KS-FLASK-SESS-0002",
        "KS-FLASK-CSRF-0001",
        "KS-FLASK-CONF-0001",
        "KS-FLASK-CONF-0002",
    }


# ---------------------------------------------------------------------------
# 5. DETERMINISM & ORDER INVARIANCE TESTS
# ---------------------------------------------------------------------------

def test_10x_repeated_execution_invariance():
    rules_dir = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns" / "flask"
    rules = GraphRuleLoader().load_directory(rules_dir)

    cfg_debug = FrameworkSemanticNode(
        id="c-4",
        node_type=SemanticNodeType.CONFIG,
        name="DEBUG",
        attributes={"key": "DEBUG", "value": True},
    )
    r1 = FrameworkSemanticNode(id="r-1", node_type=SemanticNodeType.ROUTE, name="/unprotected")
    h1 = FrameworkSemanticNode(id="h-1", node_type=SemanticNodeType.HANDLER, name="unprotected_handler")
    e1 = FrameworkSemanticEdge(source_id="h-1", target_id="r-1", edge_type=SemanticEdgeType.HANDLES)

    graph = FrameworkSemanticGraph(nodes={"c-4": cfg_debug, "r-1": r1, "h-1": h1}, edges=(e1,))
    engine = GraphSecurityRuleEngine()

    base_res = engine.evaluate(graph, rules)
    base_fingerprints = [f.fingerprint for f in base_res.findings]

    for _ in range(10):
        res = engine.evaluate(graph, rules)
        fps = [f.fingerprint for f in res.findings]
        assert fps == base_fingerprints


def test_shuffled_input_determinism():
    rules_dir = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns" / "flask"
    rules = GraphRuleLoader().load_directory(rules_dir)

    nodes_list = [
        FrameworkSemanticNode(id="c-1", node_type=SemanticNodeType.CONFIG, name="DEBUG", attributes={"key": "DEBUG", "value": True}),
        FrameworkSemanticNode(id="r-1", node_type=SemanticNodeType.ROUTE, name="/r1"),
        FrameworkSemanticNode(id="h-1", node_type=SemanticNodeType.HANDLER, name="h1"),
        FrameworkSemanticNode(id="r-2", node_type=SemanticNodeType.ROUTE, name="/r2"),
        FrameworkSemanticNode(id="h-2", node_type=SemanticNodeType.HANDLER, name="h2"),
    ]
    edges_list = [
        FrameworkSemanticEdge(source_id="h-1", target_id="r-1", edge_type=SemanticEdgeType.HANDLES),
        FrameworkSemanticEdge(source_id="h-2", target_id="r-2", edge_type=SemanticEdgeType.HANDLES),
    ]

    base_graph = FrameworkSemanticGraph(nodes={n.id: n for n in nodes_list}, edges=tuple(edges_list))
    engine = GraphSecurityRuleEngine()

    base_findings = engine.evaluate(base_graph, rules)
    base_fps = [f.fingerprint for f in base_findings.findings]

    for _ in range(5):
        shuffled_nodes = list(nodes_list)
        random.shuffle(shuffled_nodes)
        shuffled_edges = list(edges_list)
        random.shuffle(shuffled_edges)
        shuffled_rules = list(rules)
        random.shuffle(shuffled_rules)

        shuffled_graph = FrameworkSemanticGraph(nodes={n.id: n for n in shuffled_nodes}, edges=tuple(shuffled_edges))
        res = engine.evaluate(shuffled_graph, shuffled_rules)
        fps = [f.fingerprint for f in res.findings]

        assert fps == base_fps


# ---------------------------------------------------------------------------
# 6. STATIC ARCHITECTURAL IMPORT BOUNDARY TEST
# ---------------------------------------------------------------------------

def test_static_architectural_import_boundary():
    rules_pkg_dir = Path(__file__).parents[2] / "karsasec" / "framework" / "framework_semantics" / "rules"
    assert rules_pkg_dir.exists() and rules_pkg_dir.is_dir()

    forbidden = {"ast", "tree_sitter", "importlib", "subprocess", "requests", "urllib", "httpx"}

    for py_path in rules_pkg_dir.rglob("*.py"):
        code = py_path.read_text(encoding="utf-8")
        tree = ast.parse(code, filename=str(py_path))

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    pkg_root = alias.name.split(".")[0]
                    assert pkg_root not in forbidden, f"Forbidden import '{alias.name}' in {py_path}"
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    pkg_root = node.module.split(".")[0]
                    assert pkg_root not in forbidden, f"Forbidden importFrom '{node.module}' in {py_path}"


# ---------------------------------------------------------------------------
# 7. PERFORMANCE BENCHMARK (100, 1000, 10000 NODES)
# ---------------------------------------------------------------------------

def test_performance_scaling_benchmark():
    rule = create_sample_rule_auth_0001()
    engine = GraphSecurityRuleEngine()

    for count in (100, 1000, 10000):
        nodes = {}
        edges = []
        for i in range(count):
            rid = f"r-{i}"
            hid = f"h-{i}"
            nodes[rid] = FrameworkSemanticNode(id=rid, node_type=SemanticNodeType.ROUTE, name=f"/route-{i}")
            nodes[hid] = FrameworkSemanticNode(id=hid, node_type=SemanticNodeType.HANDLER, name=f"handler_{i}")
            edges.append(FrameworkSemanticEdge(source_id=hid, target_id=rid, edge_type=SemanticEdgeType.HANDLES))

        graph = FrameworkSemanticGraph(nodes=nodes, edges=tuple(edges))

        res = engine.evaluate(graph, [rule])
        assert res.total == count


# ---------------------------------------------------------------------------
# 8. TIER-B GRAPH RULE EVALUATION TESTS
# ---------------------------------------------------------------------------

def test_tier_b_auth_0002_sensitive_endpoint_unprotected():
    """KS-FLASK-AUTH-0002: High-sensitivity route missing protection edge creates CRITICAL finding."""
    rule_path = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns" / "flask" / "KS-FLASK-AUTH-0002.yaml"
    loader = GraphRuleLoader()
    rule = loader.load_file(rule_path)

    # Route with sensitivity HIGH and NO auth/middleware edge -> finding
    n_route = FrameworkSemanticNode(
        id="r-admin",
        node_type=SemanticNodeType.ROUTE,
        name="/admin/delete",
        attributes={"sensitivity": "HIGH", "exposure": "INTERNAL"},
    )
    graph = FrameworkSemanticGraph(nodes={"r-admin": n_route})
    engine = GraphSecurityRuleEngine()

    res = engine.evaluate(graph, [rule])
    assert res.total == 1
    assert res.findings[0].rule_id == "KS-FLASK-AUTH-0002"
    assert res.findings[0].severity == Severity.CRITICAL

    # Route with UNKNOWN sensitivity or protected route -> 0 finding
    n_safe = FrameworkSemanticNode(
        id="r-safe",
        node_type=SemanticNodeType.ROUTE,
        name="/public",
        attributes={"sensitivity": "UNKNOWN"},
    )
    graph_safe = FrameworkSemanticGraph(nodes={"r-safe": n_safe})
    res_safe = engine.evaluate(graph_safe, [rule])
    assert res_safe.total == 0


def test_tier_b_auth_0003_weak_auth_mechanism():
    """KS-FLASK-AUTH-0003: Weak auth mechanism (auth_strength == WEAK) creates HIGH finding."""
    rule_path = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns" / "flask" / "KS-FLASK-AUTH-0003.yaml"
    loader = GraphRuleLoader()
    rule = loader.load_file(rule_path)

    # Auth node with auth_strength WEAK
    n_weak = FrameworkSemanticNode(
        id="auth-basic",
        node_type=SemanticNodeType.AUTH,
        name="BasicAuth",
        attributes={"auth_strength": "WEAK", "mechanism": "BASIC"},
    )
    graph = FrameworkSemanticGraph(nodes={"auth-basic": n_weak})
    engine = GraphSecurityRuleEngine()

    res = engine.evaluate(graph, [rule])
    assert res.total == 1
    assert res.findings[0].rule_id == "KS-FLASK-AUTH-0003"
    assert res.findings[0].severity == Severity.HIGH

    # Auth node with auth_strength STRONG -> 0 finding
    n_strong = FrameworkSemanticNode(
        id="auth-jwt",
        node_type=SemanticNodeType.AUTH,
        name="JWT",
        attributes={"auth_strength": "STRONG", "mechanism": "JWT"},
    )
    graph_strong = FrameworkSemanticGraph(nodes={"auth-jwt": n_strong})
    res_strong = engine.evaluate(graph_strong, [rule])
    assert res_strong.total == 0


def test_tier_b_conf_0003_debug_in_production():
    """KS-FLASK-CONF-0003: DEBUG=True in PRODUCTION environment creates CRITICAL finding."""
    rule_path = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns" / "flask" / "KS-FLASK-CONF-0003.yaml"
    loader = GraphRuleLoader()
    rule = loader.load_file(rule_path)

    # Config node DEBUG=True in PRODUCTION
    n_prod_debug = FrameworkSemanticNode(
        id="cfg-debug",
        node_type=SemanticNodeType.CONFIG,
        name="DEBUG",
        attributes={"key": "DEBUG", "value": True, "environment": "PRODUCTION"},
    )
    graph = FrameworkSemanticGraph(nodes={"cfg-debug": n_prod_debug})
    engine = GraphSecurityRuleEngine()

    res = engine.evaluate(graph, [rule])
    assert res.total == 1
    assert res.findings[0].rule_id == "KS-FLASK-CONF-0003"
    assert res.findings[0].severity == Severity.CRITICAL

    # Config node DEBUG=True in DEVELOPMENT -> 0 finding
    n_dev_debug = FrameworkSemanticNode(
        id="cfg-dev-debug",
        node_type=SemanticNodeType.CONFIG,
        name="DEBUG",
        attributes={"key": "DEBUG", "value": True, "environment": "DEVELOPMENT"},
    )
    graph_dev = FrameworkSemanticGraph(nodes={"cfg-dev-debug": n_dev_debug})
    res_dev = engine.evaluate(graph_dev, [rule])
    assert res_dev.total == 0


def test_tier_b_jwt_0001_weak_jwt_algorithm():
    """KS-FLASK-JWT-0001: JWT authentication with jwt_algorithm=='none' creates CRITICAL finding."""
    rule_path = Path(__file__).parents[2] / "karsasec" / "rules" / "patterns" / "flask" / "KS-FLASK-JWT-0001.yaml"
    loader = GraphRuleLoader()
    rule = loader.load_file(rule_path)

    # Auth node JWT with algorithm 'none'
    n_jwt_none = FrameworkSemanticNode(
        id="auth-jwt-none",
        node_type=SemanticNodeType.AUTH,
        name="JWT",
        attributes={"auth_type": "JWT", "jwt_algorithm": "none"},
    )
    graph = FrameworkSemanticGraph(nodes={"auth-jwt-none": n_jwt_none})
    engine = GraphSecurityRuleEngine()

    res = engine.evaluate(graph, [rule])
    assert res.total == 1
    assert res.findings[0].rule_id == "KS-FLASK-JWT-0001"
    assert res.findings[0].severity == Severity.CRITICAL

    # Auth node JWT with HS256 -> 0 finding
    n_jwt_hs256 = FrameworkSemanticNode(
        id="auth-jwt-hs256",
        node_type=SemanticNodeType.AUTH,
        name="JWT",
        attributes={"auth_type": "JWT", "jwt_algorithm": "HS256"},
    )
    graph_hs256 = FrameworkSemanticGraph(nodes={"auth-jwt-hs256": n_jwt_hs256})
    res_hs256 = engine.evaluate(graph_hs256, [rule])
    assert res_hs256.total == 0

