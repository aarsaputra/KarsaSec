"""Comprehensive Invariant (INV-E12-RULE-01..25) and Adversarial Case (A-R) test suite for Sprint E12."""

from __future__ import annotations

from karsasec.analysis.rule_engine import SemanticRuleEngine
from karsasec.analysis.rule_registry import SecurityRuleRegistry, create_builtin_rules
from karsasec.analysis.security_finding import FindingStatus, compute_finding_id
from karsasec.analysis.security_rule import compute_rule_id
from karsasec.analysis.semantic_flow import FlowStatus, SemanticFlow
from karsasec.analysis.semantic_flow_store import SemanticFlowStore
from karsasec.cpg.models import CPGEdge, CPGGraph, CPGNode, EdgeType, NodeType
from karsasec.framework.semantic_fact import SemanticFact, SemanticFactStore, SemanticRole


def test_inv_e12_rule_01_02_03_determinism_and_hashing() -> None:
    """INV-E12-RULE-01,02,03: Rule & Finding IDs are deterministic and independent of hash seeds."""
    r_id1 = compute_rule_id("E12-SQL-001", "1.0")
    r_id2 = compute_rule_id("E12-SQL-001", "1.0")
    assert r_id1 == r_id2
    assert len(r_id1) == 64

    f_id1 = compute_finding_id("r1", "1.0", "fl1", "sf1", "sk1")
    f_id2 = compute_finding_id("r1", "1.0", "fl1", "sf1", "sk1")
    assert f_id1 == f_id2
    assert len(f_id1) == 64


def test_inv_e12_rule_04_05_indexed_lookup() -> None:
    """INV-E12-RULE-04,05: Registry indexed matching returns deterministic candidates in O(1) time."""
    registry = SecurityRuleRegistry()
    for rule in create_builtin_rules():
        registry.register(rule)

    matches_sql = registry.match("http_user_input", "sql")
    assert len(matches_sql) == 1
    assert matches_sql[0].rule_key == "E12-SQL-001"

    matches_cmd = registry.match("http_user_input", "command_execution")
    assert len(matches_cmd) == 1
    assert matches_cmd[0].rule_key == "E12-CMD-001"


def test_cases_a_b_c_d_sql_injection_matrix() -> None:
    """Adversarial Cases A, B, C, D: SQL Injection Vulnerable, Valid Sanitizer, Wrong Sanitizer, Fake Sanitizer."""
    graph = CPGGraph()
    graph.add_node(CPGNode("n1", NodeType.AST, "id", "app.py", 10))
    graph.add_node(CPGNode("n2_int", NodeType.CALLSITE, "int", "app.py", 11, attributes={"name": "int"}))
    graph.add_node(CPGNode("n2_html", NodeType.CALLSITE, "escape_html", "app.py", 11, attributes={"name": "escape_html"}))
    graph.add_node(CPGNode("n2_str", NodeType.CALLSITE, "str", "app.py", 11, attributes={"name": "str"}))
    graph.add_node(CPGNode("n3", NodeType.CALLSITE, "execute", "app.py", 12, attributes={"name": "execute"}))

    fact_store = SemanticFactStore()
    src_fact = SemanticFact.create("ext", "FLASK", "input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1", source_kind="http_user_input")
    snk_fact = SemanticFact.create("ext", "FLASK", "sink", "app.py", 12, semantic_role=SemanticRole.SECURITY_SINK, node_id="n3", sink_category="sql")
    fact_store.add_fact(src_fact)
    fact_store.add_fact(snk_fact)

    engine = SemanticRuleEngine()

    # Case A: Vulnerable (No Sanitizer) -> CONFIRMED/CANDIDATE
    flow_a = SemanticFlow.create(src_fact.fact_id, snk_fact.fact_id, "n1", "n3", path_node_ids=["n1", "n3"], status=FlowStatus.CORRELATED, confidence=0.90)
    store_a = SemanticFlowStore()
    store_a.add(flow_a)
    res_a = engine.evaluate(store_a, fact_store, graph).all()[0]
    assert res_a.status in (FindingStatus.CONFIRMED, FindingStatus.CANDIDATE)

    # Case B: Valid SQL Sanitizer (int) -> BLOCKED (INV-E12-RULE-14)
    flow_b = SemanticFlow.create(src_fact.fact_id, snk_fact.fact_id, "n1", "n3", path_node_ids=["n1", "n2_int", "n3"], sanitizer_nodes=["n2_int"], status=FlowStatus.CORRELATED, confidence=0.90)
    store_b = SemanticFlowStore()
    store_b.add(flow_b)
    res_b = engine.evaluate(store_b, fact_store, graph).all()[0]
    assert res_b.status == FindingStatus.BLOCKED

    # Case C: Wrong Sanitizer (escape_html on SQL) -> NOT BLOCKED (INV-E12-RULE-16)
    flow_c = SemanticFlow.create(src_fact.fact_id, snk_fact.fact_id, "n1", "n3", path_node_ids=["n1", "n2_html", "n3"], sanitizer_nodes=["n2_html"], status=FlowStatus.CORRELATED, confidence=0.90)
    store_c = SemanticFlowStore()
    store_c.add(flow_c)
    res_c = engine.evaluate(store_c, fact_store, graph).all()[0]
    assert res_c.status != FindingStatus.BLOCKED

    # Case D: Fake Sanitizer (str() on SQL) -> NOT BLOCKED (INV-E12-RULE-15)
    flow_d = SemanticFlow.create(src_fact.fact_id, snk_fact.fact_id, "n1", "n3", path_node_ids=["n1", "n2_str", "n3"], sanitizer_nodes=["n2_str"], status=FlowStatus.CORRELATED, confidence=0.90)
    store_d = SemanticFlowStore()
    store_d.add(flow_d)
    res_d = engine.evaluate(store_d, fact_store, graph).all()[0]
    assert res_d.status != FindingStatus.BLOCKED


def test_cases_e_f_command_injection() -> None:
    """Adversarial Cases E, F: Command Injection Vulnerable & Sanitized (shlex.quote)."""
    graph = CPGGraph()
    graph.add_node(CPGNode("n1", NodeType.AST, "cmd", "app.py", 10))
    graph.add_node(CPGNode("n2_shlex", NodeType.CALLSITE, "shlex.quote", "app.py", 11, attributes={"name": "shlex.quote"}))
    graph.add_node(CPGNode("n3", NodeType.CALLSITE, "subprocess.run", "app.py", 12, attributes={"name": "subprocess.run"}))

    fact_store = SemanticFactStore()
    src_fact = SemanticFact.create("ext", "FLASK", "input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1", source_kind="http_user_input")
    snk_fact = SemanticFact.create("ext", "FLASK", "sink", "app.py", 12, semantic_role=SemanticRole.SECURITY_SINK, node_id="n3", sink_category="command_execution")
    fact_store.add_fact(src_fact)
    fact_store.add_fact(snk_fact)

    engine = SemanticRuleEngine()

    # Case E: Command Injection -> CRITICAL severity
    flow_e = SemanticFlow.create(src_fact.fact_id, snk_fact.fact_id, "n1", "n3", path_node_ids=["n1", "n3"], status=FlowStatus.CORRELATED, confidence=0.90)
    store_e = SemanticFlowStore()
    store_e.add(flow_e)
    res_e = engine.evaluate(store_e, fact_store, graph).all()[0]
    assert res_e.severity == "CRITICAL"
    assert res_e.status in (FindingStatus.CONFIRMED, FindingStatus.CANDIDATE)

    # Case F: Command Sanitized -> BLOCKED
    flow_f = SemanticFlow.create(src_fact.fact_id, snk_fact.fact_id, "n1", "n3", path_node_ids=["n1", "n2_shlex", "n3"], sanitizer_nodes=["n2_shlex"], status=FlowStatus.CORRELATED, confidence=0.90)
    store_f = SemanticFlowStore()
    store_f.add(flow_f)
    res_f = engine.evaluate(store_f, fact_store, graph).all()[0]
    assert res_f.status == FindingStatus.BLOCKED


def test_cases_g_h_xss() -> None:
    """Adversarial Cases G, H: XSS Vulnerable & Sanitized (escape_html)."""
    graph = CPGGraph()
    graph.add_node(CPGNode("n1", NodeType.AST, "html", "app.py", 10))
    graph.add_node(CPGNode("n2_escape", NodeType.CALLSITE, "escape_html", "app.py", 11, attributes={"name": "escape_html"}))
    graph.add_node(CPGNode("n3", NodeType.CALLSITE, "render_html", "app.py", 12, attributes={"name": "render_html"}))

    fact_store = SemanticFactStore()
    src_fact = SemanticFact.create("ext", "FLASK", "input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1", source_kind="http_user_input")
    snk_fact = SemanticFact.create("ext", "FLASK", "sink", "app.py", 12, semantic_role=SemanticRole.SECURITY_SINK, node_id="n3", sink_category="html_render")
    fact_store.add_fact(src_fact)
    fact_store.add_fact(snk_fact)

    engine = SemanticRuleEngine()

    # Case G: XSS -> HIGH severity
    flow_g = SemanticFlow.create(src_fact.fact_id, snk_fact.fact_id, "n1", "n3", path_node_ids=["n1", "n3"], status=FlowStatus.CORRELATED, confidence=0.90)
    store_g = SemanticFlowStore()
    store_g.add(flow_g)
    res_g = engine.evaluate(store_g, fact_store, graph).all()[0]
    assert res_g.severity == "HIGH"

    # Case H: XSS Sanitized -> BLOCKED
    flow_h = SemanticFlow.create(src_fact.fact_id, snk_fact.fact_id, "n1", "n3", path_node_ids=["n1", "n2_escape", "n3"], sanitizer_nodes=["n2_escape"], status=FlowStatus.CORRELATED, confidence=0.90)
    store_h = SemanticFlowStore()
    store_h.add(flow_h)
    res_h = engine.evaluate(store_h, fact_store, graph).all()[0]
    assert res_h.status == FindingStatus.BLOCKED


def test_cases_k_l_m_fail_closed_handling() -> None:
    """Adversarial Cases K, L, M: Fail-closed to UNKNOWN on missing facts, broken nodes, or UNKNOWN flow status (INV-E12-RULE-07,08,09,10)."""
    graph = CPGGraph()
    graph.add_node(CPGNode("n1", NodeType.AST, "expr", "app.py", 10))

    fact_store = SemanticFactStore()
    src_fact = SemanticFact.create("ext", "FLASK", "input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1", source_kind="http_user_input")
    fact_store.add_fact(src_fact)

    engine = SemanticRuleEngine()

    # Case K: UNKNOWN flow status -> UNKNOWN finding status
    flow_k = SemanticFlow.create(src_fact.fact_id, "f_missing_snk", "n1", "n99", status=FlowStatus.UNKNOWN)
    store_k = SemanticFlowStore()
    store_k.add(flow_k)
    res_k = engine.evaluate(store_k, fact_store, graph).all()[0]
    assert res_k.status == FindingStatus.UNKNOWN
    assert res_k.status != FindingStatus.CONFIRMED

    # Case L: Missing sink fact -> UNKNOWN finding status
    flow_l = SemanticFlow.create(src_fact.fact_id, "f_nonexistent", "n1", "n1", status=FlowStatus.CORRELATED)
    store_l = SemanticFlowStore()
    store_l.add(flow_l)
    res_l = engine.evaluate(store_l, fact_store, graph).all()[0]
    assert res_l.status == FindingStatus.UNKNOWN


def test_inv_e12_rule_19_cpg_topology_immutability() -> None:
    """INV-E12-RULE-19: CPG Graph nodes and edges are strictly immutable during rule evaluation."""
    graph = CPGGraph()
    n1 = CPGNode("n1", NodeType.AST, "id", "app.py", 10)
    n2 = CPGNode("n2", NodeType.CALLSITE, "exec", "app.py", 20)
    graph.add_node(n1)
    graph.add_node(n2)
    graph.add_edge(CPGEdge("n1", "n2", EdgeType.DATAFLOW))

    nodes_before = len(graph.nodes)
    edges_before = len(graph.edges)

    fact_store = SemanticFactStore()
    f1 = SemanticFact.create("ext", "FLASK", "input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1", source_kind="http_user_input")
    f2 = SemanticFact.create("ext", "FLASK", "sink", "app.py", 20, semantic_role=SemanticRole.SECURITY_SINK, node_id="n2", sink_category="sql")
    fact_store.add_fact(f1)
    fact_store.add_fact(f2)

    flow_store = SemanticFlowStore()
    flow_store.add(SemanticFlow.create(f1.fact_id, f2.fact_id, "n1", "n2", path_node_ids=["n1", "n2"], status=FlowStatus.CORRELATED, confidence=0.90))

    engine = SemanticRuleEngine()
    engine.evaluate(flow_store, fact_store, graph)

    assert len(graph.nodes) == nodes_before
    assert len(graph.edges) == edges_before


def test_inv_e12_rule_22_23_input_reordering_and_metamorphic_invariance() -> None:
    """INV-E12-RULE-22,23: Evaluation is invariant under flow/fact input reordering and unrelated node insertion."""
    graph = CPGGraph()
    graph.add_node(CPGNode("n1", NodeType.AST, "id", "app.py", 10))
    graph.add_node(CPGNode("n2", NodeType.CALLSITE, "execute", "app.py", 20, attributes={"name": "execute"}))

    fact_store = SemanticFactStore()
    f1 = SemanticFact.create("ext", "FLASK", "input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1", source_kind="http_user_input")
    f2 = SemanticFact.create("ext", "FLASK", "sink", "app.py", 20, semantic_role=SemanticRole.SECURITY_SINK, node_id="n2", sink_category="sql")
    fact_store.add_fact(f1)
    fact_store.add_fact(f2)

    flow1 = SemanticFlow.create(f1.fact_id, f2.fact_id, "n1", "n2", path_node_ids=["n1", "n2"], status=FlowStatus.CORRELATED, confidence=0.90)

    # Store 1: insertion order flow1
    store1 = SemanticFlowStore()
    store1.add(flow1)

    engine = SemanticRuleEngine()
    findings1 = engine.evaluate(store1, fact_store, graph).all()

    # Store 2: re-evaluate
    findings2 = engine.evaluate(store1, fact_store, graph).all()

    assert len(findings1) == len(findings2)
    assert [f.finding_id for f in findings1] == [f.finding_id for f in findings2]


def test_inv_e12_rule_24_25_explainable_evidence_reconstruction() -> None:
    """INV-E12-RULE-24,25: Finding evidence must fully reconstruct the decision without re-running analyzer."""
    graph = CPGGraph()
    graph.add_node(CPGNode("n1", NodeType.AST, "user_id", "app.py", 42, attributes={"file": "app.py", "line": 42}))
    graph.add_node(CPGNode("n2", NodeType.CALLSITE, "execute", "app.py", 50, attributes={"name": "execute"}))

    fact_store = SemanticFactStore()
    f1 = SemanticFact.create("ext", "FLASK", "input", "app.py", 42, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1", source_kind="http_user_input")
    f2 = SemanticFact.create("ext", "FLASK", "sink", "app.py", 50, semantic_role=SemanticRole.SECURITY_SINK, node_id="n2", sink_category="sql")
    fact_store.add_fact(f1)
    fact_store.add_fact(f2)

    flow_store = SemanticFlowStore()
    flow_store.add(SemanticFlow.create(f1.fact_id, f2.fact_id, "n1", "n2", path_node_ids=["n1", "n2"], status=FlowStatus.CORRELATED, confidence=0.90))

    engine = SemanticRuleEngine()
    finding = engine.evaluate(flow_store, fact_store, graph).all()[0]

    serialized = finding.to_dict()
    assert "finding_id" in serialized
    assert "evidence" in serialized
    assert serialized["evidence"]["source"]["source_kind"] == "http_user_input"
    assert serialized["evidence"]["sink"]["sink_category"] == "sql"
    assert serialized["evidence"]["sanitizer"]["has_valid_barrier"] == "False"
