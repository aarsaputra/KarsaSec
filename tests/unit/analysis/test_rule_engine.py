"""Unit tests for SemanticRuleEngine rule matching, barrier matrix, and decision logic."""

from karsasec.analysis.rule_engine import SemanticRuleEngine
from karsasec.analysis.security_finding import FindingStatus
from karsasec.analysis.semantic_flow import FlowStatus, SemanticFlow
from karsasec.analysis.semantic_flow_store import SemanticFlowStore
from karsasec.cpg.models import CPGGraph, CPGNode, NodeType
from karsasec.framework.semantic_fact import SemanticFact, SemanticFactStore, SemanticRole


def test_rule_engine_basic_sql_injection() -> None:
    """Verifies that an un-sanitized HTTP to SQL flow produces a CONFIRMED/CANDIDATE finding."""
    graph = CPGGraph()
    graph.add_node(CPGNode("n1", NodeType.AST, "user_id", "app.py", 10, attributes={"file": "app.py", "line": 10, "name": "user_id"}))
    graph.add_node(CPGNode("n2", NodeType.CALLSITE, "execute", "app.py", 20, attributes={"name": "execute"}))

    fact_store = SemanticFactStore()
    src_fact = SemanticFact.create("ext", "FLASK", "input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1", source_kind="http_user_input")
    snk_fact = SemanticFact.create("ext", "FLASK", "sink", "app.py", 20, semantic_role=SemanticRole.SECURITY_SINK, node_id="n2", sink_category="sql")
    fact_store.add_fact(src_fact)
    fact_store.add_fact(snk_fact)

    flow_store = SemanticFlowStore()
    flow = SemanticFlow.create(
        source_fact_id=src_fact.fact_id,
        sink_fact_id=snk_fact.fact_id,
        source_node_id="n1",
        sink_node_id="n2",
        path_node_ids=["n1", "n2"],
        confidence=0.90,
        status=FlowStatus.CORRELATED,
    )
    flow_store.add(flow)

    engine = SemanticRuleEngine()
    finding_store = engine.evaluate(flow_store, fact_store, graph)

    assert finding_store.count() == 1
    finding = finding_store.all()[0]
    assert finding.rule_key == "E12-SQL-001"
    assert finding.severity == "HIGH"
    assert finding.status in (FindingStatus.CONFIRMED, FindingStatus.CANDIDATE)


def test_rule_engine_sql_valid_sanitizer() -> None:
    """Verifies that int() sanitizer blocks SQL injection finding (BLOCKED)."""
    graph = CPGGraph()
    graph.add_node(CPGNode("n1", NodeType.AST, "user_id", "app.py", 10))
    graph.add_node(CPGNode("n2", NodeType.CALLSITE, "int", "app.py", 15, attributes={"name": "int"}))
    graph.add_node(CPGNode("n3", NodeType.CALLSITE, "execute", "app.py", 20, attributes={"name": "execute"}))

    fact_store = SemanticFactStore()
    src_fact = SemanticFact.create("ext", "FLASK", "input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1", source_kind="http_user_input")
    snk_fact = SemanticFact.create("ext", "FLASK", "sink", "app.py", 20, semantic_role=SemanticRole.SECURITY_SINK, node_id="n3", sink_category="sql")
    fact_store.add_fact(src_fact)
    fact_store.add_fact(snk_fact)

    flow_store = SemanticFlowStore()
    flow = SemanticFlow.create(
        source_fact_id=src_fact.fact_id,
        sink_fact_id=snk_fact.fact_id,
        source_node_id="n1",
        sink_node_id="n3",
        path_node_ids=["n1", "n2", "n3"],
        sanitizer_nodes=["n2"],
        confidence=0.90,
        status=FlowStatus.CORRELATED,
    )
    flow_store.add(flow)

    engine = SemanticRuleEngine()
    finding_store = engine.evaluate(flow_store, fact_store, graph)

    assert finding_store.count() == 1
    finding = finding_store.all()[0]
    assert finding.status == FindingStatus.BLOCKED
