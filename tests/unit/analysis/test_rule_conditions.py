"""Unit tests for AST-less declarative RuleConditions (INV-E12-RULE-06)."""

from karsasec.analysis.rule_condition import (
    SanitizerAbsentCondition,
    SinkCategoryCondition,
    SourceKindCondition,
)
from karsasec.analysis.semantic_flow import SemanticFlow
from karsasec.cpg.models import CPGGraph, CPGNode, NodeType
from karsasec.framework.semantic_fact import SemanticFact, SemanticRole


def test_source_sink_condition_evaluation() -> None:
    """Tests SourceKindCondition and SinkCategoryCondition evaluation."""
    source_cond = SourceKindCondition(["http_user_input"])
    sink_cond = SinkCategoryCondition(["sql"])

    src_fact = SemanticFact.create(
        "ext", "FLASK", "input", "app.py", 10,
        semantic_role=SemanticRole.HTTP_INPUT,
        node_id="n1",
        source_kind="http_user_input",
    )
    snk_fact = SemanticFact.create(
        "ext", "FLASK", "sink", "db.py", 20,
        semantic_role=SemanticRole.SECURITY_SINK,
        node_id="n3",
        sink_category="sql",
    )
    flow = SemanticFlow.create(
        source_fact_id=src_fact.fact_id,
        sink_fact_id=snk_fact.fact_id,
        source_node_id="n1",
        sink_node_id="n3",
    )
    graph = CPGGraph()

    res_src = source_cond.evaluate(flow, src_fact, snk_fact, graph)
    res_snk = sink_cond.evaluate(flow, src_fact, snk_fact, graph)

    assert res_src.matched is True
    assert res_snk.matched is True


def test_sanitizer_absent_condition() -> None:
    """Tests SanitizerAbsentCondition logic."""
    cond = SanitizerAbsentCondition(["sanitize_sql"])

    graph = CPGGraph()
    graph.add_node(CPGNode("n1", NodeType.AST, "id", "app.py", 1))
    graph.add_node(CPGNode("n2", NodeType.CALLSITE, "escape_html", "app.py", 2, attributes={"name": "escape_html"}))
    graph.add_node(CPGNode("n3", NodeType.CALLSITE, "sanitize_sql", "app.py", 3, attributes={"name": "sanitize_sql"}))

    src_fact = SemanticFact.create("ext", "FLASK", "input", "app.py", 1, semantic_role=SemanticRole.HTTP_INPUT, node_id="n1", source_kind="http_user_input")
    snk_fact = SemanticFact.create("ext", "FLASK", "sink", "app.py", 3, semantic_role=SemanticRole.SECURITY_SINK, node_id="n3", sink_category="sql")

    flow1 = SemanticFlow.create(
        source_fact_id=src_fact.fact_id,
        sink_fact_id=snk_fact.fact_id,
        source_node_id="n1",
        sink_node_id="n2",
        sanitizer_nodes=["n2"],
    )
    flow2 = SemanticFlow.create(
        source_fact_id=src_fact.fact_id,
        sink_fact_id=snk_fact.fact_id,
        source_node_id="n1",
        sink_node_id="n3",
        sanitizer_nodes=["n3"],
    )

    assert cond.evaluate(flow1, src_fact, snk_fact, graph).matched is True
    assert cond.evaluate(flow2, src_fact, snk_fact, graph).matched is False
