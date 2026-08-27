"""End-to-End integration test suite connecting E9 (CPG) -> E10 (Facts) -> E11 (Flow) -> E12 (Findings) -> E13 (Clusters) -> E14 (Priority, Remediation, Regression)."""

from __future__ import annotations

from karsasec.analysis.finding_correlator import FindingCorrelator
from karsasec.analysis.regression_engine import RegressionEngine
from karsasec.analysis.remediation_engine import RemediationEngine
from karsasec.analysis.remediation_pattern import RemediationStatus
from karsasec.analysis.rule_engine import SemanticRuleEngine
from karsasec.analysis.semantic_correlator import SemanticCorrelator
from karsasec.analysis.vulnerability_prioritizer import VulnerabilityPrioritizer
from karsasec.analysis.vulnerability_priority import PriorityStatus
from karsasec.cpg.models import CPGEdge, CPGGraph, CPGNode, EdgeType, NodeType
from karsasec.framework.semantic_fact import SemanticFact, SemanticFactStore, SemanticRole
from karsasec.query.optimizer import QueryOptimizer
from karsasec.query.traversal_engine import MultiHopTraversalEngine


def test_full_e9_to_e14_pipeline_integration() -> None:
    """Verifies end-to-end operational execution across all pipeline stages E9 -> E14."""
    # 1. E9 CPG Graph
    graph = CPGGraph()
    graph.add_node(CPGNode("n_src", NodeType.AST, "request.args['id']", "app.py", 10))
    graph.add_node(CPGNode("n_snk", NodeType.CALLSITE, "db.execute(query)", "app.py", 20))
    graph.add_edge(CPGEdge("n_src", "n_snk", EdgeType.DATAFLOW))

    # 2. E10 Semantic Fact Store
    fact_store = SemanticFactStore()
    fact_src = SemanticFact.create("input", "FLASK", "req_input", "app.py", 10, semantic_role=SemanticRole.HTTP_INPUT, node_id="n_src", source_kind="http_user_input")
    fact_snk = SemanticFact.create("sink", "FLASK", "execute", "app.py", 20, semantic_role=SemanticRole.SECURITY_SINK, node_id="n_snk", sink_category="sql")
    fact_store.add_fact(fact_src, graph)
    fact_store.add_fact(fact_snk, graph)

    # 3. E11 Semantic Flow
    correlator = SemanticCorrelator()
    flow_store = correlator.correlate(graph, fact_store, QueryOptimizer(), MultiHopTraversalEngine(graph))
    assert flow_store.count() >= 1

    # 4. E12 Security Finding Engine
    rule_engine = SemanticRuleEngine()
    finding_store = rule_engine.evaluate(flow_store, fact_store, graph)
    assert finding_store.count() >= 1
    findings = finding_store.all()

    # 5. E13 Vulnerability Cluster & Correlation
    finding_correlator = FindingCorrelator()
    clusters = finding_correlator.correlate(findings)
    assert len(clusters) == 1
    cluster = clusters[0]

    # 6. E14 Priority Assessment
    prioritizer = VulnerabilityPrioritizer()
    priority = prioritizer.prioritize(cluster, findings=findings)
    assert priority.priority_status in (PriorityStatus.HIGH, PriorityStatus.CRITICAL)

    # 7. E14 Remediation Intelligence
    rem_engine = RemediationEngine()
    plan = rem_engine.generate(cluster, priority=priority)
    assert plan.status in (RemediationStatus.REQUIRED, RemediationStatus.RECOMMENDED)
    assert plan.primary_fix == "parameterized_query"

    # 8. E14 Regression Engine
    reg_engine = RegressionEngine()
    report = reg_engine.compare(baseline_clusters=[cluster], current_clusters=[cluster])
    assert len(report.persistent_fingerprints) == 1
    assert report.regressions_detected is False
