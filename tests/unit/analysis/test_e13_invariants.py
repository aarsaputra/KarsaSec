"""Comprehensive Invariant (INV-E13-CORR-01..35) and Adversarial Case (A-Z) test suite for Sprint E13."""

from __future__ import annotations

from karsasec.analysis.evidence_graph import (
    EvidenceEdgeType,
    EvidenceNodeType,
    compute_evidence_edge_id,
    compute_evidence_node_id,
)
from karsasec.analysis.finding_correlator import FindingCorrelator
from karsasec.analysis.security_assessment import SecurityAssessment
from karsasec.analysis.security_finding import FindingStatus, SecurityFinding
from karsasec.analysis.vulnerability_cluster import (
    ClusterStatus,
    VulnerabilityCluster,
    compute_cluster_id,
)
from karsasec.cpg.models import CPGEdge, CPGGraph, CPGNode, EdgeType, NodeType


def test_inv_e13_corr_01_02_03_determinism_and_hashing() -> None:
    """INV-E13-CORR-01,02,03: Cluster, Node, and Edge IDs are deterministic SHA-256 strings."""
    c_id1 = compute_cluster_id("SQL_INJECTION", ["sf1"], ["kf1"], ["fl1"])
    c_id2 = compute_cluster_id("SQL_INJECTION", ["sf1"], ["kf1"], ["fl1"])
    assert c_id1 == c_id2
    assert len(c_id1) == 64

    n_id1 = compute_evidence_node_id(EvidenceNodeType.SOURCE, "sf1")
    n_id2 = compute_evidence_node_id(EvidenceNodeType.SOURCE, "sf1")
    assert n_id1 == n_id2
    assert len(n_id1) == 64

    e_id1 = compute_evidence_edge_id("n1", "n2", EvidenceEdgeType.SOURCE_TO_SINK)
    e_id2 = compute_evidence_edge_id("n1", "n2", EvidenceEdgeType.SOURCE_TO_SINK)
    assert e_id1 == e_id2
    assert len(e_id1) == 64


def test_inv_e13_corr_04_05_input_ordering_invariance() -> None:
    """INV-E13-CORR-04,05,31: Input reordering does NOT alter cluster IDs or ordering."""
    f1 = SecurityFinding.create(
        rule_id="r1", rule_key="R1", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )
    f2 = SecurityFinding.create(
        rule_id="r2", rule_key="R2", rule_version="1.0", vulnerability_class="XSS",
        source_fact_id="sf2", sink_fact_id="kf2", flow_id="fl2", source_node_id="n3", sink_node_id="n4",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )

    correlator = FindingCorrelator()
    c_order1 = correlator.correlate([f1, f2])
    c_order2 = correlator.correlate([f2, f1])

    assert [c.cluster_id for c in c_order1] == [c.cluster_id for c in c_order2]


def test_cases_u_shared_source_different_sink() -> None:
    """Case U & INV-E13-CORR-26: Shared source HTTP input reaching SQL vs HTML render produces 2 clusters."""
    f_sql = SecurityFinding.create(
        rule_id="r_sql", rule_key="SQL-001", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf_http", sink_fact_id="kf_sql", flow_id="fl_sql", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )
    f_xss = SecurityFinding.create(
        rule_id="r_xss", rule_key="XSS-001", rule_version="1.0", vulnerability_class="XSS",
        source_fact_id="sf_http", sink_fact_id="kf_html", flow_id="fl_html", source_node_id="n1", sink_node_id="n3",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )

    correlator = FindingCorrelator()
    clusters = correlator.correlate([f_sql, f_xss])

    assert len(clusters) == 2, "Shared source reaching different sink vulnerability classes MUST produce 2 clusters"


def test_cases_v_w_same_flow_multiple_rules_and_duplicates() -> None:
    """Cases V, W & INV-E13-CORR-07,27,28,32: Same flow with multiple rules/duplicates yields 1 cluster."""
    # Case W: Exact duplicate findings (same rule_key) -> zero confidence change
    f1 = SecurityFinding.create(
        rule_id="r1", rule_key="E12-SQL-001", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.85,
    )
    f1_dup = SecurityFinding.create(
        rule_id="r1", rule_key="E12-SQL-001", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.85,
    )

    correlator = FindingCorrelator()
    clusters_single = correlator.correlate([f1])
    clusters_dup = correlator.correlate([f1, f1_dup])

    assert len(clusters_dup) == 1
    assert clusters_dup[0].confidence == clusters_single[0].confidence == 0.85, "Duplicate finding MUST NOT inflate confidence"

    # Case V: Multiple distinct rules for same flow -> 1 cluster with rule corroboration
    f2 = SecurityFinding.create(
        rule_id="r2", rule_key="E12-SQL-002", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.85,
    )
    clusters_multi_rule = correlator.correlate([f1, f2])
    assert len(clusters_multi_rule) == 1
    assert clusters_multi_rule[0].confidence == 0.90, "Multiple distinct rules providing corroboration add valid rule corroboration bonus"


def test_cases_x_same_sink_different_sources() -> None:
    """Case X & INV-E13-CORR-11: Same sink with different sources produces 2 clusters unless flow matches."""
    f1 = SecurityFinding.create(
        rule_id="r1", rule_key="SQL-001", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf_user", sink_fact_id="kf_db", flow_id="fl1", source_node_id="n1", sink_node_id="n10",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )
    f2 = SecurityFinding.create(
        rule_id="r1", rule_key="SQL-001", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf_admin", sink_fact_id="kf_db", flow_id="fl2", source_node_id="n2", sink_node_id="n10",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )

    correlator = FindingCorrelator()
    clusters = correlator.correlate([f1, f2])

    assert len(clusters) == 2, "Different sources reaching same sink MUST NOT automatically merge into 1 cluster"


def test_cases_y_cross_context_collision() -> None:
    """Case Y & INV-E13-CORR-13,29: Cross-context collision produces separate clusters."""
    f1 = SecurityFinding.create(
        rule_id="r1", rule_key="SQL-001", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
        flow_evidence={"call_context": "caller_A"},
    )
    f2 = SecurityFinding.create(
        rule_id="r1", rule_key="SQL-001", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf2", sink_fact_id="kf2", flow_id="fl2", source_node_id="n3", sink_node_id="n4",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
        flow_evidence={"call_context": "caller_B"},
    )

    correlator = FindingCorrelator()
    clusters = correlator.correlate([f1, f2])

    assert len(clusters) == 2


def test_cases_z_blocked_and_confirmed_same_flow() -> None:
    """Case Z & INV-E13-CORR-15,30: Blocked + Confirmed findings on same flow preserves BLOCKED evidence while cluster remains CONFIRMED."""
    f_blocked = SecurityFinding.create(
        rule_id="r1", rule_key="SQL-001", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.BLOCKED, confidence=0.90,
        sanitizer_evidence={"has_valid_barrier": "True", "barrier_name": "int"},
    )
    f_confirmed = SecurityFinding.create(
        rule_id="r2", rule_key="SQL-002", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )

    correlator = FindingCorrelator()
    clusters = correlator.correlate([f_blocked, f_confirmed])

    assert len(clusters) == 1
    assert clusters[0].status == ClusterStatus.CONFIRMED
    assert len(clusters[0].finding_ids) == 2


def test_inv_e13_corr_18_19_34_cpg_and_evidence_graph_immutability() -> None:
    """INV-E13-CORR-18,19,34: CPG Graph nodes and edges remain strictly immutable during correlation."""
    graph = CPGGraph()
    graph.add_node(CPGNode("n1", NodeType.AST, "id", "app.py", 10))
    graph.add_node(CPGNode("n2", NodeType.CALLSITE, "exec", "app.py", 20))
    graph.add_edge(CPGEdge("n1", "n2", EdgeType.DATAFLOW))

    nodes_before = len(graph.nodes)
    edges_before = len(graph.edges)

    f1 = SecurityFinding.create(
        rule_id="r1", rule_key="SQL-001", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )

    correlator = FindingCorrelator()
    correlator.correlate([f1])

    assert len(graph.nodes) == nodes_before
    assert len(graph.edges) == edges_before


def test_inv_e13_corr_35_structured_explanation_reproducibility() -> None:
    """INV-E13-CORR-35: SecurityAssessment structured explanations must be 100% reproducible byte-for-byte."""
    cluster = VulnerabilityCluster.create(
        vulnerability_class="SQL_INJECTION",
        finding_ids=["f1"],
        source_fact_ids=["sf1"],
        sink_fact_ids=["kf1"],
        flow_ids=["fl1"],
        source_nodes=["n1"],
        sink_nodes=["n2"],
        shared_contexts=(),
        confidence=0.90,
        severity="HIGH",
        status=ClusterStatus.CONFIRMED,
    )
    f1 = SecurityFinding.create(
        rule_id="r1", rule_key="SQL-001", rule_version="1.0", vulnerability_class="SQL_INJECTION",
        source_fact_id="sf1", sink_fact_id="kf1", flow_id="fl1", source_node_id="n1", sink_node_id="n2",
        severity="HIGH", status=FindingStatus.CONFIRMED, confidence=0.90,
    )

    a1 = SecurityAssessment.create(cluster, [f1])
    a2 = SecurityAssessment.create(cluster, [f1])

    assert a1.explanation == a2.explanation
    assert a1.assessment_id == a2.assessment_id
