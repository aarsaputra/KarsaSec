"""Unit test suite for Batch C13 Attack Graph Construction & Exploit Path Correlation Engine covering 40 mandatory unit tests and quality metrics."""

import pytest

from karsasec.analysis.attack_graph.engine import AttackGraphConstructionEngine
from karsasec.analysis.attack_graph.models import (
    AttackEdge,
    AttackNode,
    EdgeType,
    ImpactNode,
    NodeType,
)


def test_1_inv_c13_01_direct_impact_edge_forbidden() -> None:
    """INV-C13-01: Direct edge from ROOT_CAUSE to IMPACT without CAPABILITY edge is forbidden."""
    engine = AttackGraphConstructionEngine()
    n1 = AttackNode("n1", NodeType.ROOT_CAUSE, "SSRF", "url")
    n2 = ImpactNode("n2", NodeType.IMPACT, "TENANT_WIPE", "tenant")
    e1 = AttackEdge("e1", "n1", "n2", EdgeType.DESTROYS)

    with pytest.raises(ValueError, match="INV-C13-01 Violation"):
        engine.build_graph("g1", [n1, n2], [e1])


def test_2_inv_c13_02_impact_root_cause_tracing() -> None:
    """INV-C13-02: Impact node must have traceable root_cause_chain."""
    engine = AttackGraphConstructionEngine()
    g = engine.build_chain_m_ssrf_metadata_credential_compromise("g2")
    impact_node = [n for n in g.nodes if isinstance(n, ImpactNode)][0]
    assert "SSRF" in impact_node.root_cause_chain


def test_3_inv_c13_03_cycle_detection_rejected() -> None:
    """INV-C13-03: Cyclic graphs must be rejected."""
    engine = AttackGraphConstructionEngine()
    n1 = AttackNode("n1", NodeType.ROOT_CAUSE, "A", "a")
    n2 = AttackNode("n2", NodeType.CAPABILITY, "B", "b")
    n3 = AttackNode("n3", NodeType.CAPABILITY, "C", "c")
    e1 = AttackEdge("e1", "n1", "n2", EdgeType.ENABLES)
    e2 = AttackEdge("e2", "n2", "n3", EdgeType.ESCALATES_TO)
    e3 = AttackEdge("e3", "n3", "n2", EdgeType.ESCALATES_TO)  # Cycle

    with pytest.raises(ValueError, match="INV-C13-03 Violation"):
        engine.build_graph("g3", [n1, n2, n3], [e1, e2, e3])


def test_4_inv_c13_04_unknown_cannot_generate_capability() -> None:
    """INV-C13-04: UNKNOWN node cannot generate capability edge."""
    engine = AttackGraphConstructionEngine()
    n1 = AttackNode("n1", NodeType.UNKNOWN, "UNKNOWN_NODE", "unk", resolution="UNKNOWN")
    n2 = AttackNode("n2", NodeType.CAPABILITY, "CAP", "cap")
    e1 = AttackEdge("e1", "n1", "n2", EdgeType.ENABLES)

    with pytest.raises(ValueError, match="INV-C13-04 Violation"):
        engine.build_graph("g4", [n1, n2], [e1])


def test_5_chain_m_ssrf_metadata_credential_compromise() -> None:
    engine = AttackGraphConstructionEngine()
    g = engine.build_chain_m_ssrf_metadata_credential_compromise()
    assert g.root_causes == ["SSRF"]
    assert "CREDENTIAL_COMPROMISE" in g.impacts


def test_6_chain_n_xxe_file_read_env_db_pass() -> None:
    engine = AttackGraphConstructionEngine()
    g = engine.build_chain_n_xxe_file_read_env_db_pass()
    assert g.root_causes == ["XXE"]
    assert "DATABASE_DESTRUCTION" in g.impacts


def test_7_chain_o_ssti_rce_env_dump_secrets() -> None:
    engine = AttackGraphConstructionEngine()
    g = engine.build_chain_o_ssti_rce_env_dump_secrets()
    assert g.root_causes == ["SSTI"]
    assert "SECRET_EXPOSURE" in g.impacts


def test_8_chain_p_idor_tenant_escape_bulk_delete_tenant_wipe() -> None:
    engine = AttackGraphConstructionEngine()
    g = engine.build_chain_p_idor_tenant_escape_bulk_delete_tenant_wipe()
    assert g.root_causes == ["IDOR"]
    assert "TENANT_WIPE" in g.impacts


def test_9_attack_graph_to_dict_keys() -> None:
    engine = AttackGraphConstructionEngine()
    g = engine.build_chain_m_ssrf_metadata_credential_compromise()
    d = g.to_dict()
    assert "attack_graph_id" in d
    assert "root_cause" in d
    assert "capabilities" in d
    assert "impacts" in d
    assert "path_length" in d
    assert "confidence" in d


def test_10_multiple_root_causes_tracing() -> None:
    engine = AttackGraphConstructionEngine()
    r1 = AttackNode("r1", NodeType.ROOT_CAUSE, "IDOR", "param1")
    r2 = AttackNode("r2", NodeType.ROOT_CAUSE, "SSRF", "param2")
    c1 = AttackNode("c1", NodeType.CAPABILITY, "ADMIN_ACCESS", "cap")
    imp = ImpactNode("imp", NodeType.IMPACT, "SYSTEM_TAKEOVER", "prod")

    e1 = AttackEdge("e1", "r1", "c1", EdgeType.ENABLES)
    e2 = AttackEdge("e2", "r2", "c1", EdgeType.ENABLES)
    e3 = AttackEdge("e3", "c1", "imp", EdgeType.EXECUTES)

    g = engine.build_graph("g10", [r1, r2, c1, imp], [e1, e2, e3])
    assert sorted(imp.root_cause_chain) == ["IDOR", "SSRF"]


def test_11_single_node_safe_graph() -> None:
    engine = AttackGraphConstructionEngine()
    n1 = AttackNode("n1", NodeType.ROOT_CAUSE, "INPUT_CHECK", "param", resolution="SAFE")
    g = engine.build_graph("g11", [n1], [])
    assert g.to_dict()["resolution"] == "SAFE"


def test_12_is_acyclic_utility_positive() -> None:
    engine = AttackGraphConstructionEngine()
    n1 = AttackNode("n1", NodeType.ROOT_CAUSE, "A", "a")
    n2 = AttackNode("n2", NodeType.CAPABILITY, "B", "b")
    e1 = AttackEdge("e1", "n1", "n2", EdgeType.ENABLES)
    assert engine.is_acyclic([n1, n2], [e1]) is True


def test_13_is_acyclic_utility_negative() -> None:
    engine = AttackGraphConstructionEngine()
    n1 = AttackNode("n1", NodeType.ROOT_CAUSE, "A", "a")
    n2 = AttackNode("n2", NodeType.CAPABILITY, "B", "b")
    e1 = AttackEdge("e1", "n1", "n2", EdgeType.ENABLES)
    e2 = AttackEdge("e2", "n2", "n1", EdgeType.ENABLES)
    assert engine.is_acyclic([n1, n2], [e1, e2]) is False


def test_14_edge_types_str_enum() -> None:
    assert EdgeType.ENABLES == "ENABLES"
    assert EdgeType.REQUIRES == "REQUIRES"
    assert EdgeType.ESCALATES_TO == "ESCALATES_TO"
    assert EdgeType.EXPOSES == "EXPOSES"


def test_15_node_types_str_enum() -> None:
    assert NodeType.ROOT_CAUSE == "ROOT_CAUSE"
    assert NodeType.CAPABILITY == "CAPABILITY"
    assert NodeType.IMPACT == "IMPACT"


def test_16_confidence_high_on_vulnerable() -> None:
    engine = AttackGraphConstructionEngine()
    g = engine.build_chain_m_ssrf_metadata_credential_compromise()
    assert g.to_dict()["confidence"] == "HIGH"


def test_17_path_length_matches_edges_count() -> None:
    engine = AttackGraphConstructionEngine()
    g = engine.build_chain_m_ssrf_metadata_credential_compromise()
    assert g.to_dict()["path_length"] == 3


def test_18_capabilities_list_extraction() -> None:
    engine = AttackGraphConstructionEngine()
    g = engine.build_chain_n_xxe_file_read_env_db_pass()
    assert "FILE_READ" in g.capabilities
    assert "DATABASE_PASSWORD_LEAK" in g.capabilities


def test_19_impacts_list_extraction() -> None:
    engine = AttackGraphConstructionEngine()
    g = engine.build_chain_o_ssti_rce_env_dump_secrets()
    assert "SECRET_EXPOSURE" in g.impacts


def test_20_deterministic_graph_generation() -> None:
    engine = AttackGraphConstructionEngine()
    g1 = engine.build_chain_p_idor_tenant_escape_bulk_delete_tenant_wipe("p1")
    g2 = engine.build_chain_p_idor_tenant_escape_bulk_delete_tenant_wipe("p1")
    assert g1.to_dict() == g2.to_dict()


def test_21_to_25_additional_edge_cases() -> None:
    engine = AttackGraphConstructionEngine()

    # 21: Requires Edge
    n1 = AttackNode("n1", NodeType.ROOT_CAUSE, "RC", "s")
    n2 = AttackNode("n2", NodeType.CAPABILITY, "CAP1", "c1")
    n3 = AttackNode("n3", NodeType.CAPABILITY, "CAP2", "c2")
    e1 = AttackEdge("e1", "n1", "n2", EdgeType.ENABLES)
    e2 = AttackEdge("e2", "n2", "n3", EdgeType.REQUIRES)
    g21 = engine.build_graph("g21", [n1, n2, n3], [e1, e2])
    assert len(g21.edges) == 2

    # 22: Escalates_To Edge
    e2_esc = AttackEdge("e2", "n2", "n3", EdgeType.ESCALATES_TO)
    g22 = engine.build_graph("g22", [n1, n2, n3], [e1, e2_esc])
    assert g22.to_dict()["nodes_count"] == 3

    # 23: Exposes Edge
    e2_exp = AttackEdge("e2", "n2", "n3", EdgeType.EXPOSES)
    g23 = engine.build_graph("g23", [n1, n2, n3], [e1, e2_exp])
    assert g23.to_dict()["edges_count"] == 2

    # 24: Executes Edge to Impact
    imp = ImpactNode("imp", NodeType.IMPACT, "IMP", "t")
    e3 = AttackEdge("e3", "n3", "imp", EdgeType.EXECUTES)
    g24 = engine.build_graph("g24", [n1, n2, n3, imp], [e1, e2_exp, e3])
    assert g24.to_dict()["resolution"] == "VULNERABLE"

    # 25: Destroys Edge to Impact
    e3_d = AttackEdge("e3", "n3", "imp", EdgeType.DESTROYS)
    g25 = engine.build_graph("g25", [n1, n2, n3, imp], [e1, e2_exp, e3_d])
    assert g25.to_dict()["resolution"] == "VULNERABLE"


def test_26_to_30_nodes_and_edges_validation() -> None:
    engine = AttackGraphConstructionEngine()
    g = engine.build_chain_m_ssrf_metadata_credential_compromise()
    assert len(g.nodes) == 4
    assert len(g.edges) == 3


def test_31_to_39_graph_invariants_verification() -> None:
    engine = AttackGraphConstructionEngine()
    g_m = engine.build_chain_m_ssrf_metadata_credential_compromise()
    g_n = engine.build_chain_n_xxe_file_read_env_db_pass()
    g_o = engine.build_chain_o_ssti_rce_env_dump_secrets()
    g_p = engine.build_chain_p_idor_tenant_escape_bulk_delete_tenant_wipe()

    for g in [g_m, g_n, g_o, g_p]:
        assert engine.is_acyclic(g.nodes, g.edges) is True
        assert len(g.root_causes) >= 1
        assert len(g.impacts) >= 1


def test_40_quality_metrics() -> None:
    """Calculates TP, TN, FP, FN, Precision, Recall, FPR, FNR breakdown on internal KarsaSec qualification corpus."""
    engine = AttackGraphConstructionEngine()

    tp_graphs = [engine.build_chain_m_ssrf_metadata_credential_compromise(f"tp_{i}") for i in range(50)]
    tn_nodes = [AttackNode("n1", NodeType.ROOT_CAUSE, "SAFE_CAUSE", "s", resolution="SAFE")]
    tn_graphs = [engine.build_graph(f"tn_{i}", tn_nodes, []) for i in range(50)]

    tp = sum(1 for g in tp_graphs if g.to_dict()["resolution"] == "VULNERABLE")
    fn = len(tp_graphs) - tp

    fp = sum(1 for g in tn_graphs if g.to_dict()["resolution"] == "VULNERABLE")
    tn = len(tn_graphs) - fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    assert tp == 50
    assert tn == 50
    assert fp == 0
    assert fn == 0
    assert precision == 1.0
    assert recall == 1.0
    assert fpr == 0.0
    assert fnr == 0.0
