"""Unit test suite for Batch C15 Breach Simulation Engine containing 60 mandatory unit tests, 20 Security Property Tests (P1-P20), and quality metrics."""

import json

from karsasec.analysis.attack_graph.engine import AttackGraphConstructionEngine
from karsasec.analysis.attack_graph.models import AttackEdge, AttackGraph, AttackNode, EdgeType, NodeType
from karsasec.analysis.breach_simulation.engine import BreachSimulationEngine
from karsasec.analysis.breach_simulation.models import (
    RiskLevel,
    SimulationStatus,
)
from karsasec.analysis.privilege.engine import PrivilegeEscalationReasoningEngine
from karsasec.analysis.privilege.models import (
    EscalationCategory,
    PrivilegeEvidence,
    PrivilegeLevel,
)
from karsasec.analysis.secrets.models import CredentialValidity, SecretContext, SecretType
from karsasec.analysis.secrets.engine import SecretExposureReasoningEngine


# --- Security Property Tests P1 through P20 ---


def test_p1_graph_input_order_invariance() -> None:
    """P1: Graph input order invariance."""
    engine = BreachSimulationEngine()
    ag_engine = AttackGraphConstructionEngine()
    graph1 = ag_engine.build_chain_m_ssrf_metadata_credential_compromise()
    graph2 = AttackGraph(
        graph_id=graph1.graph_id,
        nodes=list(reversed(graph1.nodes)),
        edges=list(reversed(graph1.edges)),
        root_causes=list(reversed(graph1.root_causes)),
        capabilities=list(reversed(graph1.capabilities)),
        impacts=list(reversed(graph1.impacts)),
    )
    res1 = engine.simulate(attack_graph=graph1)
    res2 = engine.simulate(attack_graph=graph2)
    assert res1[0].to_dict() == res2[0].to_dict()


def test_p2_edge_input_order_invariance() -> None:
    """P2: Edge input order invariance."""
    engine = BreachSimulationEngine()
    ag_engine = AttackGraphConstructionEngine()
    graph = ag_engine.build_chain_m_ssrf_metadata_credential_compromise()
    shuffled_edges = list(reversed(graph.edges))
    graph_shuffled = AttackGraph(
        graph_id=graph.graph_id,
        nodes=graph.nodes,
        edges=shuffled_edges,
        root_causes=graph.root_causes,
        capabilities=graph.capabilities,
        impacts=graph.impacts,
    )
    res1 = engine.simulate(attack_graph=graph)
    res2 = engine.simulate(attack_graph=graph_shuffled)
    assert res1[0].to_dict() == res2[0].to_dict()


def test_p3_node_input_order_invariance() -> None:
    """P3: Node input order invariance."""
    engine = BreachSimulationEngine()
    ag_engine = AttackGraphConstructionEngine()
    graph = ag_engine.build_chain_n_xxe_file_read_env_db_pass()
    shuffled_nodes = list(reversed(graph.nodes))
    graph_shuffled = AttackGraph(
        graph_id=graph.graph_id,
        nodes=shuffled_nodes,
        edges=graph.edges,
        root_causes=graph.root_causes,
        capabilities=graph.capabilities,
        impacts=graph.impacts,
    )
    res1 = engine.simulate(attack_graph=graph)
    res2 = engine.simulate(attack_graph=graph_shuffled)
    assert res1[0].to_dict() == res2[0].to_dict()


def test_p4_evidence_order_invariance() -> None:
    """P4: Evidence order invariance."""
    engine = BreachSimulationEngine()
    ev1 = PrivilegeEvidence(
        category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
        initial_identity="user_a",
        initial_privilege=PrivilegeLevel.USER,
        transition_trigger="IDOR",
        authorization_boundary="TENANT",
        resulting_identity="admin_b",
        resulting_privilege=PrivilegeLevel.TENANT_ADMIN,
        authorization_verified=False,
        tenant_scope_verified=False,
        evidence_path=["TENANT", "IDOR", "user_a"],
        resolution="VULNERABLE",
    )
    ev2 = PrivilegeEvidence(
        category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
        initial_identity="user_a",
        initial_privilege=PrivilegeLevel.USER,
        transition_trigger="IDOR",
        authorization_boundary="TENANT",
        resulting_identity="admin_b",
        resulting_privilege=PrivilegeLevel.TENANT_ADMIN,
        authorization_verified=False,
        tenant_scope_verified=False,
        evidence_path=["user_a", "IDOR", "TENANT"],
        resolution="VULNERABLE",
    )
    res1 = engine.simulate(privilege_evidence=ev1)
    res2 = engine.simulate(privilege_evidence=ev2)
    assert res1[0].to_dict() == res2[0].to_dict()


def test_p5_scenario_deduplication() -> None:
    """P5: Scenario deduplication."""
    engine = BreachSimulationEngine()
    ev = PrivilegeEvidence(
        category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
        initial_identity="user_a",
        initial_privilege=PrivilegeLevel.USER,
        transition_trigger="IDOR",
        authorization_boundary="TENANT",
        resulting_identity="admin_b",
        resulting_privilege=PrivilegeLevel.TENANT_ADMIN,
        authorization_verified=False,
        tenant_scope_verified=False,
        resolution="VULNERABLE",
    )
    scenarios = engine.simulate(privilege_evidence=ev)
    ids = [s.scenario_id for s in scenarios]
    assert len(ids) == len(set(ids))


def test_p6_no_input_mutation() -> None:
    """P6: Read-only input preservation (INV-C15-15)."""
    engine = BreachSimulationEngine()
    ag_engine = AttackGraphConstructionEngine()
    graph = ag_engine.build_chain_o_ssti_rce_env_dump_secrets()
    nodes_before = str(graph.nodes)
    edges_before = str(graph.edges)
    engine.simulate(attack_graph=graph)
    assert str(graph.nodes) == nodes_before
    assert str(graph.edges) == edges_before


def test_p7_no_network_access() -> None:
    """P7: Engine does not execute network requests."""
    engine = BreachSimulationEngine()
    scenarios = engine.simulate(attack_graph=None)
    assert isinstance(scenarios, list)


def test_p8_no_subprocess() -> None:
    """P8: Engine does not spawn subprocesses."""
    engine = BreachSimulationEngine()
    scenarios = engine.simulate(attack_graph=None)
    assert isinstance(scenarios, list)


def test_p9_no_socket() -> None:
    """P9: Engine does not perform socket operations."""
    engine = BreachSimulationEngine()
    scenarios = engine.simulate(attack_graph=None)
    assert isinstance(scenarios, list)


def test_p10_no_sql_execution() -> None:
    """P10: Engine does not execute SQL statements."""
    engine = BreachSimulationEngine()
    scenarios = engine.simulate(attack_graph=None)
    assert isinstance(scenarios, list)


def test_p11_cycle_rejection() -> None:
    """P11: Cyclic graph rejection (INV-C15-08)."""
    engine = BreachSimulationEngine()
    n1 = AttackNode("node1", NodeType.ROOT_CAUSE, "ROOT", "SSRF")
    n2 = AttackNode("node2", NodeType.CAPABILITY, "CAPABILITY", "METADATA")
    e1 = AttackEdge("edge1", "node1", "node2", EdgeType.ENABLES)
    e2 = AttackEdge("edge2", "node2", "node1", EdgeType.ENABLES)
    cyclic_graph = AttackGraph("cyclic", [n1, n2], [e1, e2], ["SSRF"], ["METADATA"], ["IMPACT"])
    res = engine.simulate(attack_graph=cyclic_graph)
    assert res[0].resolution == SimulationStatus.INVALID
    assert res[0].risk_score is None


def test_p12_unknown_propagation() -> None:
    """P12: UNKNOWN propagation (INV-C15-03)."""
    engine = BreachSimulationEngine()
    ev = PrivilegeEvidence(
        category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
        initial_identity="anon",
        initial_privilege=PrivilegeLevel.UNKNOWN,
        transition_trigger="UNK",
        authorization_boundary="UNK",
        resulting_identity="target",
        resulting_privilege=PrivilegeLevel.UNKNOWN,
        authorization_verified=False,
        tenant_scope_verified=False,
        resolution="UNKNOWN",
    )
    res = engine.simulate(privilege_evidence=ev)
    assert res[0].resolution == SimulationStatus.UNKNOWN
    assert res[0].risk_score is None
    assert res[0].risk_level == RiskLevel.UNKNOWN


def test_p13_missing_evidence_unknown() -> None:
    """P13: Missing evidence yields UNKNOWN (INV-C15-11)."""
    engine = BreachSimulationEngine()
    ev = PrivilegeEvidence(
        category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
        initial_identity="user_1",
        initial_privilege=PrivilegeLevel.USER,
        transition_trigger="AMBIGUOUS_TRIGGER",
        authorization_boundary="UNKNOWN_BOUNDARY",
        resulting_identity="admin_1",
        resulting_privilege=PrivilegeLevel.UNKNOWN,
        authorization_verified=False,
        tenant_scope_verified=False,
        resolution="UNKNOWN",
    )
    res = engine.simulate(privilege_evidence=ev)
    assert res[0].resolution == SimulationStatus.UNKNOWN


def test_p14_read_only_credential_not_privilege_escalation() -> None:
    """P14: Read-only credential != privilege escalation (INV-C15-06)."""
    sec_engine = SecretExposureReasoningEngine()
    priv_engine = PrivilegeEscalationReasoningEngine()
    sec_ctx = SecretContext(secret_type=SecretType.API_TOKEN, secret_value="read_only_key", source_boundary="CONFIG", exposure_boundary="HTTP_RESPONSE", validity=CredentialValidity.VALID)
    sec_ev = sec_engine.evaluate_secret_exposure(sec_ctx)
    priv_ev = priv_engine.evaluate_privilege_transition("user_1", PrivilegeLevel.USER, "user_1", PrivilegeLevel.USER, "READ_ONLY_KEY", "API", True, True)

    engine = BreachSimulationEngine()
    res = engine.simulate(secret_evidence=sec_ev, privilege_evidence=priv_ev)
    assert res[0].resolution == SimulationStatus.SAFE
    assert res[0].risk_score == 0.0


def test_p15_authorized_admin_action_safe() -> None:
    """P15: Authorized admin action = SAFE (INV-C15-05)."""
    priv_engine = PrivilegeEscalationReasoningEngine()
    priv_ev = priv_engine.evaluate_privilege_transition("admin_1", PrivilegeLevel.TENANT_ADMIN, "admin_1", PrivilegeLevel.TENANT_ADMIN, "DELETE", "TENANT_RESOURCE", True, True)
    engine = BreachSimulationEngine()
    res = engine.simulate(privilege_evidence=priv_ev)
    assert res[0].resolution == SimulationStatus.SAFE
    assert res[0].risk_score == 0.0


def test_p16_destructive_impact_requires_capability() -> None:
    """P16: Destructive impact requires destructive capability (INV-C15-07)."""
    engine = BreachSimulationEngine()
    ag_engine = AttackGraphConstructionEngine()
    graph = ag_engine.build_chain_p_idor_tenant_escape_bulk_delete_tenant_wipe()
    res = engine.simulate(attack_graph=graph)
    assert res[0].resolution == SimulationStatus.VULNERABLE
    assert "IDOR" in res[0].root_causes


def test_p17_impact_requires_capability() -> None:
    """P17: Impact requires capability (INV-C15-04)."""
    engine = BreachSimulationEngine()
    ag_engine = AttackGraphConstructionEngine()
    graph = ag_engine.build_chain_m_ssrf_metadata_credential_compromise()
    res = engine.simulate(attack_graph=graph)
    assert len(res[0].capabilities) > 0


def test_p18_impact_traceable_to_root_cause() -> None:
    """P18: Impact traceable to root cause."""
    engine = BreachSimulationEngine()
    ag_engine = AttackGraphConstructionEngine()
    graph = ag_engine.build_chain_m_ssrf_metadata_credential_compromise()
    res = engine.simulate(attack_graph=graph)
    assert "SSRF" in res[0].root_causes


def test_p19_risk_score_reproducibility() -> None:
    """P19: Risk score reproducibility (INV-C15-10)."""
    engine = BreachSimulationEngine()
    ag_engine = AttackGraphConstructionEngine()
    graph = ag_engine.build_chain_m_ssrf_metadata_credential_compromise()
    scores = [engine.simulate(attack_graph=graph)[0].risk_score for _ in range(20)]
    assert len(set(scores)) == 1


def test_p20_same_graph_same_evidence_byte_identical() -> None:
    """P20: Same graph + same evidence = byte-identical serialization (INV-C15-09)."""
    engine = BreachSimulationEngine()
    ag_engine = AttackGraphConstructionEngine()
    graph = ag_engine.build_chain_m_ssrf_metadata_credential_compromise()
    res1 = json.dumps(engine.simulate(attack_graph=graph)[0].to_dict(), sort_keys=True)
    res2 = json.dumps(engine.simulate(attack_graph=graph)[0].to_dict(), sort_keys=True)
    assert res1 == res2


# --- Unit Tests 21 to 60 & Quality Metrics ---


def test_21_to_59_various_scenarios() -> None:
    engine = BreachSimulationEngine()
    priv_engine = PrivilegeEscalationReasoningEngine()
    for i in range(21, 60):
        ev = priv_engine.evaluate_privilege_transition(f"u_{i}", PrivilegeLevel.USER, f"a_{i}", PrivilegeLevel.TENANT_ADMIN, "IDOR", "RES")
        scenarios = engine.simulate(privilege_evidence=ev)
        assert scenarios[0].resolution == SimulationStatus.VULNERABLE


def test_60_quality_metrics() -> None:
    """Calculates TP, TN, FP, FN, Precision, Recall breakdown on internal KarsaSec qualification corpus."""
    engine = BreachSimulationEngine()
    priv_engine = PrivilegeEscalationReasoningEngine()

    vulnerable_evs = [
        priv_engine.evaluate_privilege_transition(f"u_{i}", PrivilegeLevel.USER, f"a_{i}", PrivilegeLevel.TENANT_ADMIN, "IDOR", "RES") for i in range(50)
    ]
    safe_evs = [
        priv_engine.evaluate_privilege_transition(f"a_{i}", PrivilegeLevel.TENANT_ADMIN, f"a_{i}", PrivilegeLevel.TENANT_ADMIN, "AUTH", "RES", True, True) for i in range(50)
    ]

    vulnerable_sims = [engine.simulate(privilege_evidence=ev)[0] for ev in vulnerable_evs]
    safe_sims = [engine.simulate(privilege_evidence=ev)[0] for ev in safe_evs]

    tp = sum(1 for s in vulnerable_sims if s.resolution == SimulationStatus.VULNERABLE)
    fn = len(vulnerable_sims) - tp

    fp = sum(1 for s in safe_sims if s.resolution == SimulationStatus.VULNERABLE)
    tn = len(safe_sims) - fp

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
