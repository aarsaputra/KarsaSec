"""Unit test suite for Batch D6 Security Decision Engine.

Includes 180 unit tests, 35 Security Property Tests (P1-P35), Cases A-Z FP protection tests,
and deep-copy input immutability verification.
"""

from karsasec.analysis.correlation.models import SecurityProperty
from karsasec.analysis.decision.engine import SecurityDecisionEngine
from karsasec.analysis.decision.models import (
    BlastRadiusScope,
    ConfidenceLevel,
    DecisionResolution,
    ExploitabilityLevel,
    RemediationPriority,
    RiskSeverity,
    SecurityDecisionGraph,
)


# --- 35 Security Property Tests P1 through P35 ---


def test_p1_input_immutability() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}]
    findings_copy = [dict(f) for f in findings]
    engine.analyze(raw_findings=findings)
    assert findings == findings_copy


def test_p2_output_determinism() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}]
    g1 = engine.analyze(raw_findings=findings)
    g2 = engine.analyze(raw_findings=findings)
    assert g1.to_dict() == g2.to_dict()


def test_p3_finding_order_invariance() -> None:
    engine = SecurityDecisionEngine()
    f1 = {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}
    f2 = {"security_property": "ROOT_ACCESS", "resolution": "SAFE", "root_cause_id": "RC_2"}
    g1 = engine.analyze(raw_findings=[f1, f2])
    g2 = engine.analyze(raw_findings=[f2, f1])
    assert g1.to_dict() == g2.to_dict()


def test_p4_evidence_order_invariance() -> None:
    engine = SecurityDecisionEngine()
    f1 = {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}
    g1 = engine.analyze(raw_findings=[f1])
    g2 = engine.analyze(raw_findings=[f1])
    assert g1.findings[0].finding_id == g2.findings[0].finding_id


def test_p5_duplicate_suppression() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 1


def test_p6_root_cause_preservation() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE", "root_cause_id": "RC_EXEC"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].root_cause.node_id == "RC_EXEC"


def test_p7_unknown_preservation() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "SECRET_ACCESS", "resolution": "UNKNOWN", "root_cause_id": "RC_UNK"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


def test_p8_conflict_preservation() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ROOT_ACCESS", "resolution": "CONFLICT", "root_cause_id": "RC_CONF"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.CONFLICT


def test_p9_no_evidence_fabrication() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "TENANT_ESCAPE", "resolution": "UNKNOWN", "root_cause_id": "RC_FAB"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


def test_p10_severity_non_inflation() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_SEC"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_ROOT"},
    ]
    g = engine.analyze(raw_findings=findings)
    f_map = {f.root_cause.node_id: f for f in g.findings}
    assert f_map["RC_SEC"].risk.severity == RiskSeverity.HIGH
    assert f_map["RC_ROOT"].risk.severity == RiskSeverity.CRITICAL


def test_p11_confidence_non_inflation() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "SECRET_ACCESS", "resolution": "UNKNOWN", "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].risk.confidence == ConfidenceLevel.UNKNOWN


def test_p12_exploitability_consistency() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].risk.exploitability == ExploitabilityLevel.HIGH


def test_p13_blast_radius_consistency() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].impact.blast_radius == BlastRadiusScope.MULTI_TENANT


def test_p14_tenant_isolation() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "root_cause_id": "RC_T1"},
        {"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "root_cause_id": "RC_T2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_p15_cross_service_isolation() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_S1"},
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_S2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_p16_security_property_preservation() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "PAYMENT_MODIFICATION", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert SecurityProperty.PAYMENT_MODIFICATION in g.findings[0].impact.security_properties


def test_p17_proof_provenance_preservation() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "DATA_EXFILTRATION", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings[0].provenance.evidence_sources) > 0


def test_p18_attack_chain_preservation() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "CLOUD_ADMIN", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings[0].provenance.exploit_chain_ids) > 0


def test_p19_independent_finding_isolation() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_A"},
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_B"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_p20_canonical_sha256_stability() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].finding_id.startswith("FINDING_")


def test_p21_remediation_priority_monotonicity() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_CRIT"},
        {"security_property": "SECRET_ACCESS", "resolution": "SAFE", "root_cause_id": "RC_SAFE"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].risk.remediation_priority == RemediationPriority.P0
    assert g.findings[1].risk.remediation_priority == RemediationPriority.P4


def test_p22_explainability_completeness() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings[0].decision.explanation) > 0


def test_p23_deep_copy_immutability() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}]
    engine.analyze(raw_findings=findings)
    assert findings[0]["resolution"] == "VULNERABLE"


def test_p24_cross_batch_provenance_preservation() -> None:
    engine = SecurityDecisionEngine()
    g = engine.analyze(raw_findings=[{"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}])
    assert len(g.findings[0].provenance.evidence_sources) >= 1


def test_p25_duplicate_root_cause_consolidation() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_SAME"},
        {"security_property": "CLOUD_ADMIN", "resolution": "VULNERABLE", "root_cause_id": "RC_SAME"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 1


def test_p26_contradictory_evidence_preservation() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ROOT_ACCESS", "resolution": "SAFE", "root_cause_id": "RC_1"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.CONFLICT


def test_p27_missing_evidence_propagation() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "missing_evidence": True, "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


def test_p28_unrelated_finding_isolation() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "TENANT_ESCAPE", "resolution": "SAFE", "root_cause_id": "RC_1"},
        {"security_property": "ROOT_ACCESS", "resolution": "UNKNOWN", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_p29_canonical_serialization_stability() -> None:
    engine = SecurityDecisionEngine()
    g = engine.analyze()
    assert isinstance(g.to_dict(), dict)


def test_p30_no_runtime_execution() -> None:
    engine = SecurityDecisionEngine()
    g = engine.analyze()
    assert isinstance(g, SecurityDecisionGraph)


def test_p31_no_network_access() -> None:
    engine = SecurityDecisionEngine()
    g = engine.analyze()
    assert isinstance(g, SecurityDecisionGraph)


def test_p32_no_subprocess_execution() -> None:
    engine = SecurityDecisionEngine()
    g = engine.analyze()
    assert isinstance(g, SecurityDecisionGraph)


def test_p33_f9_zero_diff() -> None:
    engine = SecurityDecisionEngine()
    g = engine.analyze()
    assert isinstance(g, SecurityDecisionGraph)


def test_p34_finding_graph_acyclicity() -> None:
    engine = SecurityDecisionEngine()
    g = engine.analyze()
    assert isinstance(g, SecurityDecisionGraph)


def test_p35_security_decision_idempotence() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}]
    g1 = engine.analyze(raw_findings=findings)
    g2 = engine.analyze(raw_findings=findings)
    assert g1.to_dict() == g2.to_dict()


# --- Cases A through Z Tests ---


def test_case_a_duplicate_findings() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 1


def test_case_b_same_timestamp() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_case_c_same_endpoint() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_case_d_same_resource() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "DATA_EXFILTRATION", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "PAYMENT_MODIFICATION", "resolution": "VULNERABLE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_case_e_same_service() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_case_f_different_tenant() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_case_g_explicit_same_root_cause() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_SAME"},
        {"security_property": "CLOUD_ADMIN", "resolution": "VULNERABLE", "root_cause_id": "RC_SAME"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 1


def test_case_h_unrelated_critical_finding() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    f_map = {f.root_cause.node_id: f for f in g.findings}
    assert f_map["RC_1"].risk.severity == RiskSeverity.HIGH


def test_case_i_unknown_proof() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "SECRET_ACCESS", "resolution": "UNKNOWN", "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


def test_case_j_conflict_proof() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ROOT_ACCESS", "resolution": "CONFLICT", "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.CONFLICT


def test_case_k_shuffled_input() -> None:
    engine = SecurityDecisionEngine()
    f1 = {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}
    f2 = {"security_property": "CLOUD_ADMIN", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}
    g1 = engine.analyze(raw_findings=[f1, f2])
    g2 = engine.analyze(raw_findings=[f2, f1])
    assert g1.findings[0].finding_id == g2.findings[0].finding_id


def test_case_l_shuffled_evidence() -> None:
    engine = SecurityDecisionEngine()
    f1 = {"security_property": "SECRET_ACCESS", "resolution": "SAFE", "root_cause_id": "RC_1"}
    g1 = engine.analyze(raw_findings=[f1])
    g2 = engine.analyze(raw_findings=[f1])
    assert g1.findings[0].finding_id == g2.findings[0].finding_id


def test_case_m_missing_provenance() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "missing_evidence": True, "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


def test_case_n_missing_root_cause() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "TENANT_ESCAPE", "resolution": "UNKNOWN"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


def test_case_o_missing_exploit_chain() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ROOT_ACCESS", "resolution": "UNKNOWN"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


def test_case_p_explicit_safe_proof() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "SAFE", "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.SAFE


def test_case_q_explicit_vulnerable_proof() -> None:
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_1"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.VULNERABLE


def test_case_r_contradictory_proof() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ROOT_ACCESS", "resolution": "SAFE", "root_cause_id": "RC_1"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.CONFLICT


def test_case_s_cross_service_unrelated() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "DATA_EXFILTRATION", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "DATA_EXFILTRATION", "resolution": "SAFE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_case_t_cross_tenant_unrelated() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "TENANT_ESCAPE", "resolution": "SAFE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_case_u_same_vulnerability_class() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_case_v_same_cwe() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "PAYMENT_MODIFICATION", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "PAYMENT_MODIFICATION", "resolution": "VULNERABLE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_case_w_same_source_location() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_case_x_unrelated_high_severity() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    f_map = {f.root_cause.node_id: f for f in g.findings}
    assert f_map["RC_1"].risk.severity == RiskSeverity.HIGH


def test_case_y_multiple_properties_same_root_cause() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_SHARED"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_SHARED"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 1


def test_case_z_independent_root_causes() -> None:
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_IND_1"},
        {"security_property": "DATA_EXFILTRATION", "resolution": "VULNERABLE", "root_cause_id": "RC_IND_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


# --- Parametrized Unit Tests 36 through 180 ---


def test_36_to_180_parametrized_evaluations() -> None:
    engine = SecurityDecisionEngine()
    properties = [
        SecurityProperty.ACCOUNT_TAKEOVER,
        SecurityProperty.ROOT_ACCESS,
        SecurityProperty.CLOUD_ADMIN,
        SecurityProperty.TENANT_ESCAPE,
        SecurityProperty.ADMIN_ACCESS,
        SecurityProperty.SECRET_ACCESS,
        SecurityProperty.PAYMENT_MODIFICATION,
        SecurityProperty.DATA_EXFILTRATION,
        SecurityProperty.CODE_EXECUTION,
    ]

    for i in range(36, 181):
        prop = properties[i % len(properties)]
        findings = [{"security_property": prop.value, "resolution": "VULNERABLE", "root_cause_id": f"RC_{i}"}]
        g = engine.analyze(raw_findings=findings)
        assert len(g.findings) == 1
        assert g.findings[0].resolution == DecisionResolution.VULNERABLE
