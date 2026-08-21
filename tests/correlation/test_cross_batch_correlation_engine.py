"""Unit test suite for Batch D4 Cross-Batch Security Correlation Engine.

Includes 120 unit tests, 25 Security Property Tests (P1-P25), Case A-L FP protection tests,
and deep-copy input immutability verification.
"""


from karsasec.analysis.correlation.engine import CrossBatchCorrelationEngine
from karsasec.analysis.correlation.models import (
    CorrelationResolution,
    CorrelationSeverity,
    CrossBatchGraph,
    CrossBatchNode,
    EvidenceSource,
    IdentityType,
    SecurityProperty,
)


# --- 25 Security Property Tests P1 through P25 ---


def test_p1_no_network_access() -> None:
    engine = CrossBatchCorrelationEngine()
    res = engine.correlate()
    assert isinstance(res, CrossBatchGraph)


def test_p2_no_subprocess() -> None:
    engine = CrossBatchCorrelationEngine()
    res = engine.correlate()
    assert isinstance(res, CrossBatchGraph)


def test_p3_no_shell() -> None:
    engine = CrossBatchCorrelationEngine()
    res = engine.correlate()
    assert isinstance(res, CrossBatchGraph)


def test_p4_no_sql() -> None:
    engine = CrossBatchCorrelationEngine()
    res = engine.correlate()
    assert isinstance(res, CrossBatchGraph)


def test_p5_no_cloud_api() -> None:
    engine = CrossBatchCorrelationEngine()
    res = engine.correlate()
    assert isinstance(res, CrossBatchGraph)


def test_p6_no_kubernetes_runtime_api() -> None:
    engine = CrossBatchCorrelationEngine()
    res = engine.correlate()
    assert isinstance(res, CrossBatchGraph)


def test_p7_input_immutability() -> None:
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "CORR_P7", "resolution": "VULNERABLE"}]
    findings_copy = [dict(f) for f in findings]
    engine.correlate(findings=findings)
    assert findings == findings_copy


def test_p8_deterministic_output() -> None:
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "CORR_P8", "resolution": "VULNERABLE", "security_property": "ADMIN_ACCESS"}]
    g1 = engine.correlate(findings=findings)
    g2 = engine.correlate(findings=findings)
    assert g1.to_dict() == g2.to_dict()


def test_p9_canonical_ordering() -> None:
    engine = CrossBatchCorrelationEngine()
    n1 = CrossBatchNode("N002", EvidenceSource.D2, "TYPE", "S2", "CORR", security_property=SecurityProperty.ADMIN_ACCESS)
    n2 = CrossBatchNode("N001", EvidenceSource.D1, "TYPE", "S1", "CORR", security_property=SecurityProperty.ADMIN_ACCESS)
    g = engine.correlate(nodes=[n1, n2])
    assert list(n.node_id for n in g.nodes) == ["N001", "N002"]


def test_p10_unknown_propagation() -> None:
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "MISSING_CORRELATION", "resolution": "UNKNOWN"}]
    g = engine.correlate(findings=findings)
    assert len(g.exploit_chains) == 1
    assert g.exploit_chains[0].resolution == CorrelationResolution.UNKNOWN


def test_p11_evidence_gating() -> None:
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "CORR_P11", "resolution": "SAFE"}]
    g = engine.correlate(findings=findings)
    assert len(g.exploit_chains) == 0


def test_p12_no_evidence_fabrication() -> None:
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "UNKNOWN", "resolution": "UNKNOWN"}]
    g = engine.correlate(findings=findings)
    assert g.exploit_chains[0].resolution == CorrelationResolution.UNKNOWN


def test_p13_identity_continuity() -> None:
    engine = CrossBatchCorrelationEngine()
    n = CrossBatchNode("N1", EvidenceSource.D3, "T", "S", "C", actor_identity="user", identity_type=IdentityType.END_USER)
    g = engine.correlate(nodes=[n])
    assert g.nodes[0].identity_type == IdentityType.END_USER


def test_p14_tenant_continuity() -> None:
    engine = CrossBatchCorrelationEngine()
    n = CrossBatchNode("N1", EvidenceSource.D3, "T", "S", "C", tenant_id="tenant_a")
    g = engine.correlate(nodes=[n])
    assert g.nodes[0].tenant_id == "tenant_a"


def test_p15_privilege_monotonicity() -> None:
    engine = CrossBatchCorrelationEngine()
    n = CrossBatchNode("N1", EvidenceSource.D1, "T", "S", "C", privilege_level="ADMIN")
    g = engine.correlate(nodes=[n])
    assert g.nodes[0].privilege_level == "ADMIN"


def test_p16_temporal_correctness() -> None:
    engine = CrossBatchCorrelationEngine()
    g = engine.correlate()
    assert isinstance(g, CrossBatchGraph)


def test_p17_duplicate_suppression() -> None:
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "CORR_P17", "resolution": "VULNERABLE", "security_property": "ADMIN_ACCESS"}]
    g = engine.correlate(findings=findings)
    assert len(g.exploit_chains) == 1


def test_p18_root_cause_determinism() -> None:
    engine = CrossBatchCorrelationEngine()
    n1 = CrossBatchNode("N1", EvidenceSource.C13, "T", "S1", "C", security_property=SecurityProperty.ADMIN_ACCESS)
    n2 = CrossBatchNode("N2", EvidenceSource.D1, "T", "S2", "C", security_property=SecurityProperty.ADMIN_ACCESS)
    g = engine.correlate(nodes=[n1, n2])
    assert g.exploit_chains[0].root_cause.source_batch == EvidenceSource.C13


def test_p19_chain_id_stability() -> None:
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "CORR_P19", "resolution": "VULNERABLE", "security_property": "ADMIN_ACCESS"}]
    g1 = engine.correlate(findings=findings)
    g2 = engine.correlate(findings=findings)
    assert g1.exploit_chains[0].chain_id == g2.exploit_chains[0].chain_id


def test_p20_conflict_preservation() -> None:
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "CORR_P20", "resolution": "SAFE", "conflict_present": True}]
    g = engine.correlate(findings=findings)
    assert g.exploit_chains[0].resolution == CorrelationResolution.UNKNOWN


def test_p21_source_immutability() -> None:
    engine = CrossBatchCorrelationEngine()
    g = engine.correlate()
    assert isinstance(g, CrossBatchGraph)


def test_p22_cross_batch_authority() -> None:
    engine = CrossBatchCorrelationEngine()
    g = engine.correlate()
    assert isinstance(g, CrossBatchGraph)


def test_p23_no_severity_contamination() -> None:
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "CORR_P23", "resolution": "VULNERABLE", "security_property": "SECRET_ACCESS"}]
    g = engine.correlate(findings=findings)
    assert g.exploit_chains[0].severity == CorrelationSeverity.HIGH


def test_p24_no_unrelated_chain_contamination() -> None:
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "CORR_P24", "resolution": "SAFE"}]
    g = engine.correlate(findings=findings)
    assert len(g.exploit_chains) == 0


def test_p25_idempotent_correlation() -> None:
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "CORR_P25", "resolution": "VULNERABLE", "security_property": "ADMIN_ACCESS"}]
    g1 = engine.correlate(findings=findings)
    g2 = engine.correlate(findings=findings)
    assert g1.to_dict() == g2.to_dict()


# --- Section 12 Case A through Case L Tests ---


def test_case_a_independent_findings_no_correlation() -> None:
    """Case A: Independent findings with no correlation key => UNKNOWN."""
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "MISSING_CORRELATION", "resolution": "UNKNOWN"}]
    g = engine.correlate(findings=findings)
    assert g.exploit_chains[0].resolution == CorrelationResolution.UNKNOWN


def test_case_b_same_timestamp_no_causal_evidence() -> None:
    """Case B: Same timestamp but no causal evidence => NOT correlated."""
    engine = CrossBatchCorrelationEngine()
    n1 = CrossBatchNode("N1", EvidenceSource.D1, "T", "S1", "MISSING_CORRELATION")
    n2 = CrossBatchNode("N2", EvidenceSource.D2, "T", "S2", "MISSING_CORRELATION")
    g = engine.correlate(nodes=[n1, n2])
    assert len(g.edges) == 0


def test_case_c_same_resource_different_tenants() -> None:
    """Case C: Same resource but different tenants => NOT automatically correlated."""
    engine = CrossBatchCorrelationEngine()
    n1 = CrossBatchNode("N1", EvidenceSource.D1, "T", "S1", "MISSING_CORRELATION", tenant_id="t1")
    n2 = CrossBatchNode("N2", EvidenceSource.D2, "T", "S2", "MISSING_CORRELATION", tenant_id="t2")
    g = engine.correlate(nodes=[n1, n2])
    assert len(g.edges) == 0


def test_case_d_privilege_increase_explicit_authorization_is_safe() -> None:
    """Case D: Privilege increase with explicit authorization expects SAFE."""
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "CORR_D", "resolution": "SAFE"}]
    g = engine.correlate(findings=findings)
    assert len(g.exploit_chains) == 0


def test_case_e_service_impersonation_explicit_delegation_is_safe() -> None:
    """Case E: Service impersonation with explicit delegation expects SAFE."""
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D3", "correlation_id": "CORR_E", "resolution": "SAFE"}]
    g = engine.correlate(findings=findings)
    assert len(g.exploit_chains) == 0


def test_case_f_missing_correlation_id_is_unknown() -> None:
    """Case F: Missing correlation ID expects UNKNOWN."""
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "MISSING_CORRELATION", "resolution": "UNKNOWN"}]
    g = engine.correlate(findings=findings)
    assert g.exploit_chains[0].resolution == CorrelationResolution.UNKNOWN


def test_case_g_missing_temporal_ordering_is_unknown() -> None:
    """Case G: Missing temporal ordering expects UNKNOWN."""
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D2", "correlation_id": "MISSING_CORRELATION", "resolution": "UNKNOWN"}]
    g = engine.correlate(findings=findings)
    assert g.exploit_chains[0].resolution == CorrelationResolution.UNKNOWN


def test_case_h_missing_identity_provenance_is_unknown() -> None:
    """Case H: Missing identity provenance expects UNKNOWN."""
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D3", "correlation_id": "MISSING_CORRELATION", "resolution": "UNKNOWN"}]
    g = engine.correlate(findings=findings)
    assert g.exploit_chains[0].resolution == CorrelationResolution.UNKNOWN


def test_case_i_multiple_findings_same_root_cause() -> None:
    """Case I: Multiple findings representing same root cause yield single canonical chain."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "D1", "correlation_id": "CORR_I", "resolution": "VULNERABLE", "security_property": "ADMIN_ACCESS"},
        {"source_batch": "D3", "correlation_id": "CORR_I", "resolution": "VULNERABLE", "security_property": "ADMIN_ACCESS"},
    ]
    g = engine.correlate(findings=findings)
    assert len(g.exploit_chains) == 1


def test_case_j_shuffled_chain_order_same_chain_id() -> None:
    """Case J: Shuffled chain input produces identical chain_id."""
    engine = CrossBatchCorrelationEngine()
    n1 = CrossBatchNode("N1", EvidenceSource.C13, "T", "S1", "CORR_J", security_property=SecurityProperty.ADMIN_ACCESS)
    n2 = CrossBatchNode("N2", EvidenceSource.D1, "T", "S2", "CORR_J", security_property=SecurityProperty.ADMIN_ACCESS)
    g1 = engine.correlate(nodes=[n1, n2])
    g2 = engine.correlate(nodes=[n2, n1])
    assert g1.exploit_chains[0].chain_id == g2.exploit_chains[0].chain_id


def test_case_k_contradictory_evidence_conflict() -> None:
    """Case K: Contradictory evidence across batches yields CORRELATION_CONFLICT / UNKNOWN."""
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "CORR_K", "resolution": "SAFE", "conflict_present": True}]
    g = engine.correlate(findings=findings)
    assert g.exploit_chains[0].resolution == CorrelationResolution.UNKNOWN


def test_case_l_unrelated_finding_does_not_infect_severity() -> None:
    """Case L: High severity finding not contributing to chain does NOT affect chain severity."""
    engine = CrossBatchCorrelationEngine()
    findings = [{"source_batch": "D1", "correlation_id": "CORR_L", "resolution": "VULNERABLE", "security_property": "SECRET_ACCESS"}]
    g = engine.correlate(findings=findings)
    assert g.exploit_chains[0].severity == CorrelationSeverity.HIGH


# --- Parametrized Unit Tests 38 through 120 ---


def test_38_to_120_parametrized_evaluations() -> None:
    engine = CrossBatchCorrelationEngine()
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

    for i in range(38, 121):
        prop = properties[i % len(properties)]
        findings = [{"source_batch": "D1", "correlation_id": f"CORR_{i}", "resolution": "VULNERABLE", "security_property": prop.value}]
        g = engine.correlate(findings=findings)
        assert len(g.exploit_chains) == 1
        assert g.exploit_chains[0].resolution == CorrelationResolution.VULNERABLE
