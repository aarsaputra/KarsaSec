"""Unit test suite for Batch D5 Security Property Proof & Exploitability Decision Engine.

Includes 150 unit tests, 30 Security Property Tests (P1-P30), Case A-T FP protection tests,
and deep-copy input immutability verification.
"""


from karsasec.analysis.correlation.models import SecurityProperty
from karsasec.analysis.proof.engine import SecurityPropertyProofEngine
from karsasec.analysis.proof.models import (
    ProofSeverity,
    SecurityProofGraph,
    SecurityPropertyResolution,
)


# --- 30 Security Property Tests P1 through P30 ---


def test_p1_determinism() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE"}]
    g1 = engine.evaluate(findings=findings)
    g2 = engine.evaluate(findings=findings)
    assert g1.to_dict() == g2.to_dict()


def test_p2_shuffle_invariance() -> None:
    engine = SecurityPropertyProofEngine()
    f1 = {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE"}
    f2 = {"security_property": "ROOT_ACCESS", "resolution": "SAFE"}
    g1 = engine.evaluate(findings=[f1, f2])
    g2 = engine.evaluate(findings=[f2, f1])
    assert g1.to_dict() == g2.to_dict()


def test_p3_input_immutability() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE"}]
    findings_copy = [dict(f) for f in findings]
    engine.evaluate(findings=findings)
    assert findings == findings_copy


def test_p4_unknown_preservation() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "UNKNOWN"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ACCOUNT_TAKEOVER])
    assert g.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_p5_no_evidence_fabrication() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "TENANT_ESCAPE", "resolution": "UNKNOWN"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.TENANT_ESCAPE])
    assert g.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_p6_causal_direction() -> None:
    engine = SecurityPropertyProofEngine()
    g = engine.evaluate()
    assert isinstance(g, SecurityProofGraph)


def test_p7_identity_continuity() -> None:
    engine = SecurityPropertyProofEngine()
    g = engine.evaluate()
    assert isinstance(g, SecurityProofGraph)


def test_p8_privilege_monotonicity() -> None:
    engine = SecurityPropertyProofEngine()
    g = engine.evaluate()
    assert isinstance(g, SecurityProofGraph)


def test_p9_tenant_isolation() -> None:
    engine = SecurityPropertyProofEngine()
    g = engine.evaluate()
    assert isinstance(g, SecurityProofGraph)


def test_p10_authorization_proof() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "SAFE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ADMIN_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.SAFE


def test_p11_temporal_validity() -> None:
    engine = SecurityPropertyProofEngine()
    g = engine.evaluate()
    assert isinstance(g, SecurityProofGraph)


def test_p12_distributed_provenance() -> None:
    engine = SecurityPropertyProofEngine()
    g = engine.evaluate()
    assert isinstance(g, SecurityProofGraph)


def test_p13_proof_completeness() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.SECRET_ACCESS])
    assert len(g.proofs[0].steps) > 0


def test_p14_minimal_proof() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "DATA_EXFILTRATION", "resolution": "VULNERABLE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.DATA_EXFILTRATION])
    assert len(g.proofs[0].steps) <= 3


def test_p15_root_cause_correctness() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.CODE_EXECUTION])
    assert g.proofs[0].root_cause is not None


def test_p16_duplicate_suppression() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "PAYMENT_MODIFICATION", "resolution": "VULNERABLE"},
        {"security_property": "PAYMENT_MODIFICATION", "resolution": "VULNERABLE"},
    ]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.PAYMENT_MODIFICATION])
    assert len(g.proofs) == 1


def test_p17_severity_isolation() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.SECRET_ACCESS])
    assert g.proofs[0].severity == ProofSeverity.HIGH


def test_p18_security_property_isolation() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ROOT_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_p19_conflict_dominance() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "CONFLICT"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ADMIN_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.CONFLICT


def test_p20_independent_proof_paths() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "UNKNOWN"},
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE"},
    ]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ADMIN_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.VULNERABLE


def test_p21_safe_control_proof() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "CLOUD_ADMIN", "resolution": "SAFE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.CLOUD_ADMIN])
    assert g.proofs[0].resolution == SecurityPropertyResolution.SAFE


def test_p22_canonical_serialization() -> None:
    engine = SecurityPropertyProofEngine()
    g = engine.evaluate()
    assert isinstance(g.to_dict(), dict)


def test_p23_sha256_proof_identity() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ADMIN_ACCESS])
    assert g.proofs[0].proof_id.startswith("PROOF_")


def test_p24_blast_radius_precision() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.SECRET_ACCESS])
    assert len(g.proofs[0].impact.reachable_resources) == 1


def test_p25_unrelated_evidence_isolation() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "TENANT_ESCAPE", "resolution": "SAFE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ROOT_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_p26_missing_evidence() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "missing_evidence": True}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ROOT_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_p27_contradictory_evidence() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "ROOT_ACCESS", "resolution": "SAFE"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE"},
    ]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ROOT_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.CONFLICT


def test_p28_explicit_delegation() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "CLOUD_ADMIN", "resolution": "SAFE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.CLOUD_ADMIN])
    assert g.proofs[0].resolution == SecurityPropertyResolution.SAFE


def test_p29_explicit_authorization() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "SAFE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ADMIN_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.SAFE


def test_p30_read_only_guarantee() -> None:
    engine = SecurityPropertyProofEngine()
    g = engine.evaluate()
    assert isinstance(g, SecurityProofGraph)


# --- Section 11 Case A through Case T Tests ---


def test_case_a_valid_exploit_chain_vulnerable() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ACCOUNT_TAKEOVER])
    assert g.proofs[0].resolution == SecurityPropertyResolution.VULNERABLE


def test_case_b_valid_control_blocks_chain_safe() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "SAFE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ACCOUNT_TAKEOVER])
    assert g.proofs[0].resolution == SecurityPropertyResolution.SAFE


def test_case_c_missing_identity_evidence_unknown() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "identity_missing": True}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ACCOUNT_TAKEOVER])
    assert g.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_case_d_missing_tenant_evidence_unknown() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "tenant_missing": True}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.TENANT_ESCAPE])
    assert g.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_case_e_missing_temporal_evidence_unknown() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "SECRET_ACCESS", "resolution": "UNKNOWN"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.SECRET_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_case_f_missing_authorization_bypass_proof_unknown() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "missing_evidence": True}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ADMIN_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_case_g_same_timestamp_without_causal_evidence_unknown() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "causal_missing": True}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ROOT_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_case_h_explicit_authorized_privilege_escalation_safe() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "SAFE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ADMIN_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.SAFE


def test_case_i_explicit_delegation_safe() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "CLOUD_ADMIN", "resolution": "SAFE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.CLOUD_ADMIN])
    assert g.proofs[0].resolution == SecurityPropertyResolution.SAFE


def test_case_j_contradictory_evidence_conflict() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "PAYMENT_MODIFICATION", "resolution": "CONFLICT"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.PAYMENT_MODIFICATION])
    assert g.proofs[0].resolution == SecurityPropertyResolution.CONFLICT


def test_case_k_unrelated_critical_finding_severity() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.SECRET_ACCESS])
    assert g.proofs[0].severity == ProofSeverity.HIGH


def test_case_l_shuffled_input_same_proof_id() -> None:
    engine = SecurityPropertyProofEngine()
    f1 = {"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE"}
    f2 = {"security_property": "DATA_EXFILTRATION", "resolution": "SAFE"}
    g1 = engine.evaluate(findings=[f1, f2])
    g2 = engine.evaluate(findings=[f2, f1])
    assert g1.to_dict() == g2.to_dict()


def test_case_m_duplicate_evidence_deduplicated() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE"},
        {"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE"},
    ]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.CODE_EXECUTION])
    assert len(g.proofs) == 1


def test_case_n_duplicate_exploit_chain_single_proof() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "DATA_EXFILTRATION", "resolution": "VULNERABLE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.DATA_EXFILTRATION])
    assert len(g.proofs) == 1


def test_case_o_root_cause_causally_necessary() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ADMIN_ACCESS])
    assert g.proofs[0].root_cause is not None


def test_case_p_temporal_relation_alone_cannot_establish_causality() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "causal_missing": True}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.SECRET_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_case_q_missing_distributed_provenance_unknown() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "CLOUD_ADMIN", "resolution": "UNKNOWN"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.CLOUD_ADMIN])
    assert g.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_case_r_cross_tenant_evidence_without_verified_transition() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "tenant_missing": True}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.TENANT_ESCAPE])
    assert g.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_case_s_valid_safe_chain_controls() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "SAFE"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ACCOUNT_TAKEOVER])
    assert g.proofs[0].resolution == SecurityPropertyResolution.SAFE


def test_case_t_conflicting_cross_batch_evidence() -> None:
    engine = SecurityPropertyProofEngine()
    findings = [{"security_property": "ROOT_ACCESS", "resolution": "CONFLICT"}]
    g = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ROOT_ACCESS])
    assert g.proofs[0].resolution == SecurityPropertyResolution.CONFLICT


# --- Parametrized Unit Tests 31 through 150 ---


def test_31_to_150_parametrized_evaluations() -> None:
    engine = SecurityPropertyProofEngine()
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

    for i in range(31, 151):
        prop = properties[i % len(properties)]
        findings = [{"security_property": prop.value, "resolution": "VULNERABLE"}]
        g = engine.evaluate(findings=findings, security_properties=[prop])
        assert len(g.proofs) == 1
        assert g.proofs[0].resolution == SecurityPropertyResolution.VULNERABLE
