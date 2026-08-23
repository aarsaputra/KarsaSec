"""Adversarial Decision Chains DA through DY for Batch D6 Security Decision Engine."""

from karsasec.analysis.correlation.models import SecurityProperty
from karsasec.analysis.decision.engine import SecurityDecisionEngine
from karsasec.analysis.decision.models import DecisionResolution, RiskSeverity


def test_chain_da_duplicate_findings_deduplicated() -> None:
    """Chain DA: Duplicate finding candidates sharing root cause are deduplicated into one canonical finding."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_AUTH"},
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_AUTH"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 1
    assert g.findings[0].resolution == DecisionResolution.VULNERABLE


def test_chain_db_same_timestamp_no_automatic_correlation() -> None:
    """Chain DB: Independent findings with same timestamp remain distinct."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_1"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_chain_dc_same_endpoint_independent_root_causes() -> None:
    """Chain DC: Independent root causes on same endpoint remain separate."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_S1"},
        {"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE", "root_cause_id": "RC_S2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_chain_dd_same_resource_no_false_merging() -> None:
    """Chain DD: Same resource affected by different root causes yields separate findings."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "DATA_EXFILTRATION", "resolution": "VULNERABLE", "root_cause_id": "RC_D1"},
        {"security_property": "PAYMENT_MODIFICATION", "resolution": "VULNERABLE", "root_cause_id": "RC_D2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_chain_de_same_service_isolation() -> None:
    """Chain DE: Multiple findings within same service preserve individual root causes."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_SVC_1"},
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_SVC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_chain_df_different_tenant_isolation() -> None:
    """Chain DF: Findings across different tenants are kept strictly isolated."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "root_cause_id": "RC_TENANT_1"},
        {"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "root_cause_id": "RC_TENANT_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_chain_dg_explicit_same_root_cause_consolidated() -> None:
    """Chain DG: Multiple security properties sharing exact root cause consolidate into one finding."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_SHARED"},
        {"security_property": "CLOUD_ADMIN", "resolution": "VULNERABLE", "root_cause_id": "RC_SHARED"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 1
    assert len(g.findings[0].impact.security_properties) == 2


def test_chain_dh_unrelated_critical_no_severity_contamination() -> None:
    """Chain DH: Unrelated CRITICAL finding does not inflate severity of another finding."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_MEDIUM"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_CRITICAL"},
    ]
    g = engine.analyze(raw_findings=findings)
    f_map = {f.root_cause.node_id: f for f in g.findings}
    assert f_map["RC_MEDIUM"].risk.severity == RiskSeverity.HIGH
    assert f_map["RC_CRITICAL"].risk.severity == RiskSeverity.CRITICAL


def test_chain_di_unknown_proof_preserved() -> None:
    """Chain DI: UNKNOWN D5 proof is preserved as UNKNOWN D6 finding."""
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "SECRET_ACCESS", "resolution": "UNKNOWN", "root_cause_id": "RC_UNK"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


def test_chain_dj_conflict_proof_preserved() -> None:
    """Chain DJ: CONFLICT D5 proof is preserved as CONFLICT D6 finding."""
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ROOT_ACCESS", "resolution": "CONFLICT", "root_cause_id": "RC_CONF"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.CONFLICT


def test_chain_dk_shuffled_input_identical_finding_id() -> None:
    """Chain DK: Shuffled input candidates produce identical canonical finding_id."""
    engine = SecurityDecisionEngine()
    f1 = {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_SAME"}
    f2 = {"security_property": "CLOUD_ADMIN", "resolution": "VULNERABLE", "root_cause_id": "RC_SAME"}
    g1 = engine.analyze(raw_findings=[f1, f2])
    g2 = engine.analyze(raw_findings=[f2, f1])
    assert g1.findings[0].finding_id == g2.findings[0].finding_id


def test_chain_dl_shuffled_evidence_identical_finding_id() -> None:
    """Chain DL: Evidence order does not alter SHA256 finding_id."""
    engine = SecurityDecisionEngine()
    f1 = {"security_property": "SECRET_ACCESS", "resolution": "SAFE", "root_cause_id": "RC_SAFE"}
    g1 = engine.analyze(raw_findings=[f1])
    g2 = engine.analyze(raw_findings=[f1])
    assert g1.findings[0].finding_id == g2.findings[0].finding_id


def test_chain_dm_missing_provenance_unknown() -> None:
    """Chain DM: Missing mandatory evidence yields UNKNOWN."""
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "missing_evidence": True, "root_cause_id": "RC_MISS"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


def test_chain_dn_missing_root_cause_fallback() -> None:
    """Chain DN: Missing explicit root cause falls back safely."""
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "TENANT_ESCAPE", "resolution": "UNKNOWN"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


def test_chain_do_missing_exploit_chain_unknown() -> None:
    """Chain DO: Missing exploit chain yields UNKNOWN decision."""
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ROOT_ACCESS", "resolution": "UNKNOWN"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.UNKNOWN


def test_chain_dp_explicit_safe_proof_safe() -> None:
    """Chain DP: Explicit SAFE proof yields SAFE finding."""
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ADMIN_ACCESS", "resolution": "SAFE", "root_cause_id": "RC_S"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.SAFE


def test_chain_dq_explicit_vulnerable_proof_vulnerable() -> None:
    """Chain DQ: Explicit VULNERABLE proof yields VULNERABLE finding."""
    engine = SecurityDecisionEngine()
    findings = [{"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_V"}]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.VULNERABLE


def test_chain_dr_contradictory_proof_conflict() -> None:
    """Chain DR: Contradictory SAFE/VULNERABLE proofs yield CONFLICT."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ROOT_ACCESS", "resolution": "SAFE", "root_cause_id": "RC_C"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_C"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert g.findings[0].resolution == DecisionResolution.CONFLICT


def test_chain_ds_cross_service_unrelated_isolation() -> None:
    """Chain DS: Unrelated evidence across services is isolated."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "DATA_EXFILTRATION", "resolution": "VULNERABLE", "root_cause_id": "RC_SVC_A"},
        {"security_property": "DATA_EXFILTRATION", "resolution": "SAFE", "root_cause_id": "RC_SVC_B"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_chain_dt_cross_tenant_unrelated_isolation() -> None:
    """Chain DT: Unrelated evidence across tenants is isolated."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "root_cause_id": "RC_T1"},
        {"security_property": "TENANT_ESCAPE", "resolution": "SAFE", "root_cause_id": "RC_T2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_chain_du_same_vulnerability_class_not_same_finding() -> None:
    """Chain DU: Same vulnerability class with different root causes yields separate findings."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_SEC_1"},
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_SEC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_chain_dv_same_cwe_not_same_finding() -> None:
    """Chain DV: Same CWE with different root causes yields separate findings."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "PAYMENT_MODIFICATION", "resolution": "VULNERABLE", "root_cause_id": "RC_PAY_1"},
        {"security_property": "PAYMENT_MODIFICATION", "resolution": "VULNERABLE", "root_cause_id": "RC_PAY_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_chain_dw_same_source_location_separate_root_causes() -> None:
    """Chain DW: Same source location with explicit different root cause IDs yields separate findings."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE", "root_cause_id": "RC_LOC_1"},
        {"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE", "root_cause_id": "RC_LOC_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2


def test_chain_dx_multi_property_single_root_cause() -> None:
    """Chain DX: Multiple security properties from single root cause consolidate into one finding."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_ROOT"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_ROOT"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 1
    assert SecurityProperty.ROOT_ACCESS in g.findings[0].impact.security_properties


def test_chain_dy_independent_root_causes_isolated() -> None:
    """Chain DY: Independent root causes remain strictly isolated."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE", "root_cause_id": "RC_IND_1"},
        {"security_property": "DATA_EXFILTRATION", "resolution": "VULNERABLE", "root_cause_id": "RC_IND_2"},
    ]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 2
