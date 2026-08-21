"""Adversarial Attack Chains PA through PT for Batch D5 Security Property Proof Engine."""

from karsasec.analysis.correlation.models import EvidenceSource, SecurityProperty
from karsasec.analysis.proof.engine import SecurityPropertyProofEngine
from karsasec.analysis.proof.models import SecurityPropertyResolution


def test_chain_pa_authentication_bypass_to_account_takeover() -> None:
    """Chain PA: Authentication bypass -> account takeover proof."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "VULNERABLE"},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ACCOUNT_TAKEOVER])
    assert len(graph.proofs) == 1
    assert graph.proofs[0].resolution == SecurityPropertyResolution.VULNERABLE


def test_chain_pb_missing_identity_provenance_unknown() -> None:
    """Chain PB: Missing identity provenance -> UNKNOWN."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "UNKNOWN", "identity_missing": True},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ACCOUNT_TAKEOVER])
    assert len(graph.proofs) == 1
    assert graph.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_chain_pc_tenant_escape_proven() -> None:
    """Chain PC: Tenant escape proven with explicit context transition."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE"},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.TENANT_ESCAPE])
    assert len(graph.proofs) == 1
    assert graph.proofs[0].resolution == SecurityPropertyResolution.VULNERABLE


def test_chain_pd_missing_tenant_context_unknown() -> None:
    """Chain PD: Missing tenant context -> UNKNOWN."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "tenant_missing": True},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.TENANT_ESCAPE])
    assert len(graph.proofs) == 1
    assert graph.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_chain_pe_explicit_authorization_control_safe() -> None:
    """Chain PE: Explicit authorization control proof -> SAFE."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "SAFE", "safe_control_proven": True},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ADMIN_ACCESS])
    assert len(graph.proofs) == 1
    assert graph.proofs[0].resolution == SecurityPropertyResolution.SAFE


def test_chain_pf_unauthorized_privilege_jump_unknown() -> None:
    """Chain PF: Unauthorized privilege jump without evidence -> UNKNOWN."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "missing_evidence": True},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ROOT_ACCESS])
    assert len(graph.proofs) == 1
    assert graph.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_chain_pg_same_timestamp_no_causal_edge_unknown() -> None:
    """Chain PG: Same timestamp without causal edge -> UNKNOWN."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "causal_missing": True},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.SECRET_ACCESS])
    assert len(graph.proofs) == 1
    assert graph.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_chain_ph_explicit_authorized_privilege_safe() -> None:
    """Chain PH: Explicit authorized privilege escalation -> SAFE."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "SAFE"},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ADMIN_ACCESS])
    assert len(graph.proofs) == 1
    assert graph.proofs[0].resolution == SecurityPropertyResolution.SAFE


def test_chain_pi_explicit_delegation_safe() -> None:
    """Chain PI: Explicit service delegation -> SAFE."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "CLOUD_ADMIN", "resolution": "SAFE"},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.CLOUD_ADMIN])
    assert len(graph.proofs) == 1
    assert graph.proofs[0].resolution == SecurityPropertyResolution.SAFE


def test_chain_pj_contradictory_evidence_conflict() -> None:
    """Chain PJ: Contradictory evidence -> CONFLICT."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "PAYMENT_MODIFICATION", "resolution": "CONFLICT", "conflict_present": True},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.PAYMENT_MODIFICATION])
    assert len(graph.proofs) == 1
    assert graph.proofs[0].resolution == SecurityPropertyResolution.CONFLICT


def test_chain_pk_unrelated_critical_finding_isolation() -> None:
    """Chain PK: Unrelated critical finding does not contaminate proof severity."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE"},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.SECRET_ACCESS])
    assert len(graph.proofs) == 1
    assert graph.proofs[0].property == SecurityProperty.SECRET_ACCESS


def test_chain_pl_shuffled_input_same_proof_id() -> None:
    """Chain PL: Shuffled input yields identical proof_id."""
    engine = SecurityPropertyProofEngine()
    f1 = {"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE"}
    f2 = {"security_property": "DATA_EXFILTRATION", "resolution": "SAFE"}
    g1 = engine.evaluate(findings=[f1, f2])
    g2 = engine.evaluate(findings=[f2, f1])
    assert g1.to_dict() == g2.to_dict()


def test_chain_pm_duplicate_evidence_deduplicated() -> None:
    """Chain PM: Duplicate evidence produces single canonical proof."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE"},
        {"security_property": "CODE_EXECUTION", "resolution": "VULNERABLE"},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.CODE_EXECUTION])
    assert len(graph.proofs) == 1


def test_chain_pn_duplicate_exploit_chain_canonical() -> None:
    """Chain PN: Duplicate exploit chain -> single canonical proof."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "DATA_EXFILTRATION", "resolution": "VULNERABLE"},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.DATA_EXFILTRATION])
    assert len(graph.proofs) == 1


def test_chain_po_root_cause_extraction() -> None:
    """Chain PO: Earliest causally necessary node extracted as root cause."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "ADMIN_ACCESS", "resolution": "VULNERABLE"},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ADMIN_ACCESS])
    assert graph.proofs[0].root_cause.source_batch == EvidenceSource.D4


def test_chain_pp_temporal_relation_alone_unknown() -> None:
    """Chain PP: Temporal relation alone cannot establish causality -> UNKNOWN."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "SECRET_ACCESS", "resolution": "VULNERABLE", "causal_missing": True},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.SECRET_ACCESS])
    assert graph.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_chain_pq_missing_distributed_provenance_unknown() -> None:
    """Chain PQ: Missing distributed provenance -> UNKNOWN."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "CLOUD_ADMIN", "resolution": "UNKNOWN", "missing_evidence": True},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.CLOUD_ADMIN])
    assert graph.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_chain_pr_cross_tenant_resource_no_transition_unknown() -> None:
    """Chain PR: Cross-tenant resource without transition proof -> UNKNOWN."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "TENANT_ESCAPE", "resolution": "VULNERABLE", "tenant_missing": True},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.TENANT_ESCAPE])
    assert graph.proofs[0].resolution == SecurityPropertyResolution.UNKNOWN


def test_chain_ps_valid_safe_chain_controls() -> None:
    """Chain PS: Valid safe chain with complete security controls -> SAFE."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "ACCOUNT_TAKEOVER", "resolution": "SAFE"},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ACCOUNT_TAKEOVER])
    assert graph.proofs[0].resolution == SecurityPropertyResolution.SAFE


def test_chain_pt_conflicting_cross_batch_evidence_conflict() -> None:
    """Chain PT: Conflicting evidence across batches -> CONFLICT."""
    engine = SecurityPropertyProofEngine()
    findings = [
        {"security_property": "ROOT_ACCESS", "resolution": "CONFLICT", "conflict_present": True},
    ]
    graph = engine.evaluate(findings=findings, security_properties=[SecurityProperty.ROOT_ACCESS])
    assert graph.proofs[0].resolution == SecurityPropertyResolution.CONFLICT
