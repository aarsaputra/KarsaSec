"""Adversarial Attack Chains CA through CO for Batch D4 Cross-Batch Security Correlation Engine."""

from karsasec.analysis.correlation.engine import CrossBatchCorrelationEngine
from karsasec.analysis.correlation.models import (
    CorrelationResolution,
    SecurityProperty,
)


def test_chain_ca_ssrf_to_cloud_admin() -> None:
    """Chain CA: SSRF -> internal service -> auth bypass -> cloud admin."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "C13", "correlation_id": "CORR_CA", "resolution": "VULNERABLE", "security_property": "CLOUD_ADMIN"},
        {"source_batch": "D1", "correlation_id": "CORR_CA", "resolution": "VULNERABLE", "security_property": "CLOUD_ADMIN"},
        {"source_batch": "D3", "correlation_id": "CORR_CA", "resolution": "VULNERABLE", "security_property": "CLOUD_ADMIN"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].resolution == CorrelationResolution.VULNERABLE
    assert graph.exploit_chains[0].security_property == SecurityProperty.CLOUD_ADMIN


def test_chain_cb_idor_to_tenant_escape() -> None:
    """Chain CB: IDOR -> tenant context loss -> tenant escape."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "C14", "correlation_id": "CORR_CB", "resolution": "VULNERABLE", "security_property": "TENANT_ESCAPE"},
        {"source_batch": "D3", "correlation_id": "CORR_CB", "resolution": "VULNERABLE", "security_property": "TENANT_ESCAPE"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].security_property == SecurityProperty.TENANT_ESCAPE


def test_chain_cc_stale_cache_async_worker() -> None:
    """Chain CC: Stale privilege cache -> async worker -> admin action."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "D2", "correlation_id": "CORR_CC", "resolution": "VULNERABLE", "security_property": "ADMIN_ACCESS"},
        {"source_batch": "D3", "correlation_id": "CORR_CC", "resolution": "VULNERABLE", "security_property": "ADMIN_ACCESS"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].resolution == CorrelationResolution.VULNERABLE


def test_chain_cd_gateway_bypass_backend_trust() -> None:
    """Chain CD: Gateway bypass -> backend trust -> privilege escalation."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "D1", "correlation_id": "CORR_CD", "resolution": "VULNERABLE", "security_property": "ADMIN_ACCESS"},
        {"source_batch": "D3", "correlation_id": "CORR_CD", "resolution": "VULNERABLE", "security_property": "ADMIN_ACCESS"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].resolution == CorrelationResolution.VULNERABLE


def test_chain_ce_message_context_identity_confusion() -> None:
    """Chain CE: Message context loss -> service identity confusion -> admin."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "D3", "correlation_id": "CORR_CE", "resolution": "VULNERABLE", "security_property": "ADMIN_ACCESS"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].resolution == CorrelationResolution.VULNERABLE


def test_chain_cf_delegated_token_missing_revocation() -> None:
    """Chain CF: Delegated token -> missing revocation -> privileged action."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "D2", "correlation_id": "CORR_CF", "resolution": "VULNERABLE", "security_property": "SECRET_ACCESS"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].resolution == CorrelationResolution.VULNERABLE


def test_chain_cg_toctou_authz_mutation() -> None:
    """Chain CG: TOCTOU -> authorization mutation -> privileged resource access."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "D2", "correlation_id": "CORR_CG", "resolution": "VULNERABLE", "security_property": "DATA_EXFILTRATION"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].resolution == CorrelationResolution.VULNERABLE


def test_chain_ch_replay_sensitive_workflow() -> None:
    """Chain CH: Replay -> sensitive workflow -> payment modification."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "D3", "correlation_id": "CORR_CH", "resolution": "VULNERABLE", "security_property": "PAYMENT_MODIFICATION"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].security_property == SecurityProperty.PAYMENT_MODIFICATION


def test_chain_ci_service_impersonation() -> None:
    """Chain CI: Service impersonation -> missing provenance -> admin access."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "D3", "correlation_id": "CORR_CI", "resolution": "VULNERABLE", "security_property": "ADMIN_ACCESS"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].resolution == CorrelationResolution.VULNERABLE


def test_chain_cj_multi_service_sod_bypass() -> None:
    """Chain CJ: Multi-service SoD bypass."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "D3", "correlation_id": "CORR_CJ", "resolution": "VULNERABLE", "security_property": "PAYMENT_MODIFICATION"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].resolution == CorrelationResolution.VULNERABLE


def test_chain_ck_defense_in_depth_failure() -> None:
    """Chain CK: Defense-in-depth failure across gateway/backend."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "D3", "correlation_id": "CORR_CK", "resolution": "VULNERABLE", "security_property": "ACCOUNT_TAKEOVER"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].security_property == SecurityProperty.ACCOUNT_TAKEOVER


def test_chain_cl_cross_service_secret_access() -> None:
    """Chain CL: Cross-service secret access."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "C15", "correlation_id": "CORR_CL", "resolution": "VULNERABLE", "security_property": "SECRET_ACCESS"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].security_property == SecurityProperty.SECRET_ACCESS


def test_chain_cm_incomplete_evidence_unknown() -> None:
    """Chain CM: Incomplete evidence expects UNKNOWN resolution."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "D1", "correlation_id": "MISSING_CORRELATION", "resolution": "UNKNOWN", "security_property": "UNKNOWN"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].resolution == CorrelationResolution.UNKNOWN


def test_chain_cn_contradictory_evidence_conflict() -> None:
    """Chain CN: Contradictory evidence yields CORRELATION_CONFLICT / UNKNOWN."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "D1", "correlation_id": "CORR_CN", "resolution": "SAFE", "conflict_present": True},
        {"source_batch": "D3", "correlation_id": "CORR_CN", "resolution": "VULNERABLE", "conflict_present": True},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 1
    assert graph.exploit_chains[0].resolution == CorrelationResolution.UNKNOWN


def test_chain_co_explicit_authorization_delegation_safe() -> None:
    """Chain CO: Explicit authorization and delegation expects SAFE (zero exploit chains)."""
    engine = CrossBatchCorrelationEngine()
    findings = [
        {"source_batch": "D3", "correlation_id": "CORR_CO", "resolution": "SAFE"},
    ]
    graph = engine.correlate(findings=findings)
    assert len(graph.exploit_chains) == 0  # SAFE
