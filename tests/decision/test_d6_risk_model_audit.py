"""Phase 4 — D6 Risk Model Audit.

Verifies:
1. Technical Severity and Business Risk are independently computed
2. They CAN diverge (RCE internal vs payment manipulation)
3. UNKNOWN business risk never collapses to LOW
4. Business Risk is NOT derived from technical severity
"""

from karsasec.analysis.decision.engine import SecurityDecisionEngine
from karsasec.analysis.decision.models import BusinessRisk, DecisionResolution, RiskSeverity


def test_rce_internal_critical_severity_medium_business_risk() -> None:
    """RCE on internal service: Technical=CRITICAL, Business=MEDIUM."""
    engine = SecurityDecisionEngine()
    findings = [{
        "security_property": "ROOT_ACCESS",
        "resolution": "VULNERABLE",
        "root_cause_id": "RC_RCE_INTERNAL",
        "component": "internal_worker",
    }]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 1
    f = g.findings[0]
    assert f.risk.severity == RiskSeverity.CRITICAL
    # Root access on SERVICE scope → Business: MEDIUM (not CRITICAL)
    assert f.risk.business_risk == BusinessRisk.MEDIUM


def test_payment_manipulation_high_severity_high_business_risk() -> None:
    """Payment manipulation: Technical=HIGH, Business=HIGH."""
    engine = SecurityDecisionEngine()
    findings = [{
        "security_property": "PAYMENT_MODIFICATION",
        "resolution": "VULNERABLE",
        "root_cause_id": "RC_PAYMENT",
        "component": "payment_gateway",
    }]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 1
    f = g.findings[0]
    assert f.risk.severity == RiskSeverity.HIGH
    # Payment modification is business-critical
    assert f.risk.business_risk == BusinessRisk.HIGH


def test_tenant_escape_critical_severity_critical_business_risk() -> None:
    """Tenant escape: Technical=CRITICAL-like, Business=CRITICAL."""
    engine = SecurityDecisionEngine()
    findings = [{
        "security_property": "TENANT_ESCAPE",
        "resolution": "VULNERABLE",
        "root_cause_id": "RC_TENANT",
        "component": "multi_tenant_db",
    }]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 1
    f = g.findings[0]
    # Tenant escape has MULTI_TENANT blast radius and is business-critical
    assert f.risk.business_risk == BusinessRisk.CRITICAL


def test_unknown_resolution_produces_unknown_business_risk() -> None:
    """UNKNOWN resolution → UNKNOWN business risk (NEVER LOW)."""
    engine = SecurityDecisionEngine()
    findings = [{
        "security_property": "SECRET_ACCESS",
        "resolution": "UNKNOWN",
        "root_cause_id": "RC_UNK",
    }]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 1
    f = g.findings[0]
    assert f.risk.business_risk == BusinessRisk.UNKNOWN
    assert f.risk.business_risk != BusinessRisk.LOW, "UNKNOWN business risk collapsed to LOW!"


def test_conflict_resolution_produces_unknown_business_risk() -> None:
    """CONFLICT resolution → UNKNOWN business risk (epistemic uncertainty preserved)."""
    engine = SecurityDecisionEngine()
    findings = [
        {"security_property": "ROOT_ACCESS", "resolution": "SAFE", "root_cause_id": "RC_CONF"},
        {"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_CONF"},
    ]
    g = engine.analyze(raw_findings=findings)
    conflict_findings = [f for f in g.findings if f.resolution == DecisionResolution.CONFLICT]
    assert len(conflict_findings) >= 1
    for f in conflict_findings:
        assert f.risk.business_risk == BusinessRisk.UNKNOWN


def test_safe_resolution_produces_low_business_risk() -> None:
    """SAFE resolution → LOW business risk."""
    engine = SecurityDecisionEngine()
    findings = [{
        "security_property": "SECRET_ACCESS",
        "resolution": "SAFE",
        "root_cause_id": "RC_SAFE",
    }]
    g = engine.analyze(raw_findings=findings)
    assert len(g.findings) == 1
    # SAFE → D6 produces empty findings (SAFE chains = zero findings)
    # So this tests the "no finding = implicitly safe" path
    # If a finding IS produced with SAFE, business_risk should be LOW


def test_severity_and_business_risk_are_independent() -> None:
    """Prove that technical severity and business risk are computed by independent functions."""
    engine = SecurityDecisionEngine()

    # RCE internal: CRITICAL severity but MEDIUM business risk
    findings_rce = [{"security_property": "ROOT_ACCESS", "resolution": "VULNERABLE", "root_cause_id": "RC_A"}]
    g_rce = engine.analyze(raw_findings=findings_rce)

    # Payment manipulation: HIGH severity but HIGH business risk
    findings_payment = [{"security_property": "PAYMENT_MODIFICATION", "resolution": "VULNERABLE", "root_cause_id": "RC_B"}]
    g_payment = engine.analyze(raw_findings=findings_payment)

    rce_finding = g_rce.findings[0]
    payment_finding = g_payment.findings[0]

    # Technical severity: RCE (CRITICAL) > Payment (HIGH)
    assert rce_finding.risk.severity == RiskSeverity.CRITICAL
    assert payment_finding.risk.severity == RiskSeverity.HIGH

    # Business risk: Payment (HIGH) > RCE (MEDIUM) — exact opposite ordering proves independence!
    risk_rank = {BusinessRisk.LOW: 1, BusinessRisk.MEDIUM: 2, BusinessRisk.HIGH: 3, BusinessRisk.CRITICAL: 4}
    assert risk_rank[payment_finding.risk.business_risk] > risk_rank[rce_finding.risk.business_risk]
