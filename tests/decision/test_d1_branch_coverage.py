"""Phase 1 — D1 Branch Coverage Tests.

Targets uncovered invariant decision branches in SecurityInvariantEngine.
Focus: invariant types AUTHORITY, RESOURCE_OWNERSHIP, DELEGATION, LIFECYCLE,
CONSISTENCY, SEPARATION_OF_DUTY, DEFENSE_IN_DEPTH, and UNKNOWN/CONFLICT transitions.
"""

from karsasec.analysis.breach_simulation.models import BreachScenario, ConfidenceLevel, RiskLevel, ScenarioType, SimulationStatus
from karsasec.analysis.invariants.engine import SecurityInvariantEngine
from karsasec.analysis.invariants.models import InvariantEvidence, InvariantType
from karsasec.analysis.privilege.models import EscalationCategory, PrivilegeEvidence


def test_d1_privilege_boundary_violated() -> None:
    engine = SecurityInvariantEngine()
    ev = InvariantEvidence(
        evidence_id="EV_PRIV_01",
        invariant_type=InvariantType.PRIVILEGE_BOUNDARY,
        source_boundary="USER",
        target_boundary="ADMIN",
        initial_state="USER",
        resulting_state="ADMIN",
        proof_present=False,
    )
    viols = engine.evaluate_invariants(evidence_item=ev)
    assert any(v.category == "PRIVILEGE_BOUNDARY_VIOLATION" for v in viols)


def test_d1_authority_violated() -> None:
    engine = SecurityInvariantEngine()
    ev = InvariantEvidence(
        evidence_id="EV_AUTH_01",
        invariant_type=InvariantType.AUTHORITY,
        source_boundary="USER",
        target_boundary="ADMIN_ACTION",
        initial_state="NORMAL",
        resulting_state="MODIFIED",
        proof_present=False,
    )
    viols = engine.evaluate_invariants(evidence_item=ev)
    assert any(v.category == "AUTHORITY_VIOLATION" for v in viols)


def test_d1_resource_ownership_violated() -> None:
    engine = SecurityInvariantEngine()
    ev = InvariantEvidence(
        evidence_id="EV_OWNR_01",
        invariant_type=InvariantType.RESOURCE_OWNERSHIP,
        source_boundary="USER_A",
        target_boundary="USER_B_RESOURCE",
        initial_state="OWNER_B",
        resulting_state="ACCESSED_BY_A",
        proof_present=False,
    )
    viols = engine.evaluate_invariants(evidence_item=ev)
    assert any(v.category == "RESOURCE_OWNERSHIP_VIOLATION" for v in viols)


def test_d1_delegation_violated() -> None:
    engine = SecurityInvariantEngine()
    ev = InvariantEvidence(
        evidence_id="EV_DELEG_01",
        invariant_type=InvariantType.DELEGATION,
        source_boundary="USER",
        target_boundary="SERVICE_ACCOUNT",
        initial_state="USER",
        resulting_state="SERVICE_ACCOUNT",
        proof_present=False,
    )
    viols = engine.evaluate_invariants(evidence_item=ev)
    assert any(v.category == "DELEGATION_CHAIN_VIOLATION" for v in viols)


def test_d1_lifecycle_violated() -> None:
    engine = SecurityInvariantEngine()
    ev = InvariantEvidence(
        evidence_id="EV_LIFE_01",
        invariant_type=InvariantType.LIFECYCLE,
        source_boundary="TOKEN_GEN",
        target_boundary="TOKEN_REUSE",
        initial_state="VALID",
        resulting_state="EXPIRED_REUSED",
        proof_present=False,
    )
    viols = engine.evaluate_invariants(evidence_item=ev)
    assert any(v.category == "LIFECYCLE_INVARIANT_VIOLATION" for v in viols)


def test_d1_consistency_violated() -> None:
    engine = SecurityInvariantEngine()
    ev = InvariantEvidence(
        evidence_id="EV_CONS_01",
        invariant_type=InvariantType.CONSISTENCY,
        source_boundary="GATEWAY",
        target_boundary="BACKEND",
        initial_state="GATEWAY_ALLOW",
        resulting_state="BACKEND_ALLOW",
        proof_present=False,
    )
    viols = engine.evaluate_invariants(evidence_item=ev)
    assert any(v.category == "CONSISTENCY_INVARIANT_VIOLATION" for v in viols)


def test_d1_separation_of_duty_violated() -> None:
    engine = SecurityInvariantEngine()
    ev = InvariantEvidence(
        evidence_id="EV_SOD_01",
        invariant_type=InvariantType.SEPARATION_OF_DUTY,
        source_boundary="PAYMENT",
        target_boundary="APPROVAL",
        initial_state="CREATE",
        resulting_state="APPROVE",
        proof_present=False,
    )
    viols = engine.evaluate_invariants(evidence_item=ev)
    assert any(v.category == "SEPARATION_OF_DUTY_VIOLATION" for v in viols)


def test_d1_defense_in_depth_violated() -> None:
    engine = SecurityInvariantEngine()
    ev = InvariantEvidence(
        evidence_id="EV_DID_01",
        invariant_type=InvariantType.DEFENSE_IN_DEPTH,
        source_boundary="AUTHN",
        target_boundary="AUTHZ",
        initial_state="AUTHN_PRESENT",
        resulting_state="AUTHZ_MISSING",
        proof_present=False,
    )
    viols = engine.evaluate_invariants(evidence_item=ev)
    assert any(v.category == "DEFENSE_IN_DEPTH_VIOLATION" for v in viols)


def test_d1_state_machine_unauthenticated_to_privileged() -> None:
    engine = SecurityInvariantEngine()
    ev = InvariantEvidence(
        evidence_id="EV_SM_01",
        invariant_type=InvariantType.STATE_TRANSITION,
        source_boundary="AUTH_GATE",
        target_boundary="PRIVILEGED_ZONE",
        initial_state="UNAUTHENTICATED",
        resulting_state="PRIVILEGED",
        proof_present=False,
    )
    viols = engine.evaluate_invariants(evidence_item=ev)
    assert any(v.category == "STATE_MACHINE_VIOLATION" for v in viols)


def test_d1_privilege_evidence_unknown_produces_unknown_violation() -> None:
    engine = SecurityInvariantEngine()
    priv_ev = PrivilegeEvidence(
        category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
        initial_identity="user_a",
        initial_privilege="LOW",
        transition_trigger="unknown_action",
        authorization_boundary="API_GATEWAY",
        resulting_identity="user_a",
        resulting_privilege="LOW",
        authorization_verified=False,
        tenant_scope_verified=False,
        evidence_path=["step1"],
        resolution="UNKNOWN",
    )
    viols = engine.evaluate_invariants(privilege_evidence=priv_ev)
    assert any(v.resolution == "UNKNOWN" for v in viols)


def test_d1_privilege_evidence_vulnerable_boundary_crossed() -> None:
    engine = SecurityInvariantEngine()
    priv_ev = PrivilegeEvidence(
        category=EscalationCategory.VERTICAL_PRIVILEGE_ESCALATION,
        initial_identity="user_a",
        initial_privilege="LOW",
        transition_trigger="priv_escalation",
        authorization_boundary="API_GATEWAY",
        resulting_identity="admin",
        resulting_privilege="ADMIN",
        authorization_verified=False,
        tenant_scope_verified=False,
        evidence_path=["step1", "step2"],
        resolution="VULNERABLE",
    )
    viols = engine.evaluate_invariants(privilege_evidence=priv_ev)
    assert any(v.category == "PRIVILEGE_BOUNDARY_VIOLATION" for v in viols)


def test_d1_breach_scenario_unknown() -> None:
    engine = SecurityInvariantEngine()
    bs = BreachScenario(
        scenario_id="BS_01",
        scenario_type=ScenarioType.UNKNOWN_SCENARIO,
        root_causes=("RC_01",),
        capabilities=(),
        impacts=(),
        steps=(),
        privilege_transition=None,
        business_impact=(),
        risk_factors=(),
        risk_score=None,
        risk_level=RiskLevel.UNKNOWN,
        confidence=ConfidenceLevel.UNKNOWN,
        resolution=SimulationStatus.UNKNOWN,
        evidence_ids=(),
        evidence_path=("E1",),
    )
    viols = engine.evaluate_invariants(breach_scenario=bs)
    assert any(v.resolution == "UNKNOWN" for v in viols)


def test_d1_breach_scenario_tenant_escape() -> None:
    engine = SecurityInvariantEngine()
    bs = BreachScenario(
        scenario_id="BS_02",
        scenario_type=ScenarioType.TENANT_BOUNDARY_BREACH,
        root_causes=("RC_02",),
        capabilities=("TENANT_BOUNDARY_ESCAPE",),
        impacts=("TENANT_WIPE",),
        steps=(),
        privilege_transition=None,
        business_impact=(),
        risk_factors=(),
        risk_score=0.9,
        risk_level=RiskLevel.CRITICAL,
        confidence=ConfidenceLevel.HIGH,
        resolution=SimulationStatus.VULNERABLE,
        evidence_ids=(),
        evidence_path=("E1", "E2"),
    )
    viols = engine.evaluate_invariants(breach_scenario=bs)
    assert any(v.category == "TENANT_ISOLATION_FAILURE" for v in viols)


def test_d1_no_evidence_produces_no_violations() -> None:
    engine = SecurityInvariantEngine()
    viols = engine.evaluate_invariants()
    assert viols == []


def test_d1_findings_unknown_resolution() -> None:
    engine = SecurityInvariantEngine()
    findings = [{"resolution": "UNKNOWN", "rule_id": "RULE_01"}]
    viols = engine.evaluate_invariants(findings=findings)
    assert any(v.resolution == "UNKNOWN" for v in viols)


def test_d1_findings_vulnerable_resolution() -> None:
    engine = SecurityInvariantEngine()
    findings = [{"resolution": "VULNERABLE", "rule_id": "RULE_02", "category": "INJECTION"}]
    viols = engine.evaluate_invariants(findings=findings)
    assert any(v.resolution == "VULNERABLE" for v in viols)


def test_d1_proof_present_produces_no_violation() -> None:
    """When proof_present=True, the invariant is satisfied and no violation is created."""
    engine = SecurityInvariantEngine()
    ev = InvariantEvidence(
        evidence_id="EV_SAFE",
        invariant_type=InvariantType.TRUST_BOUNDARY,
        source_boundary="A",
        target_boundary="B",
        initial_state="X",
        resulting_state="Y",
        proof_present=True,
    )
    viols = engine.evaluate_invariants(evidence_item=ev)
    assert not any(v.category == "TRUST_BOUNDARY_VIOLATION" for v in viols)
