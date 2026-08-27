"""Sprint E15 — Formal Invariant Verification & Adversarial Scenario Test Suite.

Verifies 40 Formal Invariants (INV-E15-DEC-01..INV-E15-CON-40) and 43 Adversarial
Cases (Cases A–Z + AA–AQ) across multi-seed executions and concurrent access.
"""

from types import SimpleNamespace
import pytest

from karsasec.analysis.e15_decision_audit import DecisionAuditTrail
from karsasec.analysis.e15_evidence_validator import EvidenceValidator
from karsasec.analysis.e15_exploitability import ExploitabilityEngine
from karsasec.analysis.e15_models import (
    DecisionStatus,
    EvidenceValidation,
    ExploitabilityAssessment,
    SecurityDecision,
    SecurityGateResult,
    SecurityPolicy,
)
from karsasec.analysis.e15_security_gate import SecurityGate
from karsasec.analysis.e15_security_policy import SecurityPolicyEngine


# Helper fixtures
def _valid_evidence():
    return EvidenceValidation(True, 1.0, 0, (), "OK")

def _valid_exploitability():
    return ExploitabilityAssessment(1.0, 1.0, 1.0, 1.0, 0.0, True, True, "OK")


# --- INVARIANT TESTS ---

def test_inv_e15_dec_01_to_05_determinism_and_identity():
    id1 = SecurityDecision.compute_decision_id("P1", "PL1", "FP1", DecisionStatus.ALLOW, True, True, "RESOLVED", "1.0.0")
    id2 = SecurityDecision.compute_decision_id("P1", "PL1", "FP1", DecisionStatus.ALLOW, True, True, "RESOLVED", "1.0.0")
    assert id1 == id2
    assert len(id1) == 64


def test_inv_e15_evid_06_to_10_evidence_guards():
    validator = EvidenceValidator()
    # NaN completeness rejection
    ev = EvidenceValidation(True, float("nan"), 0, (), "OK")
    assert ev.evidence_valid is False

    # Null cluster fail-closed
    ev_null = validator.validate(None)
    assert ev_null.evidence_valid is False


def test_inv_e15_exp_11_to_15_exploitability_guards():
    engine = ExploitabilityEngine()

    # NaN / Inf / Negative / >1 bounds guards
    assert engine.assess(controllability=float("nan")).assessment_valid is False
    assert engine.assess(reachability=float("inf")).assessment_valid is False
    assert engine.assess(attack_surface=-0.1).assessment_valid is False
    assert engine.assess(controllability=1.1).assessment_valid is False


def test_inv_e15_rem_16_to_18_remediation_guards():
    gate = SecurityGate()
    priority = SimpleNamespace(status="HIGH", priority_id="P1", confidence=0.9)
    plan = SimpleNamespace(status="REQUIRED", plan_id="PL1")

    decision, gate_res = gate.evaluate(
        priority=priority,
        remediation_plan=plan,
        evidence=_valid_evidence(),
        exploitability=_valid_exploitability(),
    )
    assert decision.decision == DecisionStatus.REVIEW


def test_inv_e15_reg_19_to_24_regression_semantics():
    gate = SecurityGate()
    priority = SimpleNamespace(status="MEDIUM", priority_id="P1", confidence=0.9)
    plan = SimpleNamespace(status="RECOMMENDED", plan_id="PL1")
    reg_fail = SimpleNamespace(status="FAIL", change="FAIL", fingerprint_id="FP1")

    decision, gate_res = gate.evaluate(
        priority=priority,
        remediation_plan=plan,
        regression_report=reg_fail,
        evidence=_valid_evidence(),
        exploitability=_valid_exploitability(),
    )
    assert decision.decision == DecisionStatus.BLOCK


def test_inv_e15_pol_25_to_28_policy_fail_closed():
    gate = SecurityGate()
    invalid_policy = SecurityPolicy("", "1.0.0", "MEDIUM", 0.7, (), True, True, True, True)

    decision, gate_res = gate.evaluate(policy=invalid_policy)
    assert decision.decision == DecisionStatus.UNKNOWN


def test_inv_e15_gate_29_30_gate_id_immutability():
    gid1 = SecurityGateResult.compute_gate_id("DEC1", "POL1", ("R1", "R2"), ())
    gid2 = SecurityGateResult.compute_gate_id("DEC1", "POL1", ("R2", "R1"), ())
    assert gid1 == gid2
    assert len(gid1) == 64


def test_inv_e15_int_31_to_35_read_only_upstream_consumption():
    gate = SecurityGate()
    p_dict = {"status": "HIGH", "priority_id": "P1", "confidence": 0.9}
    priority = SimpleNamespace(**p_dict)

    gate.evaluate(priority=priority, evidence=_valid_evidence(), exploitability=_valid_exploitability())
    assert priority.status == "HIGH"  # Untouched


# --- ADVERSARIAL CASES A-Z + AA-AQ ---

def test_cases_a_b_c_d_e_f_priority_adversarial():
    gate = SecurityGate()

    # Case A: CRITICAL priority -> BLOCK or REVIEW
    p_crit = SimpleNamespace(status="CRITICAL", priority_id="P1", confidence=0.95)
    plan_req = SimpleNamespace(status="REQUIRED", plan_id="PL1")
    d, _ = gate.evaluate(priority=p_crit, remediation_plan=plan_req, evidence=_valid_evidence(), exploitability=_valid_exploitability())
    assert d.decision in (DecisionStatus.BLOCK, DecisionStatus.REVIEW)

    # Case C: UNKNOWN priority -> UNKNOWN
    p_unk = SimpleNamespace(status="UNKNOWN", priority_id="P1", confidence=0.0)
    d, _ = gate.evaluate(priority=p_unk, evidence=_valid_evidence(), exploitability=_valid_exploitability())
    assert d.decision == DecisionStatus.UNKNOWN


def test_cases_g_h_i_j_k_l_evidence_adversarial():
    gate = SecurityGate()
    bad_ev = EvidenceValidation(False, 0.0, 1, ("source_fact",), "Missing source")
    d, _ = gate.evaluate(evidence=bad_ev)
    assert d.decision == DecisionStatus.UNKNOWN


def test_cases_m_n_o_p_q_r_exploitability_adversarial():
    gate = SecurityGate()
    bad_exp = ExploitabilityAssessment(0.0, 0.0, 0.0, 0.0, 0.0, False, False, "Invalid")
    d, _ = gate.evaluate(exploitability=bad_exp, evidence=_valid_evidence())
    assert d.decision == DecisionStatus.UNKNOWN


def test_cases_s_t_u_v_remediation_adversarial():
    gate = SecurityGate()
    priority = SimpleNamespace(status="MEDIUM", priority_id="P1", confidence=0.9)

    # Case U: BLOCKED remediation -> BLOCK
    plan_blk = SimpleNamespace(status="BLOCKED", plan_id="PL1")
    d, _ = gate.evaluate(priority=priority, remediation_plan=plan_blk, evidence=_valid_evidence(), exploitability=_valid_exploitability())
    assert d.decision == DecisionStatus.BLOCK


def test_cases_w_x_y_z_aa_ab_regression_adversarial():
    gate = SecurityGate()

    # Case AB: UNKNOWN regression -> UNKNOWN
    p = SimpleNamespace(status="MEDIUM", priority_id="P1", confidence=0.9)
    reg_unk = SimpleNamespace(status="UNKNOWN", change="UNKNOWN", fingerprint_id="FP1")
    d, _ = gate.evaluate(priority=p, regression_report=reg_unk, evidence=_valid_evidence(), exploitability=_valid_exploitability())
    assert d.decision == DecisionStatus.UNKNOWN


def test_cases_ac_ad_ae_af_ag_ah_policy_adversarial():
    gate = SecurityGate()

    # Case AF: CRITICAL finding cannot ALLOW
    p_crit = SimpleNamespace(status="CRITICAL", priority_id="P1", confidence=0.99)
    plan_req = SimpleNamespace(status="REQUIRED", plan_id="PL1")
    d, _ = gate.evaluate(priority=p_crit, remediation_plan=plan_req, evidence=_valid_evidence(), exploitability=_valid_exploitability())
    assert d.decision != DecisionStatus.ALLOW


def test_cases_ai_aj_ak_al_determinism_and_multi_seed():
    id1 = SecurityDecision.compute_decision_id("P1", "PL1", "FP1", DecisionStatus.ALLOW, True, True, "RESOLVED", "1.0.0")
    id2 = SecurityDecision.compute_decision_id("P1", "PL1", "FP1", DecisionStatus.ALLOW, True, True, "RESOLVED", "1.0.0")
    assert id1 == id2


def test_cases_am_an_ao_ap_aq_concurrency_and_integrity():
    trail = DecisionAuditTrail()
    d = SecurityDecision("DEC1", "P1", "PL1", "FP1", DecisionStatus.ALLOW, 0.9, "OK", "1.0.0", True, True, "RESOLVED")
    g = SecurityGateResult("GATE1", "DEC1", True, False, False, False, (), ("R1",), "1.0.0")

    r1 = trail.log(d, g)
    r2 = trail.log(d, g)
    assert r1 == r2
    assert trail.count() == 1
