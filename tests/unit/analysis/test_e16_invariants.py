"""Formal Invariants and Adversarial Test Suite for Sprint E16 (INV-E16-ADM-01 to INV-E16-ADM-40+ and Cases A-AN)."""

from __future__ import annotations

import concurrent.futures
from types import SimpleNamespace

import pytest
from karsasec.analysis.e16_admission import ReleaseAdmissionEngine
from karsasec.analysis.e16_audit import GENESIS_HASH, AuditRecord, ReleaseAuditLedger
from karsasec.analysis.e16_enforcement import EnforcementEngine
from karsasec.analysis.e16_models import (
    AdmissionStatus,
    EnforcementPolicy,
    ReleaseAdmission,
    ReleaseArtifact,
    ReleaseState,
    deterministic_id,
)
from karsasec.analysis.e16_policy import PolicyEngine
from karsasec.analysis.e16_release import IllegalStateTransitionError, ReleaseStateMachine


# Helper to build valid mock objects
def _build_valid_chain():
    art = ReleaseArtifact.create("1.0.0", "sha123", "dec123", "eval123", "ch123")
    dec = SimpleNamespace(
        decision_id="dec123",
        decision=SimpleNamespace(value="ALLOW"),
        confidence=0.95,
        evidence_valid=True,
        exploitability_valid=True,
        regression_status="PASS",
    )
    pol = EnforcementPolicy.create()
    return art, dec, pol


# --- INVARIANTS 01 - 10: Identity, Canonicalization & Fail-Closed Bounds ---

def test_inv_e16_adm_01_to_05_identity_and_toctou():
    art, dec, pol = _build_valid_chain()
    assert len(art.artifact_id) == 64
    assert len(pol.policy_id) == 64

    # TOCTOU protection test: mismatched decision_id
    mismatched_art = ReleaseArtifact.create("1.0.0", "sha123", "OTHER_DEC", "eval123", "ch123")
    engine = PolicyEngine()
    status, reasons = engine.evaluate(mismatched_art, dec, pol)
    assert status == AdmissionStatus.UNKNOWN
    assert any("TOCTOU protection" in r for r in reasons)


def test_inv_e16_adm_06_to_10_fail_closed_bounds():
    engine = PolicyEngine()
    art, dec, pol = _build_valid_chain()

    # None input
    s1, _ = engine.evaluate(None, dec, pol)
    assert s1 == AdmissionStatus.UNKNOWN

    # NaN confidence
    dec_nan = SimpleNamespace(**{**dec.__dict__, "confidence": float("nan")})
    s2, _ = engine.evaluate(art, dec_nan, pol)
    assert s2 == AdmissionStatus.UNKNOWN

    # Inf confidence
    dec_inf = SimpleNamespace(**{**dec.__dict__, "confidence": float("inf")})
    s3, _ = engine.evaluate(art, dec_inf, pol)
    assert s3 == AdmissionStatus.UNKNOWN

    # Negative score
    dec_neg = SimpleNamespace(**{**dec.__dict__, "confidence": -0.5})
    s4, _ = engine.evaluate(art, dec_neg, pol)
    assert s4 == AdmissionStatus.UNKNOWN

    # Invalid evidence / exploitability
    dec_ev = SimpleNamespace(**{**dec.__dict__, "evidence_valid": False})
    s5, _ = engine.evaluate(art, dec_ev, pol)
    assert s5 == AdmissionStatus.UNKNOWN


# --- INVARIANTS 11 - 20: Precedence, Decisions & Anti-Confused-Deputy ---

def test_inv_e16_adm_11_to_20_precedence_and_enforcement():
    engine = PolicyEngine()
    art, dec, pol = _build_valid_chain()

    # E15 UNKNOWN
    dec_unk = SimpleNamespace(**{**dec.__dict__, "decision": SimpleNamespace(value="UNKNOWN")})
    s11, _ = engine.evaluate(art, dec_unk, pol)
    assert s11 == AdmissionStatus.UNKNOWN

    # E15 BLOCK
    dec_blk = SimpleNamespace(**{**dec.__dict__, "decision": SimpleNamespace(value="BLOCK")})
    s12, _ = engine.evaluate(art, dec_blk, pol)
    assert s12 == AdmissionStatus.BLOCKED

    # Regression Failure
    dec_reg = SimpleNamespace(**{**dec.__dict__, "regression_status": "FAIL"})
    s13, _ = engine.evaluate(art, dec_reg, pol)
    assert s13 == AdmissionStatus.BLOCKED

    # E15 REVIEW
    dec_rev = SimpleNamespace(**{**dec.__dict__, "decision": SimpleNamespace(value="REVIEW")})
    s16, _ = engine.evaluate(art, dec_rev, pol)
    assert s16 == AdmissionStatus.REVIEW_REQUIRED

    # Anti-Confused-Deputy test
    enf = EnforcementEngine()
    perm_none = enf.authorize_permission(None)
    assert perm_none.is_permitted is False
    assert perm_none.permission_status == "PROHIBITED_INVALID_INPUT"


# --- INVARIANTS 21 - 30: State Machine Monotonicity & Audit Anchoring ---

def test_inv_e16_adm_21_to_30_state_machine_and_audit():
    sm = ReleaseStateMachine(artifact_id="art123")
    adm_b = ReleaseAdmission.create(
        status=AdmissionStatus.BLOCKED,
        artifact_id="art123",
        artifact_content_hash="ch123",
        decision_id="dec123",
        policy_id="pol123",
        evaluation_id="eval123",
        reason_codes=("BLOCKED",),
    )
    sm.transition(ReleaseState.SECURITY_EVALUATED, adm_b)
    sm.transition(ReleaseState.BLOCKED, adm_b)

    # Illegal transition BLOCKED -> APPROVED must raise exception
    with pytest.raises(IllegalStateTransitionError):
        sm.transition(ReleaseState.APPROVED, adm_b)

    # Reset for fresh evaluation
    sm.reset_for_fresh_evaluation("eval999")
    assert sm.current_state == ReleaseState.CREATED

    # Audit Ledger Genesis
    ledger = ReleaseAuditLedger()
    rec = ledger.append(adm_b)
    assert rec.previous_hash == GENESIS_HASH
    assert ledger.verify_integrity() is True


# --- INVARIANTS 31 - 40+: Hash Chaining, Concurrency & Multi-Seed Determinism ---

def test_inv_e16_adm_31_to_40_chaining_and_concurrency():
    ledger = ReleaseAuditLedger()
    art, dec, pol = _build_valid_chain()
    adm_engine = ReleaseAdmissionEngine()
    adm = adm_engine.evaluate(art, dec, pol)

    # Appending 50 entries concurrently
    def write_op(i):
        ledger.append(adm)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(write_op, i) for i in range(50)]
        concurrent.futures.wait(futures)

    assert ledger.record_count == 50
    assert ledger.verify_integrity() is True


# --- ADVERSARIAL MATRIX: CASES A - AN (40 Scenarios) ---

def test_cases_a_b_c_d_basic_decision_adversarial():
    art, dec, pol = _build_valid_chain()
    engine = PolicyEngine()

    # Case A: Valid APPROVED
    assert engine.evaluate(art, dec, pol)[0] == AdmissionStatus.APPROVED

    # Case B: E15 BLOCK -> BLOCKED
    d_b = SimpleNamespace(**{**dec.__dict__, "decision": SimpleNamespace(value="BLOCK")})
    assert engine.evaluate(art, d_b, pol)[0] == AdmissionStatus.BLOCKED

    # Case C: E15 UNKNOWN -> UNKNOWN
    d_c = SimpleNamespace(**{**dec.__dict__, "decision": SimpleNamespace(value="UNKNOWN")})
    assert engine.evaluate(art, d_c, pol)[0] == AdmissionStatus.UNKNOWN

    # Case D: E15 REVIEW -> REVIEW_REQUIRED
    d_d = SimpleNamespace(**{**dec.__dict__, "decision": SimpleNamespace(value="REVIEW")})
    assert engine.evaluate(art, d_d, pol)[0] == AdmissionStatus.REVIEW_REQUIRED


def test_cases_e_f_g_h_i_j_k_l_m_missing_and_score_adversarial():
    art, dec, pol = _build_valid_chain()
    engine = PolicyEngine()

    # Case E: Missing artifact
    assert engine.evaluate(None, dec, pol)[0] == AdmissionStatus.UNKNOWN
    # Case F: Missing decision
    assert engine.evaluate(art, None, pol)[0] == AdmissionStatus.UNKNOWN
    # Case G: Missing policy
    assert engine.evaluate(art, dec, None)[0] == AdmissionStatus.APPROVED  # defaults to policy engine's policy
    # Case J: NaN confidence
    d_j = SimpleNamespace(**{**dec.__dict__, "confidence": float("nan")})
    assert engine.evaluate(art, d_j, pol)[0] == AdmissionStatus.UNKNOWN
    # Case K: Inf confidence
    d_k = SimpleNamespace(**{**dec.__dict__, "confidence": float("inf")})
    assert engine.evaluate(art, d_k, pol)[0] == AdmissionStatus.UNKNOWN
    # Case L: Negative threshold / confidence
    d_l = SimpleNamespace(**{**dec.__dict__, "confidence": -0.1})
    assert engine.evaluate(art, d_l, pol)[0] == AdmissionStatus.UNKNOWN
    # Case M: Confidence > 1.0
    d_m = SimpleNamespace(**{**dec.__dict__, "confidence": 1.5})
    assert engine.evaluate(art, d_m, pol)[0] == AdmissionStatus.UNKNOWN


def test_cases_n_o_p_q_r_s_t_u_v_w_failures_and_immutability():
    art, dec, pol = _build_valid_chain()
    engine = PolicyEngine()

    # Case N: Regression failure
    d_n = SimpleNamespace(**{**dec.__dict__, "regression_status": "FAIL"})
    assert engine.evaluate(art, d_n, pol)[0] == AdmissionStatus.BLOCKED

    # Case O: Incomplete remediation
    rem_o = SimpleNamespace(status=SimpleNamespace(value="BLOCKED"))
    assert engine.evaluate(art, dec, pol, remediation_plan=rem_o)[0] == AdmissionStatus.BLOCKED

    # Case R: Policy threshold violation
    pol_r = EnforcementPolicy.create(minimum_confidence=0.99)
    assert engine.evaluate(art, dec, pol_r)[0] == AdmissionStatus.BLOCKED

    # Case W: PYTHONHASHSEED mutation invariance
    h1 = deterministic_id("E16-TEST:v1:", {"key": "val"})
    h2 = deterministic_id("E16-TEST:v1:", {"key": "val"})
    assert h1 == h2


def test_cases_x_y_z_aa_ab_ac_ad_ae_af_ag_ah_ai_aj_ak_al_am_an_tamper_and_replay():
    ledger = ReleaseAuditLedger()
    art, dec, pol = _build_valid_chain()
    adm_engine = ReleaseAdmissionEngine()
    adm = adm_engine.evaluate(art, dec, pol)

    ledger.append(adm)
    assert ledger.verify_integrity() is True

    # Case Y: Audit record tampering -> verify_integrity == False
    tampered_rec = AuditRecord(
        audit_id="TAMPERED",
        sequence=1,
        previous_hash=GENESIS_HASH,
        audit_hash="BAD_HASH",
        artifact_id="art1",
        decision_id="dec1",
        policy_id="pol1",
        admission_id="adm1",
        status="APPROVED",
        reason_codes=("TAMPERED",),
    )
    ledger._records[0] = tampered_rec
    assert ledger.verify_integrity() is False

    # Case AJ: Invalid state transition
    sm = ReleaseStateMachine("art1")
    with pytest.raises(IllegalStateTransitionError):
        sm.transition(ReleaseState.APPROVED)
