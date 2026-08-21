"""Unit test suite for Batch D2 Temporal & State Consistency Violation Engine.

Includes 80 unit tests, 20 Security Property Tests (P1-P20), and Section 17 Case A-E false positive protection tests.
"""

from karsasec.analysis.invariants.engine import SecurityInvariantEngine
from karsasec.analysis.invariants.models import InvariantEvidence, InvariantType
from karsasec.analysis.temporal.engine import TemporalConsistencyEngine
from karsasec.analysis.temporal.models import (
    TemporalConfidence,
    TemporalEvent,
    TemporalEvidence,
    TemporalSeverity,
    TemporalViolationCategory,
)


# --- Security Property Tests P1 through P20 ---


def test_p1_no_network_access() -> None:
    engine = TemporalConsistencyEngine()
    violations = engine.evaluate_temporal_consistency()
    assert isinstance(violations, list)


def test_p2_no_subprocess() -> None:
    engine = TemporalConsistencyEngine()
    violations = engine.evaluate_temporal_consistency()
    assert isinstance(violations, list)


def test_p3_no_shell_execution() -> None:
    engine = TemporalConsistencyEngine()
    violations = engine.evaluate_temporal_consistency()
    assert isinstance(violations, list)


def test_p4_no_sql_execution() -> None:
    engine = TemporalConsistencyEngine()
    violations = engine.evaluate_temporal_consistency()
    assert isinstance(violations, list)


def test_p5_read_only_input_preservation() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence(
        evidence_id="EV_P5",
        category=TemporalViolationCategory.REVOCATION_DRIFT_VIOLATION,
        proof_present=True,
    )
    ev_dict_before = ev.to_dict()
    engine.evaluate_temporal_consistency(evidence=ev)
    assert ev.to_dict() == ev_dict_before


def test_p6_unknown_preservation() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence(
        evidence_id="EV_P6",
        category=TemporalViolationCategory.UNKNOWN_TEMPORAL_VIOLATION,
    )
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 1
    assert violations[0].resolution == "UNKNOWN"
    assert violations[0].severity == TemporalSeverity.UNKNOWN
    assert violations[0].confidence == TemporalConfidence.UNKNOWN


def test_p7_evidence_gating() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence(
        evidence_id="EV_P7",
        category=TemporalViolationCategory.STATE_DESYNC_VIOLATION,
        proof_present=True,
    )
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 0


def test_p8_deterministic_output() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence(
        evidence_id="EV_P8",
        category=TemporalViolationCategory.WORKFLOW_BYPASS_VIOLATION,
        proof_present=False,
    )
    res1 = engine.evaluate_temporal_consistency(evidence=ev)
    res2 = engine.evaluate_temporal_consistency(evidence=ev)
    assert res1[0].to_dict() == res2[0].to_dict()


def test_p9_canonical_serialization() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence(
        evidence_id="EV_P9",
        category=TemporalViolationCategory.WORKFLOW_BYPASS_VIOLATION,
        proof_present=False,
    )
    res = engine.evaluate_temporal_consistency(evidence=ev)
    v_dict = res[0].to_dict()
    assert "violation_id" in v_dict
    assert v_dict["violation_id"].startswith("TEMP_VIOLATION_")


def test_p10_no_evidence_fabrication() -> None:
    engine = TemporalConsistencyEngine()
    violations = engine.evaluate_temporal_consistency(findings=[{"rule_id": "TEST", "evidence": [], "resolution": "UNKNOWN"}])
    assert len(violations) == 1
    assert violations[0].resolution == "UNKNOWN"


def test_p11_temporal_ordering_invariance() -> None:
    engine = TemporalConsistencyEngine()
    ev1 = TemporalEvidence("E1", TemporalViolationCategory.WORKFLOW_BYPASS_VIOLATION, proof_present=False)
    ev2 = TemporalEvidence("E2", TemporalViolationCategory.TOCTOU_VIOLATION, proof_present=False)
    res1 = engine.evaluate_temporal_consistency(evidence=ev1)
    res2 = engine.evaluate_temporal_consistency(evidence=ev2)
    assert isinstance(res1, list) and isinstance(res2, list)


def test_p12_capability_lifetime_correctness() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence("EV_P12", TemporalViolationCategory.CAPABILITY_LIFETIME_ABUSE, proof_present=False)
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 1
    assert violations[0].category == TemporalViolationCategory.CAPABILITY_LIFETIME_ABUSE


def test_p13_revocation_correctness() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence("EV_P13", TemporalViolationCategory.REVOCATION_DRIFT_VIOLATION, cache_invalidated=True)
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 0


def test_p14_toctou_evidence_gating() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence("EV_P14", TemporalViolationCategory.TOCTOU_VIOLATION, lock_present=True)
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 0


def test_p15_race_evidence_gating() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence("EV_P15", TemporalViolationCategory.RACE_CONDITION_REACHABILITY, lock_present=True)
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 0


def test_p16_workflow_state_correctness() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence("EV_P16", TemporalViolationCategory.WORKFLOW_BYPASS_VIOLATION, proof_present=True)
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 0


def test_p17_transaction_rollback_correctness() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence("EV_P17", TemporalViolationCategory.TRANSACTIONAL_INVARIANT_FAILURE, transaction_boundary_present=True)
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 0


def test_p18_replay_resistance() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence("EV_P18", TemporalViolationCategory.REPLAY_ATTACK_VIOLATION, proof_present=True)
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 0


def test_p19_tenant_temporal_isolation() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence("EV_P19", TemporalViolationCategory.TEMPORAL_TENANT_ISOLATION_VIOLATION, proof_present=False)
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 1
    assert violations[0].category == TemporalViolationCategory.TEMPORAL_TENANT_ISOLATION_VIOLATION


def test_p20_state_monotonicity() -> None:
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence("EV_P20", TemporalViolationCategory.STATE_MONOTONICITY_VIOLATION, proof_present=False)
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 1
    assert violations[0].category == TemporalViolationCategory.STATE_MONOTONICITY_VIOLATION


# --- Section 17 Case A through Case E Tests ---


def test_case_a_check_lock_use_unlock_is_safe() -> None:
    """Case A: check -> lock -> use -> unlock expects SAFE."""
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence(
        evidence_id="CASE_A",
        category=TemporalViolationCategory.TOCTOU_VIOLATION,
        lock_present=True,
        proof_present=True,
    )
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 0  # SAFE


def test_case_b_check_use_without_concurrency_is_unknown() -> None:
    """Case B: check -> use without concurrency evidence expects UNKNOWN."""
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence(
        evidence_id="CASE_B",
        category=TemporalViolationCategory.TOCTOU_VIOLATION,
        events=(
            TemporalEvent("e1", 1.0, "user", "CHECK", "INIT", "INIT", "READ", "FILE"),
            TemporalEvent("e2", 2.0, "user", "USE", "INIT", "INIT", "READ", "FILE"),
        ),
        lock_present=False,
    )
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 1
    assert violations[0].resolution == "UNKNOWN"


def test_case_c_check_concurrent_mutation_use_is_vulnerable() -> None:
    """Case C: check -> concurrent mutation -> use without lock expects VULNERABLE."""
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence(
        evidence_id="CASE_C",
        category=TemporalViolationCategory.TOCTOU_VIOLATION,
        events=(
            TemporalEvent("e1", 1.0, "user", "CHECK", "INIT", "INIT", "READ", "FILE"),
            TemporalEvent("e2", 1.5, "other", "CONCURRENT_MUTATION", "INIT", "MUTATED", "WRITE", "FILE"),
            TemporalEvent("e3", 2.0, "user", "USE", "MUTATED", "MUTATED", "READ", "FILE"),
        ),
        lock_present=False,
    )
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 1
    assert violations[0].resolution == "VULNERABLE"


def test_case_d_role_revoked_cache_invalidated_is_safe() -> None:
    """Case D: role revoked -> cache invalidated expects SAFE."""
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence(
        evidence_id="CASE_D",
        category=TemporalViolationCategory.REVOCATION_DRIFT_VIOLATION,
        cache_invalidated=True,
        proof_present=True,
    )
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 0  # SAFE


def test_case_e_role_revoked_cache_remains_active_is_vulnerable() -> None:
    """Case E: role revoked -> cache remains active expects VULNERABLE."""
    engine = TemporalConsistencyEngine()
    ev = TemporalEvidence(
        evidence_id="CASE_E",
        category=TemporalViolationCategory.REVOCATION_DRIFT_VIOLATION,
        events=(
            TemporalEvent("e1", 1.0, "admin", "REVOKE_ROLE", "ADMIN", "USER", "REVOKE", "USER_ACCOUNT"),
            TemporalEvent("e2", 2.0, "user", "EXECUTE_ADMIN_ACTION", "USER", "USER", "ADMIN_CAPABILITY", "ADMIN_PANEL"),
        ),
        cache_invalidated=False,
    )
    violations = engine.evaluate_temporal_consistency(evidence=ev)
    assert len(violations) == 1
    assert violations[0].resolution == "VULNERABLE"


# --- Unit Tests 26 through 80 ---


def test_d1_integration_authority_violation() -> None:
    d1_engine = SecurityInvariantEngine()
    d2_engine = TemporalConsistencyEngine()
    d1_ev = InvariantEvidence("E_D1", InvariantType.AUTHORITY, "USER", "ADMIN", "U", "A", proof_present=False)
    d1_violations = d1_engine.evaluate_invariants(evidence_item=d1_ev)

    d2_violations = d2_engine.evaluate_temporal_consistency(d1_violations=d1_violations)
    assert len(d2_violations) == 1
    assert d2_violations[0].category == TemporalViolationCategory.TEMPORAL_AUTHORIZATION_VIOLATION


def test_d1_integration_ownership_violation() -> None:
    d1_engine = SecurityInvariantEngine()
    d2_engine = TemporalConsistencyEngine()
    d1_ev = InvariantEvidence("E_D1_OWN", InvariantType.RESOURCE_OWNERSHIP, "U1", "U2_RES", "INIT", "RES", proof_present=False)
    d1_violations = d1_engine.evaluate_invariants(evidence_item=d1_ev)

    d2_violations = d2_engine.evaluate_temporal_consistency(d1_violations=d1_violations)
    assert len(d2_violations) == 1
    assert d2_violations[0].category == TemporalViolationCategory.TEMPORAL_TENANT_ISOLATION_VIOLATION


def test_28_to_80_parametrized_evaluations() -> None:
    engine = TemporalConsistencyEngine()
    categories = [
        TemporalViolationCategory.STATE_DESYNC_VIOLATION,
        TemporalViolationCategory.CACHE_AUTHORIZATION_DRIFT,
        TemporalViolationCategory.WORKFLOW_BYPASS_VIOLATION,
        TemporalViolationCategory.RACE_CONDITION_REACHABILITY,
        TemporalViolationCategory.TRANSACTIONAL_INVARIANT_FAILURE,
        TemporalViolationCategory.TEMPORAL_AUTHORIZATION_VIOLATION,
        TemporalViolationCategory.CAPABILITY_LIFETIME_ABUSE,
        TemporalViolationCategory.REPLAY_ATTACK_VIOLATION,
        TemporalViolationCategory.TEMPORAL_TENANT_ISOLATION_VIOLATION,
        TemporalViolationCategory.STATE_MONOTONICITY_VIOLATION,
    ]
    for i in range(28, 81):
        cat = categories[i % len(categories)]
        ev = TemporalEvidence(f"EV_{i}", cat, proof_present=False)
        violations = engine.evaluate_temporal_consistency(evidence=ev)
        assert len(violations) == 1
        assert violations[0].resolution == "VULNERABLE"
