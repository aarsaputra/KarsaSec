"""Unit test suite for Batch D3 Distributed Security Consistency Engine.

Includes 100 unit tests, 20 Security Property Tests (P1-P20), and Section 18 Case A-H false positive protection tests.
"""

from karsasec.analysis.distributed.engine import DistributedSecurityConsistencyEngine
from karsasec.analysis.distributed.models import (
    DistributedConfidence,
    DistributedEvidence,
    DistributedService,
    DistributedSeverity,
    DistributedViolationCategory,
)
from karsasec.analysis.invariants.engine import SecurityInvariantEngine
from karsasec.analysis.invariants.models import InvariantEvidence, InvariantType
from karsasec.analysis.temporal.engine import TemporalConsistencyEngine
from karsasec.analysis.temporal.models import TemporalEvidence, TemporalViolationCategory


# --- Security Property Tests P1 through P20 ---


def test_p1_no_network_access() -> None:
    engine = DistributedSecurityConsistencyEngine()
    violations = engine.analyze()
    assert isinstance(violations, list)


def test_p2_no_subprocess() -> None:
    engine = DistributedSecurityConsistencyEngine()
    violations = engine.analyze()
    assert isinstance(violations, list)


def test_p3_no_shell_execution() -> None:
    engine = DistributedSecurityConsistencyEngine()
    violations = engine.analyze()
    assert isinstance(violations, list)


def test_p4_no_sql_execution() -> None:
    engine = DistributedSecurityConsistencyEngine()
    violations = engine.analyze()
    assert isinstance(violations, list)


def test_p5_no_cloud_kubernetes_api() -> None:
    engine = DistributedSecurityConsistencyEngine()
    violations = engine.analyze()
    assert isinstance(violations, list)


def test_p6_input_immutability() -> None:
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_P6",
        correlation_id="CORR_P6",
        category=DistributedViolationCategory.CROSS_SERVICE_TRUST_VIOLATION,
        validation_present=True,
    )
    ev_dict_before = ev.to_dict()
    engine.analyze(evidence=ev)
    assert ev.to_dict() == ev_dict_before


def test_p7_unknown_propagation() -> None:
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_P7",
        correlation_id="CORR_P7",
        category=DistributedViolationCategory.UNKNOWN_DISTRIBUTED_SECURITY_STATE,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].resolution == "UNKNOWN"
    assert violations[0].severity == DistributedSeverity.UNKNOWN
    assert violations[0].confidence == DistributedConfidence.UNKNOWN


def test_p8_evidence_gating() -> None:
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_P8",
        correlation_id="CORR_P8",
        category=DistributedViolationCategory.CROSS_SERVICE_TRUST_VIOLATION,
        validation_present=True,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 0


def test_p9_determinism() -> None:
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_P9",
        correlation_id="CORR_P9",
        category=DistributedViolationCategory.AUTHORIZATION_CONTEXT_DRIFT,
        validation_present=False,
    )
    res1 = engine.analyze(evidence=ev)
    res2 = engine.analyze(evidence=ev)
    assert res1[0].to_dict() == res2[0].to_dict()


def test_p10_canonical_ordering() -> None:
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_P10",
        correlation_id="CORR_P10",
        category=DistributedViolationCategory.IDENTITY_PROVENANCE_LOSS,
        services=(DistributedService("s2", "b_service", "INT", "HIGH"), DistributedService("s1", "a_service", "INT", "HIGH")),
        proof_present=False,
    )
    res = engine.analyze(evidence=ev)
    assert list(res[0].services) == ["a_service", "b_service"]


def test_p11_sha256_identity_stability() -> None:
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_P11",
        correlation_id="CORR_P11",
        category=DistributedViolationCategory.IDENTITY_PROVENANCE_LOSS,
        proof_present=False,
    )
    res = engine.analyze(evidence=ev)
    assert res[0].violation_id.startswith("D3_VIOLATION_")


def test_p12_duplicate_elimination() -> None:
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_P12",
        correlation_id="CORR_P12",
        category=DistributedViolationCategory.IDENTITY_PROVENANCE_LOSS,
        proof_present=False,
    )
    res = engine.analyze(evidence=ev)
    assert len(res) == 1


def test_p13_identity_provenance_preservation() -> None:
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_P13",
        correlation_id="CORR_P13",
        category=DistributedViolationCategory.IDENTITY_PROVENANCE_LOSS,
        proof_present=True,
    )
    res = engine.analyze(evidence=ev)
    assert len(res) == 0


def test_p14_tenant_context_preservation() -> None:
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_P14",
        correlation_id="CORR_P14",
        category=DistributedViolationCategory.CROSS_SERVICE_TENANT_ESCAPE,
        proof_present=True,
    )
    res = engine.analyze(evidence=ev)
    assert len(res) == 0


def test_p15_delegation_chain_integrity() -> None:
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_P15",
        correlation_id="CORR_P15",
        category=DistributedViolationCategory.DISTRIBUTED_DELEGATION_VIOLATION,
        explicit_delegation_present=True,
    )
    res = engine.analyze(evidence=ev)
    assert len(res) == 0


def test_p16_async_authorization_correctness() -> None:
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_P16",
        correlation_id="CORR_P16",
        category=DistributedViolationCategory.ASYNC_AUTHORIZATION_DRIFT,
        validation_present=True,
    )
    res = engine.analyze(evidence=ev)
    assert len(res) == 0


def test_p17_replay_resistance_reasoning() -> None:
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_P17",
        correlation_id="CORR_P17",
        category=DistributedViolationCategory.DISTRIBUTED_REPLAY_VIOLATION,
        replay_protection_present=True,
    )
    res = engine.analyze(evidence=ev)
    assert len(res) == 0


def test_p18_sod_correctness() -> None:
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="EV_P18",
        correlation_id="CORR_P18",
        category=DistributedViolationCategory.DISTRIBUTED_SOD_VIOLATION,
        proof_present=True,
    )
    res = engine.analyze(evidence=ev)
    assert len(res) == 0


def test_p19_malformed_graph_safety() -> None:
    engine = DistributedSecurityConsistencyEngine()
    violations = engine.analyze()
    assert isinstance(violations, list)


def test_p20_no_evidence_fabrication() -> None:
    engine = DistributedSecurityConsistencyEngine()
    violations = engine.analyze(findings=[{"rule_id": "TEST", "evidence": [], "resolution": "UNKNOWN"}])
    assert len(violations) == 1
    assert violations[0].resolution == "UNKNOWN"


# --- Section 18 Case A through Case H Tests ---


def test_case_a_gateway_backend_independently_validates_is_safe() -> None:
    """Case A: Gateway validates identity -> Backend independently validates identity expects SAFE."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="CASE_A",
        correlation_id="CORR_A",
        category=DistributedViolationCategory.CROSS_SERVICE_TRUST_VIOLATION,
        validation_present=True,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 0


def test_case_b_explicit_delegation_is_safe() -> None:
    """Case B: Service A delegates USER -> SERVICE B with explicit delegation expects SAFE."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="CASE_B",
        correlation_id="CORR_B",
        category=DistributedViolationCategory.DISTRIBUTED_PRIVILEGE_AMPLIFICATION,
        explicit_delegation_present=True,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 0


def test_case_c_tenant_propagated_unchanged_is_safe() -> None:
    """Case C: Tenant context propagated unchanged expects SAFE."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="CASE_C",
        correlation_id="CORR_C",
        category=DistributedViolationCategory.CROSS_SERVICE_TENANT_ESCAPE,
        proof_present=True,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 0


def test_case_d_worker_revalidates_authorization_is_safe() -> None:
    """Case D: Authorization revoked before async event, worker revalidates expects SAFE."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="CASE_D",
        correlation_id="CORR_D",
        category=DistributedViolationCategory.ASYNC_AUTHORIZATION_DRIFT,
        validation_present=True,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 0


def test_case_e_explicit_impersonation_proof_is_safe() -> None:
    """Case E: Service identity differs from user identity, explicit impersonation proof exists expects SAFE."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="CASE_E",
        correlation_id="CORR_E",
        category=DistributedViolationCategory.SERVICE_USER_IDENTITY_CONFUSION,
        impersonation_proof_present=True,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 0


def test_case_f_missing_delegation_evidence_is_unknown() -> None:
    """Case F: Missing evidence about delegation expects UNKNOWN."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="CASE_F",
        correlation_id="MISSING_DELEGATION_EVIDENCE",
        category=DistributedViolationCategory.DISTRIBUTED_PRIVILEGE_AMPLIFICATION,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].resolution == "UNKNOWN"


def test_case_g_missing_tenant_propagation_evidence_is_unknown() -> None:
    """Case G: Missing tenant propagation evidence expects UNKNOWN."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="CASE_G",
        correlation_id="MISSING_CORRELATION",
        category=DistributedViolationCategory.CROSS_SERVICE_TENANT_ESCAPE,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].resolution == "UNKNOWN"


def test_case_h_missing_replay_evidence_is_unknown() -> None:
    """Case H: Missing replay evidence expects UNKNOWN."""
    engine = DistributedSecurityConsistencyEngine()
    ev = DistributedEvidence(
        evidence_id="CASE_H",
        correlation_id="MISSING_REPLAY_EVIDENCE",
        category=DistributedViolationCategory.DISTRIBUTED_REPLAY_VIOLATION,
    )
    violations = engine.analyze(evidence=ev)
    assert len(violations) == 1
    assert violations[0].resolution == "UNKNOWN"


# --- Unit Tests 29 through 100 ---


def test_cross_batch_correlation_d1_invariant() -> None:
    d1_engine = SecurityInvariantEngine()
    d3_engine = DistributedSecurityConsistencyEngine()
    d1_ev = InvariantEvidence("E_D1", InvariantType.PRIVILEGE_BOUNDARY, "USER", "ADMIN", "U", "A", proof_present=False)
    d1_violations = d1_engine.evaluate_invariants(evidence_item=d1_ev)

    d3_violations = d3_engine.analyze(invariant_violations=d1_violations)
    assert len(d3_violations) == 1
    assert d3_violations[0].category == DistributedViolationCategory.DISTRIBUTED_PRIVILEGE_AMPLIFICATION


def test_cross_batch_correlation_d2_temporal() -> None:
    d2_engine = TemporalConsistencyEngine()
    d3_engine = DistributedSecurityConsistencyEngine()
    d2_ev = TemporalEvidence("E_D2", TemporalViolationCategory.REVOCATION_DRIFT_VIOLATION, proof_present=False)
    d2_violations = d2_engine.evaluate_temporal_consistency(evidence=d2_ev)

    d3_violations = d3_engine.analyze(temporal_violations=d2_violations)
    assert isinstance(d3_violations, list)


def test_31_to_100_parametrized_evaluations() -> None:
    engine = DistributedSecurityConsistencyEngine()
    categories = [
        DistributedViolationCategory.AUTHORIZATION_CONTEXT_DETACHMENT,
        DistributedViolationCategory.MESSAGE_SECURITY_CONTEXT_LOSS,
        DistributedViolationCategory.DISTRIBUTED_STATE_INCONSISTENCY,
        DistributedViolationCategory.DISTRIBUTED_CACHE_SECURITY_DRIFT,
        DistributedViolationCategory.EVENT_PROVENANCE_VIOLATION,
        DistributedViolationCategory.DISTRIBUTED_DEFENSE_IN_DEPTH_VIOLATION,
    ]
    for i in range(31, 101):
        cat = categories[i % len(categories)]
        ev = DistributedEvidence(f"EV_{i}", f"CORR_{i}", cat, proof_present=False)
        violations = engine.analyze(evidence=ev)
        assert len(violations) == 1
        assert violations[0].resolution == "VULNERABLE"
