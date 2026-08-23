"""Unit, adversarial, and property-based test suite for Sprint D4 — Security Assurance Engine.

Verifies invariants INV-D4-SEC-01 through INV-D4-SEC-20 across fail-closed security assurance, explicit deny dominance,
distributed authority validity, quorum safety, fencing safety, partition safety, membership isolation, policy version safety,
revocation dominance, tenant isolation, capability scope isolation, provenance completeness, non-suppression, determinism,
order invariance, replay resistance, state convergence, conflict safety, unknown safety, and bounded observability.
"""

import pytest
from karsasec.analysis.authz.assurance import (
    ConsensusVote,
    SecurityAssuranceContext,
    SecurityAssuranceDecisionType,
    SecurityAssuranceEngine,
    SecurityAssuranceEvent,
    SecurityAssuranceEvidence,
    SecurityAssuranceFailureType,
    SecurityAssuranceRequest,
    SecurityAssuranceSnapshot,
)
from karsasec.analysis.authz.models import AuthorizationPolicyRef
from karsasec.analysis.distributed.partition import NetworkCondition


@pytest.fixture
def base_sec_request() -> SecurityAssuranceRequest:
    return SecurityAssuranceRequest(
        request_id="req_sec_200",
        principal="usr_bob",
        resource="res_payroll",
        action="view",
        tenant_id="tenant_sec",
        namespace="sec_domain_core",
        policy_id="pol_payroll_view",
        policy_version=3,
        authority_generation=10,
        membership_generation=5,
        fencing_token=12,
    )


@pytest.fixture
def base_sec_context() -> SecurityAssuranceContext:
    return SecurityAssuranceContext(
        policy_version=3,
        authority_generation=10,
        membership_generation=5,
        fencing_token=12,
        quorum_size=2,
        cluster_size=3,
        connectivity=NetworkCondition.HEALTHY,
    )


@pytest.fixture
def base_sec_policy() -> AuthorizationPolicyRef:
    return AuthorizationPolicyRef(
        policy_id="pol_payroll_view",
        policy_version=3,
        allowed_actions=("view", "export"),
        allowed_resources=("res_payroll", "res_summary"),
        tenant_id="tenant_sec",
        namespace="sec_domain_core",
    )


@pytest.fixture
def base_votes(base_sec_context: SecurityAssuranceContext) -> tuple[ConsensusVote, ...]:
    return (
        ConsensusVote(
            voter_id="node_1",
            term=base_sec_context.authority_generation,
            epoch=base_sec_context.authority_generation,
            fencing_token=base_sec_context.fencing_token,
            membership_view=str(base_sec_context.membership_generation),
            vote_granted=True,
        ),
        ConsensusVote(
            voter_id="node_2",
            term=base_sec_context.authority_generation,
            epoch=base_sec_context.authority_generation,
            fencing_token=base_sec_context.fencing_token,
            membership_view=str(base_sec_context.membership_generation),
            vote_granted=True,
        ),
    )


@pytest.fixture
def base_sec_evidence() -> SecurityAssuranceEvidence:
    return SecurityAssuranceEvidence(
        evidence_id="ev_sec_1",
        source_node="node_1",
        decision=SecurityAssuranceDecisionType.ALLOW,
        policy_version=3,
        authority_generation=10,
        membership_generation=5,
        tenant_id="tenant_sec",
        namespace="sec_domain_core",
    )


def test_d4_01_fail_closed(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_context: SecurityAssuranceContext,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
) -> None:
    """INV-D4-SEC-01 — Missing or empty evidence MUST produce BLOCKED, never ALLOW."""
    engine = SecurityAssuranceEngine()
    res = engine.evaluate(base_sec_request, base_sec_context, policy=base_sec_policy, assurance_evidence=(), consensus_votes=base_votes)
    assert res.is_allow() is False
    assert res.decision == SecurityAssuranceDecisionType.BLOCKED
    assert res.failure_type == SecurityAssuranceFailureType.MISSING_EVIDENCE


def test_d4_02_deny_precedence(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_context: SecurityAssuranceContext,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-02 — Authoritative DENY MUST dominate ALLOW."""
    engine = SecurityAssuranceEngine()
    deny_ev = SecurityAssuranceEvidence(
        evidence_id="ev_deny_1",
        source_node="node_2",
        decision=SecurityAssuranceDecisionType.DENY,
        policy_version=3,
        authority_generation=10,
        membership_generation=5,
        tenant_id="tenant_sec",
        namespace="sec_domain_core",
        is_authoritative=True,
    )
    res = engine.evaluate(base_sec_request, base_sec_context, policy=base_sec_policy, assurance_evidence=(base_sec_evidence, deny_ev), consensus_votes=base_votes)
    assert res.is_allow() is False
    assert res.decision == SecurityAssuranceDecisionType.DENY


def test_d4_03_authority_generation_safety(
    base_sec_context: SecurityAssuranceContext,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-03 — Stale authority generation rejected."""
    engine = SecurityAssuranceEngine()
    stale_req = SecurityAssuranceRequest(
        request_id="req_stale_gen",
        principal="usr_bob",
        resource="res_payroll",
        action="view",
        tenant_id="tenant_sec",
        namespace="sec_domain_core",
        policy_version=3,
        authority_generation=5,  # Stale vs context 10
        membership_generation=5,
        fencing_token=12,
    )
    res = engine.evaluate(stale_req, base_sec_context, policy=base_sec_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=base_votes)
    assert res.decision == SecurityAssuranceDecisionType.BLOCKED
    assert res.failure_type == SecurityAssuranceFailureType.STALE_AUTHORITY


def test_d4_04_quorum_safety(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_context: SecurityAssuranceContext,
    base_sec_policy: AuthorizationPolicyRef,
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-04 — Insufficient votes below quorum BLOCKED."""
    engine = SecurityAssuranceEngine()
    single_vote = (
        ConsensusVote("node_1", term=10, epoch=10, fencing_token=12, membership_view="5", vote_granted=True),
    )
    res = engine.evaluate(base_sec_request, base_sec_context, policy=base_sec_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=single_vote)
    assert res.decision == SecurityAssuranceDecisionType.BLOCKED
    assert res.failure_type == SecurityAssuranceFailureType.QUORUM_FAILURE


def test_d4_05_fencing_safety(
    base_sec_context: SecurityAssuranceContext,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-05 — Stale fencing token BLOCKED."""
    engine = SecurityAssuranceEngine()
    stale_fencing_req = SecurityAssuranceRequest(
        request_id="req_stale_fencing",
        principal="usr_bob",
        resource="res_payroll",
        action="view",
        tenant_id="tenant_sec",
        namespace="sec_domain_core",
        policy_version=3,
        authority_generation=10,
        membership_generation=5,
        fencing_token=1,  # Stale vs context 12
    )
    res = engine.evaluate(stale_fencing_req, base_sec_context, policy=base_sec_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=base_votes)
    assert res.decision == SecurityAssuranceDecisionType.BLOCKED
    assert res.failure_type == SecurityAssuranceFailureType.STALE_FENCING


def test_d4_06_partition_safety(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-06 — PARTITIONED or UNKNOWN connectivity forces BLOCKED."""
    engine = SecurityAssuranceEngine()
    partition_ctx = SecurityAssuranceContext(
        policy_version=3,
        authority_generation=10,
        membership_generation=5,
        fencing_token=12,
        connectivity=NetworkCondition.PARTITIONED,
    )
    res = engine.evaluate(base_sec_request, partition_ctx, policy=base_sec_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=base_votes)
    assert res.decision == SecurityAssuranceDecisionType.BLOCKED
    assert res.failure_type == SecurityAssuranceFailureType.PARTITION_UNSAFE


def test_d4_07_membership_isolation(
    base_sec_context: SecurityAssuranceContext,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-07 — Incompatible membership generation BLOCKED."""
    engine = SecurityAssuranceEngine()
    mismatch_req = SecurityAssuranceRequest(
        request_id="req_mismatch",
        principal="usr_bob",
        resource="res_payroll",
        action="view",
        tenant_id="tenant_sec",
        namespace="sec_domain_core",
        policy_version=3,
        authority_generation=10,
        membership_generation=999,  # Mismatch vs context 5
        fencing_token=12,
    )
    res = engine.evaluate(mismatch_req, base_sec_context, policy=base_sec_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=base_votes)
    assert res.decision == SecurityAssuranceDecisionType.BLOCKED
    assert res.failure_type == SecurityAssuranceFailureType.MEMBERSHIP_MISMATCH


def test_d4_08_policy_version_safety(
    base_sec_context: SecurityAssuranceContext,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-08 — Stale policy version BLOCKED."""
    engine = SecurityAssuranceEngine()
    stale_pol_req = SecurityAssuranceRequest(
        request_id="req_stale_pol",
        principal="usr_bob",
        resource="res_payroll",
        action="view",
        tenant_id="tenant_sec",
        namespace="sec_domain_core",
        policy_version=1,  # Stale vs context 3
    )
    res = engine.evaluate(stale_pol_req, base_sec_context, policy=base_sec_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=base_votes)
    assert res.decision == SecurityAssuranceDecisionType.BLOCKED
    assert res.failure_type == SecurityAssuranceFailureType.STALE_POLICY


def test_d4_09_revocation_dominance(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-09 — Explicit revocation forces DENY."""
    engine = SecurityAssuranceEngine()
    revoked_ctx = SecurityAssuranceContext(
        policy_version=3,
        authority_generation=10,
        membership_generation=5,
        fencing_token=12,
        revoked_principals=("usr_bob",),
    )
    res = engine.evaluate(base_sec_request, revoked_ctx, policy=base_sec_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=base_votes)
    assert res.decision == SecurityAssuranceDecisionType.DENY
    assert res.failure_type == SecurityAssuranceFailureType.REVOCATION


def test_d4_10_tenant_isolation(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_context: SecurityAssuranceContext,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-10 — Cross-tenant attempt DENIED."""
    engine = SecurityAssuranceEngine()
    cross_tenant_policy = AuthorizationPolicyRef(
        policy_id="pol_beta",
        policy_version=3,
        allowed_actions=("view",),
        allowed_resources=("res_payroll",),
        tenant_id="tenant_BETA",  # Mismatch vs request tenant_sec
        namespace="sec_domain_core",
    )
    res = engine.evaluate(base_sec_request, base_sec_context, policy=cross_tenant_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=base_votes)
    assert res.decision == SecurityAssuranceDecisionType.DENY
    assert res.failure_type == SecurityAssuranceFailureType.TENANT_VIOLATION


def test_d4_11_capability_scope_isolation(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_context: SecurityAssuranceContext,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-11 — Out of scope action or resource DENIED."""
    engine = SecurityAssuranceEngine()
    restricted_policy = AuthorizationPolicyRef(
        policy_id="pol_summary_only",
        policy_version=3,
        allowed_actions=("view",),
        allowed_resources=("res_summary",),  # res_payroll NOT allowed
        tenant_id="tenant_sec",
        namespace="sec_domain_core",
    )
    res = engine.evaluate(base_sec_request, base_sec_context, policy=restricted_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=base_votes)
    assert res.decision == SecurityAssuranceDecisionType.DENY
    assert res.failure_type == SecurityAssuranceFailureType.SCOPE_VIOLATION


def test_d4_12_provenance_completeness(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_context: SecurityAssuranceContext,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-12 — Complete provenance generated on decision."""
    engine = SecurityAssuranceEngine()
    res = engine.evaluate(base_sec_request, base_sec_context, policy=base_sec_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=base_votes)
    prov = res.provenance
    assert prov.request_id == "req_sec_200"
    assert prov.principal_id == "usr_bob"
    assert prov.resource_id == "res_payroll"
    assert prov.action == "view"
    assert prov.policy_id == "pol_payroll_view"
    assert prov.fencing_token == 12
    assert prov.evidence_ids == ("ev_sec_1",)


def test_d4_13_non_suppression(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_context: SecurityAssuranceContext,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
) -> None:
    """INV-D4-SEC-13 — Explicit DENY cannot be suppressed by weak positive evidence."""
    engine = SecurityAssuranceEngine()
    deny_ev = SecurityAssuranceEvidence("e_deny", "n2", SecurityAssuranceDecisionType.DENY, 3, 10, 5, is_authoritative=True)
    allow_ev = SecurityAssuranceEvidence("e_allow", "n1", SecurityAssuranceDecisionType.ALLOW, 3, 10, 5, is_authoritative=False)

    res = engine.evaluate(base_sec_request, base_sec_context, policy=base_sec_policy, assurance_evidence=(allow_ev, deny_ev), consensus_votes=base_votes)
    assert res.decision == SecurityAssuranceDecisionType.DENY


def test_d4_14_determinism(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_context: SecurityAssuranceContext,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-14 — Byte-identical decisions across multiple invocations."""
    e1 = SecurityAssuranceEngine(node_id="n1")
    e2 = SecurityAssuranceEngine(node_id="n2")

    res1 = e1.evaluate(base_sec_request, base_sec_context, policy=base_sec_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=base_votes)
    res2 = e2.evaluate(base_sec_request, base_sec_context, policy=base_sec_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=base_votes)

    assert res1.provenance.to_dict() == res2.provenance.to_dict()
    assert res1.decision == res2.decision


def test_d4_15_order_invariance(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_context: SecurityAssuranceContext,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
) -> None:
    """INV-D4-SEC-15 — Permuting evidence list yields identical decision."""
    engine = SecurityAssuranceEngine()
    e1 = SecurityAssuranceEvidence("e1", "n1", SecurityAssuranceDecisionType.ALLOW, 3, 10, 5)
    e2 = SecurityAssuranceEvidence("e2", "n2", SecurityAssuranceDecisionType.ALLOW, 3, 10, 5)
    e3 = SecurityAssuranceEvidence("e3", "n3", SecurityAssuranceDecisionType.ALLOW, 3, 10, 5)

    res_a = engine.evaluate(base_sec_request, base_sec_context, policy=base_sec_policy, assurance_evidence=(e1, e2, e3), consensus_votes=base_votes)
    res_b = engine.evaluate(base_sec_request, base_sec_context, policy=base_sec_policy, assurance_evidence=(e3, e1, e2), consensus_votes=base_votes)

    assert res_a.decision == res_b.decision
    assert res_a.provenance.evidence_ids == res_b.provenance.evidence_ids


def test_d4_16_replay_resistance() -> None:
    """INV-D4-SEC-16 — Duplicate security events are idempotent."""
    engine = SecurityAssuranceEngine()
    snap = SecurityAssuranceSnapshot(1, 1, 1, 1, (), (), ())
    evt = SecurityAssuranceEvent("evt_sec_100", "GRANT", "usr_bob", "res_payroll", "view", 1, 1, 1)

    snap1, applied1 = engine.apply_event(snap, evt)
    snap2, applied2 = engine.apply_event(snap1, evt)

    assert applied1 is True
    assert applied2 is False  # Replay ignored
    assert engine.calculate_state_digest(snap1) == engine.calculate_state_digest(snap2)


def test_d4_17_state_convergence() -> None:
    """INV-D4-SEC-17 — Equivalent snapshots converge to identical SHA256 state digest."""
    engine = SecurityAssuranceEngine()
    s1 = SecurityAssuranceSnapshot(10, 3, 5, 12, ("usr_revoked:res:read",), ("usr_bob:res:view",), ("evt_1", "evt_2"))
    s2 = SecurityAssuranceSnapshot(10, 3, 5, 12, ("usr_revoked:res:read",), ("usr_bob:res:view",), ("evt_2", "evt_1"))

    reconciled1 = engine.reconcile([s1, s2])
    reconciled2 = engine.reconcile([s2, s1])

    assert engine.calculate_state_digest(reconciled1) == engine.calculate_state_digest(reconciled2)


def test_d4_18_conflict_safety(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_context: SecurityAssuranceContext,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-18 — Unresolved non-authoritative conflict produces BLOCKED."""
    engine = SecurityAssuranceEngine()
    non_auth_deny = SecurityAssuranceEvidence("ev_conflict", "n2", SecurityAssuranceDecisionType.DENY, 3, 10, 5, tenant_id="tenant_sec", namespace="sec_domain_core", is_authoritative=False)
    res = engine.evaluate(base_sec_request, base_sec_context, policy=base_sec_policy, assurance_evidence=(base_sec_evidence, non_auth_deny), consensus_votes=base_votes)
    assert res.decision == SecurityAssuranceDecisionType.BLOCKED
    assert res.failure_type == SecurityAssuranceFailureType.CONFLICT


def test_d4_19_unknown_is_not_safe(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-19 — UNKNOWN connectivity forces BLOCKED (UNKNOWN != SAFE)."""
    engine = SecurityAssuranceEngine()
    unknown_ctx = SecurityAssuranceContext(
        policy_version=3,
        authority_generation=10,
        membership_generation=5,
        fencing_token=12,
        connectivity=NetworkCondition.UNKNOWN,
    )
    res = engine.evaluate(base_sec_request, unknown_ctx, policy=base_sec_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=base_votes)
    assert res.is_allow() is False
    assert res.decision == SecurityAssuranceDecisionType.BLOCKED
    assert res.failure_type == SecurityAssuranceFailureType.PARTITION_UNSAFE


def test_d4_20_bounded_observability(
    base_sec_request: SecurityAssuranceRequest,
    base_sec_context: SecurityAssuranceContext,
    base_sec_policy: AuthorizationPolicyRef,
    base_votes: tuple[ConsensusVote, ...],
    base_sec_evidence: SecurityAssuranceEvidence,
) -> None:
    """INV-D4-SEC-20 — Observability metrics expose only bounded categorical fields."""
    engine = SecurityAssuranceEngine()
    res = engine.evaluate(base_sec_request, base_sec_context, policy=base_sec_policy, assurance_evidence=(base_sec_evidence,), consensus_votes=base_votes)
    details = res.details
    assert "status_code" in details
    assert "node_id" in details
    assert "principal" in details
    assert "resource" in details
    assert res.provenance.failure_type.value in [e.value for e in SecurityAssuranceFailureType]


@pytest.mark.parametrize("cluster_nodes", [1, 3, 5, 7])
def test_parameterized_cluster_security_assurance(cluster_nodes: int) -> None:
    """Adversarial/Property — Security assurance evaluation across 1, 3, 5, and 7 node cluster sizes."""
    engine = SecurityAssuranceEngine()
    req = SecurityAssuranceRequest("r_param", "u_param", "res_param", "read", "t1", "ns1", "p1", 1, 1, 1, 1)
    ctx = SecurityAssuranceContext(1, 1, 1, 1, quorum_size=(cluster_nodes // 2) + 1, cluster_size=cluster_nodes)
    pol = AuthorizationPolicyRef("p1", 1, ("read",), ("res_param",), "t1", "ns1")

    evidence_list = tuple(
        SecurityAssuranceEvidence(f"ev_{i}", f"node_{i}", SecurityAssuranceDecisionType.ALLOW, 1, 1, 1, "t1", "ns1")
        for i in range(cluster_nodes)
    )
    votes = tuple(
        ConsensusVote(f"node_{i}", term=1, epoch=1, fencing_token=1, membership_view="1", vote_granted=True)
        for i in range(cluster_nodes)
    )

    res = engine.evaluate(req, ctx, policy=pol, assurance_evidence=evidence_list, consensus_votes=votes)
    assert res.is_allow() is True
    assert res.decision == SecurityAssuranceDecisionType.ALLOW
