"""Unit, adversarial, and property-based test suite for Sprint D3 — Distributed Authorization Reasoning Engine.

Verifies invariants INV-D3-AUTH-01 through INV-D3-AUTH-16 across fail-closed authorization, deny precedence,
policy version safety, authority generation safety, membership view isolation, revocation dominance, conflict safety,
order invariance, replay resistance, provenance completeness, capability/tenant scope boundaries, and distributed convergence.
"""

import pytest
from karsasec.analysis.authz.engine import DistributedAuthorizationReasoningEngine
from karsasec.analysis.authz.models import (
    AuthorizationContext,
    AuthorizationDecisionType,
    AuthorizationEvent,
    AuthorizationEvidenceState,
    AuthorizationFailureType,
    AuthorizationPolicyRef,
    AuthorizationRequest,
    AuthorizationSnapshot,
    DistributedAuthorizationEvidence,
)
from karsasec.analysis.distributed.partition import NetworkCondition


@pytest.fixture
def base_request() -> AuthorizationRequest:
    return AuthorizationRequest(
        request_id="req_100",
        principal="usr_alice",
        resource="doc_secret",
        action="read",
        tenant_id="tenant_alpha",
        namespace="sec_domain_1",
        policy_id="pol_read_secret",
        policy_version=2,
        authority_generation=5,
        membership_generation=3,
    )


@pytest.fixture
def base_context() -> AuthorizationContext:
    return AuthorizationContext(
        policy_version=2,
        authority_generation=5,
        membership_generation=3,
    )


@pytest.fixture
def base_policy() -> AuthorizationPolicyRef:
    return AuthorizationPolicyRef(
        policy_id="pol_read_secret",
        policy_version=2,
        allowed_actions=("read", "download"),
        allowed_resources=("doc_secret", "doc_public"),
        tenant_id="tenant_alpha",
        namespace="sec_domain_1",
    )


@pytest.fixture
def base_evidence() -> DistributedAuthorizationEvidence:
    return DistributedAuthorizationEvidence(
        evidence_id="ev_1",
        source_node="node_A",
        decision=AuthorizationDecisionType.ALLOW,
        policy_version=2,
        authority_generation=5,
        membership_generation=3,
        tenant_id="tenant_alpha",
        namespace="sec_domain_1",
    )


def test_d3_01_fail_closed_missing_evidence(
    base_request: AuthorizationRequest,
    base_context: AuthorizationContext,
    base_policy: AuthorizationPolicyRef,
) -> None:
    """D3-01 — Missing evidence MUST NOT produce ALLOW (INV-D3-AUTH-01)."""
    engine = DistributedAuthorizationReasoningEngine()
    res = engine.evaluate(base_request, base_context, evidence=(), policy=base_policy)
    assert res.is_allow() is False
    assert res.decision == AuthorizationDecisionType.BLOCKED
    assert res.failure_type == AuthorizationFailureType.MISSING_EVIDENCE


def test_d3_02_deny_precedence(
    base_request: AuthorizationRequest,
    base_context: AuthorizationContext,
    base_policy: AuthorizationPolicyRef,
    base_evidence: DistributedAuthorizationEvidence,
) -> None:
    """D3-02 — Authoritative explicit DENY dominates conflicting ALLOW (INV-D3-AUTH-02)."""
    engine = DistributedAuthorizationReasoningEngine()
    deny_ev = DistributedAuthorizationEvidence(
        evidence_id="ev_deny",
        source_node="node_B",
        decision=AuthorizationDecisionType.DENY,
        policy_version=2,
        authority_generation=5,
        membership_generation=3,
        tenant_id="tenant_alpha",
        namespace="sec_domain_1",
        is_authoritative=True,
    )
    res = engine.evaluate(base_request, base_context, evidence=(base_evidence, deny_ev), policy=base_policy)
    assert res.is_allow() is False
    assert res.decision == AuthorizationDecisionType.DENY
    assert res.failure_type == AuthorizationFailureType.REVOCATION


def test_d3_03_stale_policy_rejected(
    base_request: AuthorizationRequest,
    base_context: AuthorizationContext,
    base_policy: AuthorizationPolicyRef,
    base_evidence: DistributedAuthorizationEvidence,
) -> None:
    """D3-03 — Evidence under older policy version is stale (INV-D3-AUTH-03)."""
    engine = DistributedAuthorizationReasoningEngine()
    stale_req = AuthorizationRequest(
        request_id="req_stale",
        principal="usr_alice",
        resource="doc_secret",
        action="read",
        policy_version=1,  # Stale vs context (2)
        authority_generation=5,
        membership_generation=3,
    )
    res = engine.evaluate(stale_req, base_context, evidence=(base_evidence,), policy=base_policy)
    assert res.decision == AuthorizationDecisionType.BLOCKED
    assert res.failure_type == AuthorizationFailureType.STALE_POLICY


def test_d3_04_stale_authority_rejected(
    base_request: AuthorizationRequest,
    base_context: AuthorizationContext,
    base_policy: AuthorizationPolicyRef,
    base_evidence: DistributedAuthorizationEvidence,
) -> None:
    """D3-04 — Stale authority generation rejected (INV-D3-AUTH-04)."""
    engine = DistributedAuthorizationReasoningEngine()
    stale_req = AuthorizationRequest(
        request_id="req_stale_auth",
        principal="usr_alice",
        resource="doc_secret",
        action="read",
        policy_version=2,
        authority_generation=4,  # Stale vs context (5)
        membership_generation=3,
    )
    res = engine.evaluate(stale_req, base_context, evidence=(base_evidence,), policy=base_policy)
    assert res.decision == AuthorizationDecisionType.BLOCKED
    assert res.failure_type == AuthorizationFailureType.STALE_AUTHORITY


def test_d3_05_membership_view_isolation(
    base_request: AuthorizationRequest,
    base_context: AuthorizationContext,
    base_policy: AuthorizationPolicyRef,
    base_evidence: DistributedAuthorizationEvidence,
) -> None:
    """D3-05 — Incompatible membership generation cannot be trusted (INV-D3-AUTH-05)."""
    engine = DistributedAuthorizationReasoningEngine()
    mismatch_req = AuthorizationRequest(
        request_id="req_mismatch",
        principal="usr_alice",
        resource="doc_secret",
        action="read",
        policy_version=2,
        authority_generation=5,
        membership_generation=99,  # Mismatch vs context (3)
    )
    res = engine.evaluate(mismatch_req, base_context, evidence=(base_evidence,), policy=base_policy)
    assert res.decision == AuthorizationDecisionType.BLOCKED
    assert res.failure_type == AuthorizationFailureType.MEMBERSHIP_MISMATCH


def test_d3_06_revocation_dominates_allow(
    base_request: AuthorizationRequest,
    base_policy: AuthorizationPolicyRef,
    base_evidence: DistributedAuthorizationEvidence,
) -> None:
    """D3-06 — Revoked principal MUST NOT receive ALLOW from cached positive evidence (INV-D3-AUTH-06)."""
    engine = DistributedAuthorizationReasoningEngine()
    revoked_context = AuthorizationContext(
        policy_version=2,
        authority_generation=5,
        membership_generation=3,
        revoked_principals=("usr_alice",),
    )
    res = engine.evaluate(base_request, revoked_context, evidence=(base_evidence,), policy=base_policy)
    assert res.is_allow() is False
    assert res.decision == AuthorizationDecisionType.DENY
    assert res.failure_type == AuthorizationFailureType.REVOCATION


def test_d3_07_conflicting_evidence_blocks(
    base_request: AuthorizationRequest,
    base_context: AuthorizationContext,
    base_policy: AuthorizationPolicyRef,
    base_evidence: DistributedAuthorizationEvidence,
) -> None:
    """D3-07 — Unresolved conflicting evidence produces BLOCKED, not silent ALLOW (INV-D3-AUTH-07)."""
    engine = DistributedAuthorizationReasoningEngine()
    non_auth_deny = DistributedAuthorizationEvidence(
        evidence_id="ev_2",
        source_node="node_C",
        decision=AuthorizationDecisionType.DENY,
        policy_version=2,
        authority_generation=5,
        membership_generation=3,
        tenant_id="tenant_alpha",
        namespace="sec_domain_1",
        is_authoritative=False,  # Non-authoritative conflict
    )
    res = engine.evaluate(base_request, base_context, evidence=(base_evidence, non_auth_deny), policy=base_policy)
    assert res.is_allow() is False
    assert res.decision == AuthorizationDecisionType.BLOCKED
    assert res.failure_type == AuthorizationFailureType.CONFLICT


def test_d3_08_deterministic_decision(
    base_request: AuthorizationRequest,
    base_context: AuthorizationContext,
    base_policy: AuthorizationPolicyRef,
    base_evidence: DistributedAuthorizationEvidence,
) -> None:
    """D3-08 — Identical inputs produce byte-identical logical outputs (INV-D3-AUTH-08)."""
    e1 = DistributedAuthorizationReasoningEngine()
    e2 = DistributedAuthorizationReasoningEngine()

    res1 = e1.evaluate(base_request, base_context, evidence=(base_evidence,), policy=base_policy)
    res2 = e2.evaluate(base_request, base_context, evidence=(base_evidence,), policy=base_policy)

    assert res1.provenance.to_dict() == res2.provenance.to_dict()
    assert res1.decision == res2.decision


def test_d3_09_evidence_order_invariance(
    base_request: AuthorizationRequest,
    base_context: AuthorizationContext,
    base_policy: AuthorizationPolicyRef,
) -> None:
    """D3-09 — Reordering independent evidence list produces identical decision (INV-D3-AUTH-09)."""
    engine = DistributedAuthorizationReasoningEngine()
    ev1 = DistributedAuthorizationEvidence("e1", "n1", AuthorizationDecisionType.ALLOW, 2, 5, 3)
    ev2 = DistributedAuthorizationEvidence("e2", "n2", AuthorizationDecisionType.ALLOW, 2, 5, 3)
    ev3 = DistributedAuthorizationEvidence("e3", "n3", AuthorizationDecisionType.ALLOW, 2, 5, 3)

    res_a = engine.evaluate(base_request, base_context, evidence=(ev1, ev2, ev3), policy=base_policy)
    res_b = engine.evaluate(base_request, base_context, evidence=(ev3, ev1, ev2), policy=base_policy)

    assert res_a.decision == res_b.decision
    assert res_a.provenance.evidence_ids == res_b.provenance.evidence_ids


def test_d3_10_event_replay_resistance() -> None:
    """D3-10 — Reapplying processed authorization event is idempotent (INV-D3-AUTH-10)."""
    engine = DistributedAuthorizationReasoningEngine()
    snap = AuthorizationSnapshot(
        generation=1, policy_version=1, membership_generation=1, revocations=(), grants=(), applied_events=()
    )
    event = AuthorizationEvent("evt_1", "GRANT", "usr_alice", "doc_secret", "read", 1, 1)

    snap1, applied1 = engine.apply_event(snap, event)
    snap2, applied2 = engine.apply_event(snap1, event)

    assert applied1 is True
    assert applied2 is False  # Replay ignored
    assert engine.calculate_state_digest(snap1) == engine.calculate_state_digest(snap2)


def test_d3_11_monotonic_revocation(
    base_request: AuthorizationRequest,
    base_policy: AuthorizationPolicyRef,
    base_evidence: DistributedAuthorizationEvidence,
) -> None:
    """D3-11 — Stale historical evidence cannot restore ALLOW for revoked grant (INV-D3-AUTH-11)."""
    engine = DistributedAuthorizationReasoningEngine()
    ctx_revoked = AuthorizationContext(
        policy_version=2,
        authority_generation=5,
        membership_generation=3,
        revoked_grants=("usr_alice:doc_secret:read",),
    )
    res = engine.evaluate(base_request, ctx_revoked, evidence=(base_evidence,), policy=base_policy)
    assert res.is_allow() is False
    assert res.decision == AuthorizationDecisionType.DENY


def test_d3_12_provenance_completeness(
    base_request: AuthorizationRequest,
    base_context: AuthorizationContext,
    base_policy: AuthorizationPolicyRef,
    base_evidence: DistributedAuthorizationEvidence,
) -> None:
    """D3-12 — Complete provenance attached to decision (INV-D3-AUTH-12)."""
    engine = DistributedAuthorizationReasoningEngine()
    res = engine.evaluate(base_request, base_context, evidence=(base_evidence,), policy=base_policy)
    prov = res.provenance
    assert prov.principal_id == "usr_alice"
    assert prov.resource_id == "doc_secret"
    assert prov.action == "read"
    assert prov.policy_id == "pol_read_secret"
    assert prov.policy_version == 2
    assert prov.authority_generation == 5
    assert prov.membership_generation == 3
    assert prov.evidence_ids == ("ev_1",)


def test_d3_13_non_suppression(
    base_request: AuthorizationRequest,
    base_context: AuthorizationContext,
    base_policy: AuthorizationPolicyRef,
) -> None:
    """D3-13 — Missing or weak evidence cannot suppress explicit authoritative DENY (INV-D3-AUTH-13)."""
    engine = DistributedAuthorizationReasoningEngine()
    deny_ev = DistributedAuthorizationEvidence("e_deny", "node_X", AuthorizationDecisionType.DENY, 2, 5, 3, is_authoritative=True)
    stale_allow_ev = DistributedAuthorizationEvidence("e_stale", "node_Y", AuthorizationDecisionType.ALLOW, 1, 4, 3, state=AuthorizationEvidenceState.STALE)

    res = engine.evaluate(base_request, base_context, evidence=(stale_allow_ev, deny_ev), policy=base_policy)
    assert res.decision == AuthorizationDecisionType.DENY


def test_d3_14_capability_scope_isolation(
    base_request: AuthorizationRequest,
    base_context: AuthorizationContext,
    base_evidence: DistributedAuthorizationEvidence,
) -> None:
    """D3-14 — Scope isolation prevents ungranted action or resource access (INV-D3-AUTH-14)."""
    engine = DistributedAuthorizationReasoningEngine()
    restricted_policy = AuthorizationPolicyRef(
        policy_id="pol_restricted",
        policy_version=2,
        allowed_actions=("read",),
        allowed_resources=("doc_public",),  # doc_secret is NOT allowed
    )
    res = engine.evaluate(base_request, base_context, evidence=(base_evidence,), policy=restricted_policy)
    assert res.decision == AuthorizationDecisionType.DENY
    assert res.failure_type == AuthorizationFailureType.SCOPE_VIOLATION


def test_d3_15_namespace_isolation(
    base_request: AuthorizationRequest,
    base_context: AuthorizationContext,
    base_evidence: DistributedAuthorizationEvidence,
) -> None:
    """D3-15 — Cross-tenant or cross-namespace attempt is DENIED (INV-D3-AUTH-15)."""
    engine = DistributedAuthorizationReasoningEngine()
    cross_tenant_policy = AuthorizationPolicyRef(
        policy_id="pol_tenant_beta",
        policy_version=2,
        allowed_actions=("read",),
        allowed_resources=("doc_secret",),
        tenant_id="tenant_BETA",  # Mismatch vs request tenant_alpha
        namespace="sec_domain_1",
    )
    res = engine.evaluate(base_request, base_context, evidence=(base_evidence,), policy=cross_tenant_policy)
    assert res.decision == AuthorizationDecisionType.DENY
    assert res.failure_type == AuthorizationFailureType.TENANT_VIOLATION


def test_d3_16_distributed_convergence() -> None:
    """D3-16 — Equivalent replicas converge to identical state digest (INV-D3-AUTH-16)."""
    e1 = DistributedAuthorizationReasoningEngine(node_id="replica_1")
    e2 = DistributedAuthorizationReasoningEngine(node_id="replica_2")

    s1 = AuthorizationSnapshot(1, 1, 1, ("usr_banned:res_1:write",), ("usr_alice:res_2:read",), ("evt_1", "evt_2"))
    s2 = AuthorizationSnapshot(1, 1, 1, ("usr_banned:res_1:write",), ("usr_alice:res_2:read",), ("evt_2", "evt_1"))

    reconciled1 = e1.reconcile([s1, s2])
    reconciled2 = e2.reconcile([s2, s1])

    digest1 = e1.calculate_state_digest(reconciled1)
    digest2 = e2.calculate_state_digest(reconciled2)

    assert digest1 == digest2


def test_unknown_connectivity_blocks_authorization(
    base_request: AuthorizationRequest,
    base_context: AuthorizationContext,
    base_policy: AuthorizationPolicyRef,
    base_evidence: DistributedAuthorizationEvidence,
) -> None:
    """Adversarial — UNKNOWN connectivity MUST force fail-closed BLOCKED status."""
    engine = DistributedAuthorizationReasoningEngine()
    res = engine.evaluate(
        base_request, base_context, evidence=(base_evidence,), policy=base_policy, connectivity=NetworkCondition.UNKNOWN
    )
    assert res.is_allow() is False
    assert res.decision == AuthorizationDecisionType.BLOCKED
    assert res.failure_type == AuthorizationFailureType.UNKNOWN_CONNECTIVITY


@pytest.mark.parametrize("cluster_size", [1, 3, 5, 7])
def test_parameterized_cluster_node_authorization(cluster_size: int) -> None:
    """Property/Adversarial — Authorization reasoning across 1, 3, 5, 7 node clusters."""
    engine = DistributedAuthorizationReasoningEngine()
    req = AuthorizationRequest("r_param", "u1", "r1", "read", "tenant1", "ns1", "pol1", 1, 1, 1)
    ctx = AuthorizationContext(policy_version=1, authority_generation=1, membership_generation=1)
    pol = AuthorizationPolicyRef("pol1", 1, ("read",), ("r1",), "tenant1", "ns1")

    evidence_list = tuple(
        DistributedAuthorizationEvidence(f"ev_{i}", f"node_{i}", AuthorizationDecisionType.ALLOW, 1, 1, 1, "tenant1", "ns1")
        for i in range(cluster_size)
    )

    res = engine.evaluate(req, ctx, evidence=evidence_list, policy=pol)
    assert res.is_allow() is True
    assert len(res.provenance.evidence_ids) == cluster_size
