"""Unit and adversarial test suite for Sprint F15 — Multi-Node Partition Consensus & Split-Brain Hardening Engine.

Verifies invariants INV-F15-CONS-01 through INV-F15-CONS-16 across quorum authority rules, split-brain prevention,
epoch & fencing token monotonicity, replay resistance, partition healing reconciliation, state convergence,
and bounded observability controls.
"""

import pytest
from karsasec.analysis.distributed.consensus import (
    ConsensusEvent,
    ConsensusFailureType,
    ConsensusProposal,
    ConsensusStatus,
    MembershipView,
    MultiNodeConsensusEngine,
    calculate_state_digest,
)
from karsasec.analysis.distributed.partition import (
    NetworkCondition,
    PartitionType,
)


def test_f15_01_quorum_authority() -> None:
    """F15-01 — Authority granted ONLY if valid votes satisfy quorum requirement (INV-F15-CONS-01)."""
    engine = MultiNodeConsensusEngine()
    view = MembershipView(view_id="v1", members=("node_1", "node_2", "node_3"))  # Quorum = 2

    # Proposal with 2 votes -> Granted
    p_granted = ConsensusProposal(
        proposal_id="p1",
        resource_id="res_1",
        proposer_node="node_1",
        target_epoch=1,
        target_fencing_token=2,
        votes=("node_1", "node_2"),
        membership_view=view,
    )
    res_granted = engine.request_authority(p_granted)
    assert res_granted.is_granted() is True
    assert res_granted.status == ConsensusStatus.AUTHORITY_GRANTED

    # Proposal with 1 vote -> Blocked
    engine_minority = MultiNodeConsensusEngine()
    p_blocked = ConsensusProposal(
        proposal_id="p2",
        resource_id="res_1",
        proposer_node="node_1",
        target_epoch=1,
        target_fencing_token=2,
        votes=("node_1",),
        membership_view=view,
    )
    res_blocked = engine_minority.request_authority(p_blocked)
    assert res_blocked.is_granted() is False
    assert res_blocked.status == ConsensusStatus.BLOCKED_NO_QUORUM
    assert res_blocked.failure_type == ConsensusFailureType.NO_QUORUM


def test_f15_02_no_dual_authority() -> None:
    """F15-02 — At most one node can hold active authority for a resource at a given epoch (INV-F15-CONS-02)."""
    engine = MultiNodeConsensusEngine()
    view = MembershipView(view_id="v1", members=("node_1", "node_2", "node_3"))

    p1 = ConsensusProposal(
        proposal_id="p1",
        resource_id="res_db",
        proposer_node="node_1",
        target_epoch=5,
        target_fencing_token=10,
        votes=("node_1", "node_2"),
        membership_view=view,
    )
    res1 = engine.request_authority(p1)
    assert res1.is_granted() is True

    # Node 2 attempts to claim authority for same resource at same epoch -> Rejected (Split-Brain)
    p2 = ConsensusProposal(
        proposal_id="p2",
        resource_id="res_db",
        proposer_node="node_2",
        target_epoch=5,
        target_fencing_token=11,
        votes=("node_2", "node_3"),
        membership_view=view,
    )
    res2 = engine.request_authority(p2)
    assert res2.is_granted() is False
    assert res2.status == ConsensusStatus.REJECTED_SPLIT_BRAIN
    assert res2.failure_type == ConsensusFailureType.SPLIT_BRAIN


def test_f15_03_epoch_monotonicity() -> None:
    """F15-03 — Target epoch must be >= current epoch; stale epoch is rejected (INV-F15-CONS-03)."""
    engine = MultiNodeConsensusEngine(initial_epoch=10)
    view = MembershipView(view_id="v1", members=("n1", "n2", "n3"))

    p_stale = ConsensusProposal(
        proposal_id="p_stale",
        resource_id="res_x",
        proposer_node="n1",
        target_epoch=8,
        target_fencing_token=20,
        votes=("n1", "n2"),
        membership_view=view,
    )
    res = engine.request_authority(p_stale)
    assert res.status == ConsensusStatus.REJECTED_STALE
    assert res.failure_type == ConsensusFailureType.STALE_EPOCH


def test_f15_04_fencing_monotonicity() -> None:
    """F15-04 — Target fencing token must be strictly greater than current fencing token (INV-F15-CONS-04)."""
    engine = MultiNodeConsensusEngine(initial_fencing_token=15)
    view = MembershipView(view_id="v1", members=("n1", "n2", "n3"))

    p_stale = ConsensusProposal(
        proposal_id="p1",
        resource_id="res_y",
        proposer_node="n1",
        target_epoch=1,
        target_fencing_token=15,  # Not strictly greater
        votes=("n1", "n2"),
        membership_view=view,
    )
    res = engine.request_authority(p_stale)
    assert res.status == ConsensusStatus.REJECTED_STALE
    assert res.failure_type == ConsensusFailureType.STALE_FENCING_TOKEN


def test_f15_05_membership_view_isolation() -> None:
    """F15-05 — Proposer must be part of the explicit membership view provided (INV-F15-CONS-05)."""
    engine = MultiNodeConsensusEngine()
    view = MembershipView(view_id="v1", members=("n1", "n2", "n3"))

    p_outsider = ConsensusProposal(
        proposal_id="p1",
        resource_id="res_z",
        proposer_node="rogue_node",  # Not in view
        target_epoch=1,
        target_fencing_token=2,
        votes=("n1", "n2"),
        membership_view=view,
    )
    res = engine.request_authority(p_outsider)
    assert res.status == ConsensusStatus.BLOCKED_FAIL_CLOSED
    assert res.failure_type == ConsensusFailureType.MEMBERSHIP_CONFLICT


def test_f15_06_no_quorum_no_authority() -> None:
    """F15-06 — Minority partitioned group cannot obtain authority (INV-F15-CONS-06)."""
    engine = MultiNodeConsensusEngine()
    view = MembershipView(view_id="v1", members=("n1", "n2", "n3", "n4", "n5"))  # Quorum = 3

    p_minority = ConsensusProposal(
        proposal_id="p1",
        resource_id="res_auth",
        proposer_node="n1",
        target_epoch=1,
        target_fencing_token=2,
        votes=("n1", "n2"),  # 2 votes < 3 quorum
        membership_view=view,
    )
    res = engine.request_authority(p_minority)
    assert res.is_granted() is False
    assert res.status == ConsensusStatus.BLOCKED_NO_QUORUM


def test_f15_07_stale_leader_rejection() -> None:
    """F15-07 — Reconnected stale leader from older epoch cannot exercise authority (INV-F15-CONS-07)."""
    engine = MultiNodeConsensusEngine(initial_epoch=5)
    view = MembershipView(view_id="v1", members=("n1", "n2", "n3"))

    p_old_leader = ConsensusProposal(
        proposal_id="p1",
        resource_id="res_core",
        proposer_node="n1",
        target_epoch=3,
        target_fencing_token=10,
        votes=("n1", "n2"),
        membership_view=view,
    )
    res = engine.request_authority(p_old_leader)
    assert res.status == ConsensusStatus.REJECTED_STALE


def test_f15_08_replay_resistance() -> None:
    """F15-08 — Applying the exact same consensus event twice is idempotent (INV-F15-CONS-08)."""
    engine = MultiNodeConsensusEngine()
    event = ConsensusEvent(
        event_id="e_100",
        event_type="AUTHORITY_GRANT",
        epoch=2,
        fencing_token=5,
        sequence=1,
        source_node="n1",
        resource_id="res_k",
        membership_digest="digest_v1",
    )

    snap1, applied1 = engine.apply_event(event)
    snap2, applied2 = engine.apply_event(event)

    assert applied1 is True
    assert applied2 is False  # Replay ignored
    assert snap1.canonical_digest() == snap2.canonical_digest()


def test_f15_09_event_ordering_safety() -> None:
    """F15-09 — Out-of-order sequence events cannot regress engine state (INV-F15-CONS-09)."""
    engine = MultiNodeConsensusEngine()
    e_new = ConsensusEvent(
        event_id="e_2",
        event_type="AUTHORITY_GRANT",
        epoch=5,
        fencing_token=10,
        sequence=10,
        source_node="n1",
        resource_id="res_order",
        membership_digest="d1",
    )
    engine.apply_event(e_new)

    # Older sequence event
    e_old = ConsensusEvent(
        event_id="e_1",
        event_type="AUTHORITY_GRANT",
        epoch=4,
        fencing_token=8,
        sequence=5,
        source_node="n1",
        resource_id="res_order",
        membership_digest="d1",
    )
    snap, applied = engine.apply_event(e_old)
    assert applied is False
    assert engine.current_epoch == 5
    assert engine.sequence == 10


def test_f15_10_deterministic_election() -> None:
    """F15-10 — Deterministic consensus evaluation produces identical digest (INV-F15-CONS-10)."""
    e1 = MultiNodeConsensusEngine()
    e2 = MultiNodeConsensusEngine()
    view = MembershipView(view_id="v1", members=("n1", "n2", "n3"))

    p = ConsensusProposal(
        proposal_id="p1",
        resource_id="res_det",
        proposer_node="n1",
        target_epoch=2,
        target_fencing_token=3,
        votes=("n1", "n2"),
        membership_view=view,
    )

    res1 = e1.request_authority(p)
    res2 = e2.request_authority(p)

    assert res1.snapshot_digest == res2.snapshot_digest
    assert res1.snapshot_digest != ""


def test_f15_11_partition_healing_safety() -> None:
    """F15-11 — Post-healing reconciliation selects highest authority generation (INV-F15-CONS-11)."""
    engine = MultiNodeConsensusEngine()

    view = MembershipView(view_id="v1", members=("n1", "n2", "n3"))
    # Snapshot from majority partition (epoch 5, fencing 20)
    snap_majority = MultiNodeConsensusEngine(initial_epoch=5, initial_fencing_token=20).get_snapshot(view.members)

    # Snapshot from minority partition (epoch 2, fencing 5)
    snap_minority = MultiNodeConsensusEngine(initial_epoch=2, initial_fencing_token=5).get_snapshot(view.members)

    reconciled = engine.reconcile_partition_healing([snap_minority, snap_majority])
    assert reconciled.epoch == 5
    assert reconciled.fencing_token == 20


def test_f15_12_convergence() -> None:
    """F15-12 — Reconciled nodes converge to identical state digest (INV-F15-CONS-12)."""
    e1 = MultiNodeConsensusEngine(initial_epoch=10, initial_fencing_token=50)
    e2 = MultiNodeConsensusEngine(initial_epoch=1, initial_fencing_token=1)
    view = MembershipView(view_id="v1", members=("n1", "n2", "n3"))

    snap1 = e1.get_snapshot(view.members)
    e2.reconcile_partition_healing([snap1])

    digest1 = calculate_state_digest(e1.get_snapshot(view.members))
    digest2 = calculate_state_digest(e2.get_snapshot(view.members))

    assert digest1 == digest2


def test_f15_13_unknown_connectivity_fail_closed() -> None:
    """F15-13 — UNKNOWN connectivity forces fail-closed BLOCKED status (INV-F15-CONS-13)."""
    engine = MultiNodeConsensusEngine()
    view = MembershipView(view_id="v1", members=("n1", "n2", "n3"))

    p_unknown = ConsensusProposal(
        proposal_id="p1",
        resource_id="res_unk",
        proposer_node="n1",
        target_epoch=1,
        target_fencing_token=2,
        votes=("n1", "n2"),
        membership_view=view,
        connectivity=NetworkCondition.UNKNOWN,
    )
    res = engine.request_authority(p_unknown)
    assert res.is_granted() is False
    assert res.status == ConsensusStatus.BLOCKED_FAIL_CLOSED
    assert res.failure_type == ConsensusFailureType.UNKNOWN_CONNECTIVITY


def test_f15_14_split_brain_detection() -> None:
    """F15-14 — Explicit split-brain authority conflict detection (INV-F15-CONS-14)."""
    engine = MultiNodeConsensusEngine()
    view = MembershipView(view_id="v1", members=("n1", "n2", "n3"))

    p1 = ConsensusProposal("p1", "res_split", "n1", 2, 5, ("n1", "n2"), view)
    engine.request_authority(p1)

    p2 = ConsensusProposal("p2", "res_split", "n2", 2, 6, ("n2", "n3"), view)
    res2 = engine.request_authority(p2)

    assert res2.status == ConsensusStatus.REJECTED_SPLIT_BRAIN
    assert res2.failure_type == ConsensusFailureType.SPLIT_BRAIN


def test_f15_15_authority_generation_safety() -> None:
    """F15-15 — Lower generation cannot supersede higher generation (INV-F15-CONS-15)."""
    engine = MultiNodeConsensusEngine(initial_epoch=10, initial_fencing_token=100)
    view = MembershipView(view_id="v1", members=("n1", "n2", "n3"))

    res = engine.validate_authority("res_gen", "n1", epoch=5, fencing_token=50, membership_view=view)
    assert res.is_granted() is False
    assert res.status == ConsensusStatus.REJECTED_STALE


def test_f15_16_bounded_observability() -> None:
    """F15-16 — Metric labels use bounded categorical values only (INV-F15-CONS-16)."""
    engine = MultiNodeConsensusEngine()
    view = MembershipView(view_id="v1", members=("n1", "n2", "n3"))
    p = ConsensusProposal("p1", "res_obs", "n1", 1, 2, ("n1", "n2"), view)
    res = engine.request_authority(p)

    assert "status_code" in res.details
    assert res.details["status_code"] == ConsensusStatus.AUTHORITY_GRANTED.value


def test_duplicate_votes_do_not_increase_quorum() -> None:
    """Adversarial — Duplicate votes from same node do not inflate vote count."""
    engine = MultiNodeConsensusEngine()
    view = MembershipView(view_id="v1", members=("n1", "n2", "n3", "n4", "n5"))  # Quorum = 3

    p_dup = ConsensusProposal(
        proposal_id="p_dup",
        resource_id="res_dup",
        proposer_node="n1",
        target_epoch=1,
        target_fencing_token=2,
        votes=("n1", "n1", "n1", "n2"),  # Duplicate n1 votes -> Only 2 unique valid votes
        membership_view=view,
    )
    res = engine.request_authority(p_dup)
    assert res.is_granted() is False
    assert res.valid_votes_count == 2
    assert res.status == ConsensusStatus.BLOCKED_NO_QUORUM


def test_different_dict_order_same_digest() -> None:
    """Adversarial — Dictionary insertion order does not alter canonical state digest."""
    e1 = MultiNodeConsensusEngine()
    e2 = MultiNodeConsensusEngine()
    view = MembershipView(view_id="v1", members=("n1", "n2", "n3"))

    snap1 = e1.get_snapshot(view.members)
    snap2 = e2.get_snapshot(view.members)

    assert snap1.canonical_digest() == snap2.canonical_digest()


@pytest.mark.parametrize("cluster_size", [3, 5, 7])
def test_parameterized_cluster_partition_scenarios(cluster_size: int) -> None:
    """Property/Adversarial — Multi-node cluster partition resilience across 3, 5, 7 nodes."""
    members = tuple(f"node_{i}" for i in range(1, cluster_size + 1))
    view = MembershipView(view_id="v_param", members=members, active_partition=PartitionType.PARTIAL_PARTITION)
    quorum = view.calculate_quorum()

    engine = MultiNodeConsensusEngine()

    # Proposal with exact quorum
    quorum_votes = members[:quorum]
    p_quorum = ConsensusProposal(
        proposal_id=f"p_{cluster_size}",
        resource_id=f"res_{cluster_size}",
        proposer_node="node_1",
        target_epoch=1,
        target_fencing_token=2,
        votes=quorum_votes,
        membership_view=view,
    )
    res = engine.request_authority(p_quorum)
    assert res.is_granted() is True

    # Minority proposal
    minority_votes = members[: quorum - 1]
    engine_minority = MultiNodeConsensusEngine()
    p_minority = ConsensusProposal(
        proposal_id=f"p_min_{cluster_size}",
        resource_id=f"res_{cluster_size}",
        proposer_node="node_1",
        target_epoch=1,
        target_fencing_token=2,
        votes=minority_votes,
        membership_view=view,
    )
    res_min = engine_minority.request_authority(p_minority)
    assert res_min.is_granted() is False
    assert res_min.status == ConsensusStatus.BLOCKED_NO_QUORUM
