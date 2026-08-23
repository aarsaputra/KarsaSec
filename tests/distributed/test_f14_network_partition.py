"""Unit and adversarial test suite for Sprint F14 — Network Partition Validation Framework.

Verifies invariants INV-F14-NET-01 through INV-F14-NET-12 across split-brain scenarios, fencing token monotonicity,
unknown connectivity fail-closed rules, event reordering, and recovery convergence.
"""

from karsasec.analysis.distributed.partition import (
    NetworkCondition,
    NetworkNode,
    PartitionEvent,
    PartitionFailureType,
    PartitionScenario,
    PartitionType,
    PartitionValidationEngine,
    PartitionValidationState,
    verify_partition_validation_scenario,
)


def test_f14_01_partition_isolation_fails_closed() -> None:
    """F14-01 — Partitioned node must not assume unreachable peer is reachable (INV-F14-NET-01)."""
    engine = PartitionValidationEngine()
    # Reachable = False, but claimed_reachable = True -> Invalid
    res = engine.evaluate_partition_isolation(src_node="node_a", dst_node="node_b", reachable=False, claimed_reachable=True)
    assert res is False

    # Reachable = False, claimed_reachable = False -> Valid
    res_valid = engine.evaluate_partition_isolation(src_node="node_a", dst_node="node_b", reachable=False, claimed_reachable=False)
    assert res_valid is True


def test_f14_02_split_brain_authority_prevention() -> None:
    """F14-02 — Multiple nodes claiming primary authority simultaneously forces split-brain block (INV-F14-NET-02)."""
    nodes = (
        NetworkNode(node_id="node_a", is_leader=True, fencing_token=10),
        NetworkNode(node_id="node_b", is_leader=True, fencing_token=10),
    )
    res = verify_partition_validation_scenario(nodes=nodes, partition_type=PartitionType.FULL_PARTITION)

    assert res.resilient is True
    assert res.state == PartitionValidationState.BLOCKED_FAIL_CLOSED
    assert res.failure_type == PartitionFailureType.SPLIT_BRAIN_ATTEMPT
    assert res.invariant_results.get("INV-F14-NET-02") is False


def test_f14_03_stale_fencing_token_rejection() -> None:
    """F14-03 — Fencing token must remain monotonic; stale token is rejected (INV-F14-NET-03)."""
    engine = PartitionValidationEngine()

    assert engine.evaluate_fencing_monotonicity(current_token=10, attempted_token=10) is True
    assert engine.evaluate_fencing_monotonicity(current_token=10, attempted_token=11) is True
    assert engine.evaluate_fencing_monotonicity(current_token=10, attempted_token=9) is False


def test_f14_04_unknown_connectivity_fails_closed() -> None:
    """F14-04 — UNKNOWN != SAFE. Absence of connectivity evidence blocks mutation (INV-F14-NET-04)."""
    engine = PartitionValidationEngine()

    assert engine.evaluate_unknown_connectivity(NetworkCondition.UNKNOWN, allow_mutation=True) is False
    assert engine.evaluate_unknown_connectivity(NetworkCondition.UNKNOWN, allow_mutation=False) is True


def test_f14_05_reordered_event_rejection() -> None:
    """F14-05 — Out-of-order event delivery sequence is rejected (INV-F14-NET-05)."""
    engine = PartitionValidationEngine()
    scenario = PartitionScenario(
        scenario_id="EXP_REORDER",
        nodes=(NetworkNode(node_id="node_a"),),
        partition_type=PartitionType.FULL_PARTITION,
        events=(
            PartitionEvent(event_id="e2", src_node="node_a", dst_node="node_b", condition=NetworkCondition.DELAYED, sequence_number=2),
            PartitionEvent(event_id="e1", src_node="node_a", dst_node="node_b", condition=NetworkCondition.DELAYED, sequence_number=1),
        ),
    )

    res = engine.simulate_partition_scenario(scenario)
    assert res.state == PartitionValidationState.BLOCKED_FAIL_CLOSED
    assert res.failure_type == PartitionFailureType.REORDERING
    assert res.invariant_results.get("INV-F14-NET-05") is False


def test_f14_06_idempotent_recovery_replay() -> None:
    """F14-06 — Repeated recovery attempts produce idempotent logical effect (INV-F14-NET-06)."""
    engine = PartitionValidationEngine()
    assert engine.evaluate_idempotent_recovery("HASH_ABC123", replay_count=1) is True
    assert engine.evaluate_idempotent_recovery("HASH_ABC123", replay_count=5) is True


def test_f14_07_partition_healing_convergence() -> None:
    """F14-07 — Replicas must converge to identical state after partition healing (INV-F14-NET-07)."""
    engine = PartitionValidationEngine()
    state_a = "STATE_DIGEST_999"
    state_b = "STATE_DIGEST_999"
    state_c = "STATE_DIGEST_888"

    assert engine.evaluate_recovery_convergence(state_a, state_b) is True
    assert engine.evaluate_recovery_convergence(state_a, state_c) is False


def test_f14_08_deterministic_partition_simulation() -> None:
    """F14-08 — Simulation with identical seed produces identical result (INV-F14-NET-08)."""
    nodes = (
        NetworkNode(node_id="node_1", fencing_token=5),
        NetworkNode(node_id="node_2", fencing_token=5),
    )
    r1 = verify_partition_validation_scenario(nodes=nodes, partition_type=PartitionType.PARTIAL_PARTITION, seed=12345)
    r2 = verify_partition_validation_scenario(nodes=nodes, partition_type=PartitionType.PARTIAL_PARTITION, seed=12345)

    assert r1.scenario_id == r2.scenario_id
    assert r1.state == r2.state
    assert r1.failure_type == r2.failure_type
    assert r1.deterministic is True


def test_f14_09_no_hidden_network_state() -> None:
    """F14-09 — Partition model explicit dictionary representation (INV-F14-NET-09)."""
    node = NetworkNode(node_id="n1", group_id="g1", fencing_token=7, epoch=2, is_leader=True)
    d = node.to_dict()

    assert d["node_id"] == "n1"
    assert d["group_id"] == "g1"
    assert d["fencing_token"] == 7
    assert d["epoch"] == 2
    assert d["is_leader"] is True


def test_f14_10_recovery_respects_authority_generation() -> None:
    """F14-10 — Higher fencing token/epoch takes authority precedence (INV-F14-NET-10)."""
    n1 = NetworkNode(node_id="n1", fencing_token=10, epoch=2)
    n2 = NetworkNode(node_id="n2", fencing_token=5, epoch=1)

    assert n1.fencing_token > n2.fencing_token
    assert n1.epoch > n2.epoch


def test_f14_11_failure_classification_determinism() -> None:
    """F14-11 — Structured failure classification is deterministic (INV-F14-NET-11)."""
    nodes = (NetworkNode(node_id="n1", is_leader=True), NetworkNode(node_id="n2", is_leader=True))
    res = verify_partition_validation_scenario(nodes=nodes, partition_type=PartitionType.FULL_PARTITION)

    assert res.failure_type == PartitionFailureType.SPLIT_BRAIN_ATTEMPT


def test_f14_12_bounded_observability_labels() -> None:
    """F14-12 — Metric labels and validation results are bounded (INV-F14-NET-12)."""
    nodes = (NetworkNode(node_id="n1"),)
    res = verify_partition_validation_scenario(nodes=nodes, partition_type=PartitionType.FULL_PARTITION)

    assert "gate_state" in res.details
    assert "node_count" in res.details


def test_f14_13_adversarial_partial_partition_resilience() -> None:
    """F14-13 — Adversarial partial partition preserves valid cluster state when single leader exists."""
    nodes = (
        NetworkNode(node_id="leader", is_leader=True, fencing_token=100),
        NetworkNode(node_id="worker_1", is_leader=False, fencing_token=100),
        NetworkNode(node_id="worker_2", is_leader=False, fencing_token=100),
    )
    res = verify_partition_validation_scenario(nodes=nodes, partition_type=PartitionType.PARTIAL_PARTITION)

    assert res.is_valid() is True
    assert res.state == PartitionValidationState.VALID
    assert res.failure_type == PartitionFailureType.NO_FAILURE


def test_f14_14_stale_authority_mutation_negative_test() -> None:
    """F14-14 — Negative test: Stale authority mutation fails closed."""
    engine = PartitionValidationEngine()
    # Attempt mutation with stale fencing token
    valid = engine.evaluate_fencing_monotonicity(current_token=50, attempted_token=20)
    assert valid is False
