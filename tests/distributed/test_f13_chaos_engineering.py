"""Unit test suite for Sprint F13 — Chaos Engineering Framework.

Verifies invariants INV-F13-01 through INV-F13-08 across network partitions, clock drift, node crashes,
and fault campaign determinism.
"""

from karsasec.analysis.distributed.chaos import (
    ChaosExperimentStatus,
    ChaosFaultCategory,
    ChaosFaultConfig,
    ChaosFaultInjector,
    verify_chaos_resilience,
)
from karsasec.analysis.distributed.certification import (
    DistributedGateState,
    DistributedIntegrityStatus,
)


def test_f13_01_network_partition_fails_closed() -> None:
    """F13-01 — Synthetic network partition forces fail-closed BLOCKED status (INV-F13-02)."""
    cfg = ChaosFaultConfig(fault_category=ChaosFaultCategory.NETWORK_PARTITION)
    res = verify_chaos_resilience(fault_config=cfg)

    assert res.resilient is True
    assert res.status == ChaosExperimentStatus.BLOCKED_FAIL_CLOSED
    assert res.gate_state == DistributedGateState.BLOCKED
    assert res.integrity_status == DistributedIntegrityStatus.SPLIT_BRAIN_RISK


def test_f13_02_clock_drift_exceeding_threshold_fences_node() -> None:
    """F13-02 — Clock drift > 500ms forces fencing lock (INV-F13-03)."""
    cfg = ChaosFaultConfig(fault_category=ChaosFaultCategory.CLOCK_DRIFT, clock_drift_ms=750)
    res = verify_chaos_resilience(fault_config=cfg)

    assert res.resilient is True
    assert res.status == ChaosExperimentStatus.BLOCKED_FAIL_CLOSED
    assert res.gate_state == DistributedGateState.BLOCKED
    assert res.integrity_status == DistributedIntegrityStatus.STALE_TOKEN


def test_f13_03_node_crash_recovery_verifies_preconditions() -> None:
    """F13-03 — Crashed node re-verifies preconditions on restart and achieves READY (INV-F13-04)."""
    cfg = ChaosFaultConfig(fault_category=ChaosFaultCategory.NODE_CRASH)
    res = verify_chaos_resilience(fault_config=cfg)

    assert res.resilient is True
    assert res.status == ChaosExperimentStatus.PASSED
    assert res.gate_state == DistributedGateState.READY
    assert res.integrity_status == DistributedIntegrityStatus.VALID


def test_f13_04_network_latency_maintains_fail_closed_guarantees() -> None:
    """F13-04 — Latency spikes preserve valid precondition check (INV-F13-01)."""
    cfg = ChaosFaultConfig(fault_category=ChaosFaultCategory.NETWORK_LATENCY, latency_spike_ms=2000)
    res = verify_chaos_resilience(fault_config=cfg)

    assert res.resilient is True
    assert res.gate_state == DistributedGateState.READY


def test_f13_05_chaos_campaign_determinism() -> None:
    """F13-05 — Chaos campaign with fixed seed produces 100% deterministic experiment results (INV-F13-06)."""
    injector = ChaosFaultInjector()
    campaign = [
        ChaosFaultConfig(fault_category=ChaosFaultCategory.NETWORK_PARTITION, seed=100),
        ChaosFaultConfig(fault_category=ChaosFaultCategory.CLOCK_DRIFT, clock_drift_ms=600, seed=101),
        ChaosFaultConfig(fault_category=ChaosFaultCategory.NODE_CRASH, seed=102),
        ChaosFaultConfig(fault_category=ChaosFaultCategory.PACKET_LOSS, seed=103),
    ]

    res1 = injector.run_campaign(campaign)
    res2 = injector.run_campaign(campaign)

    assert len(res1) == len(res2) == 4
    for r1, r2 in zip(res1, res2, strict=True):
        assert r1.experiment_id == r2.experiment_id
        assert r1.status == r2.status
        assert r1.gate_state == r2.gate_state
        assert r1.integrity_status == r2.integrity_status
