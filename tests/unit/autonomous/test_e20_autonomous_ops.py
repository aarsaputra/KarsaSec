"""Unit and Invariant test suite for Sprint E20: Autonomous Security Operations."""

from karsasec.autonomous.circuit_breaker import CircuitBreakerEngine
from karsasec.autonomous.engine import AutonomousOpsEngine
from karsasec.autonomous.models import CircuitBreakerBudget


def test_circuit_breaker_budget_and_trip():
    budget = CircuitBreakerBudget.create(action_budget=2)
    cb = CircuitBreakerEngine(budget)

    ok1, r1 = cb.check_and_consume()
    assert ok1 is True

    ok2, r2 = cb.check_and_consume()
    assert ok2 is True

    ok3, r3 = cb.check_and_consume()
    assert ok3 is False
    assert cb.is_tripped is True


def test_autonomous_engine_shadow_mode_default():
    engine = AutonomousOpsEngine(is_shadow_mode=True)
    prop = engine.propose_action(
        target_id="APP-1",
        action_type="AUTO_BLOCK",
        cluster_id="CL-1",
    )
    assert prop.requires_human_approval is True

    res = engine.execute_proposal(prop)
    assert res.executed is False
    assert res.status == "SHADOW_MODE_PROPOSAL"


def test_autonomous_engine_active_mode_budget_enforcement():
    budget = CircuitBreakerBudget.create(max_auto_block_per_window=1, action_budget=10)
    engine = AutonomousOpsEngine(budget=budget, is_shadow_mode=False)

    prop1 = engine.propose_action("APP-1", "AUTO_BLOCK", "CL-1")
    res1 = engine.execute_proposal(prop1)
    assert res1.executed is True

    prop2 = engine.propose_action("APP-1", "AUTO_BLOCK", "CL-2")
    res2 = engine.execute_proposal(prop2)
    assert res2.executed is False
    assert res2.status == "CIRCUIT_BREAKER_BLOCKED"


def test_circuit_breaker_time_and_retry_budget():
    import time
    budget = CircuitBreakerBudget.create(time_budget_seconds=1, retry_budget=1)
    cb = CircuitBreakerEngine(budget)

    ok_retry, _ = cb.check_and_consume(is_retry=True)
    assert ok_retry is True

    ok_retry2, _ = cb.check_and_consume(is_retry=True)
    assert ok_retry2 is False
    assert cb.is_tripped is True

    cb_time = CircuitBreakerEngine(CircuitBreakerBudget.create(time_budget_seconds=1))
    time.sleep(1.1)
    ok_time, _ = cb_time.check_and_consume()
    assert ok_time is False
    assert cb_time.is_tripped is True
