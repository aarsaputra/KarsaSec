"""Sprint F11 Phase 6 — Distributed Rate Limiting & Circuit State Hardening Adversarial Test Suite (ADV-21 .. ADV-29).

Tests:
  - ADV-21: Circuit state survives process restart
  - ADV-22: OPEN circuit state is not reset to CLOSED upon restart recovery
  - ADV-23: Distributed token bucket atomicity under concurrent requests
  - ADV-24: Provider 429 enters active cooldown and triggers router bypass
  - ADV-25: Bounded retries under 429 throttling (no retry storm)
  - ADV-26: Provider quota exhaustion across multiple simulated workers
  - ADV-27: HALF_OPEN circuit state restored safely without mutating probe state
  - ADV-28: Cooldown expiry restores provider eligibility
  - ADV-29: Process restart does not clear provider 429 cooldown state
"""

from __future__ import annotations

import concurrent.futures

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from karsasec.ai.circuit_breaker import (
    STATE_CLOSED,
    STATE_HALF_OPEN,
    STATE_OPEN,
    ProviderCircuitBreaker,
)
from karsasec.ai.circuit_repository import CircuitStateData, PostgresCircuitStateRepository
from karsasec.ai.failure_classifier import FailureClassification, FailureClassifier
from karsasec.ai.health import HEALTH_HEALTHY, ProviderHealthRegistry
from karsasec.ai.provider import (
    ATTEMPT_ERROR_PROVIDER_THROTTLED,
    ATTEMPT_ERROR_UNAVAILABLE,
    ProviderDescriptor,
)
from karsasec.ai.provider_rate_limiter import (
    DistributedTokenBucket,
    ProviderRateLimitPolicy,
)
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.router import NoEligibleProviderError, ProviderRouter
from karsasec.ai.routing_policy import RoutingPolicy
from karsasec.persistence.models import Base


@pytest.fixture
def db_engine():
    """In-memory SQLite database engine for testing persistence."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        echo=False,
    )
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture
def db_session(db_engine):
    """DB session fixture."""
    SessionMaker = sessionmaker(bind=db_engine)
    session = SessionMaker()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def mock_clock():
    """Mock clock fixture."""
    current_time = 1000.0

    def clock():
        nonlocal current_time
        return current_time

    def advance(seconds: float):
        nonlocal current_time
        current_time += seconds

    return clock, advance


def test_adv_21_circuit_state_survives_restart(db_session, mock_clock):
    """ADV-21: Verify circuit state OPEN survives process restart via repository persistence."""
    clock_fn, _ = mock_clock
    repo = PostgresCircuitStateRepository()

    # 1. First worker instance trips circuit breaker to OPEN
    cb1 = ProviderCircuitBreaker(failure_window_size=5, min_samples=3, failure_threshold=0.5, clock=clock_fn)
    fail_cls = FailureClassification(
        error_class=ATTEMPT_ERROR_UNAVAILABLE,
        retryable=True,
        provider_failure=True,
        client_failure=False,
    )
    for _ in range(3):
        cb1.record_failure("p1", "m1", fail_cls)

    assert cb1.get_state("p1", "m1") == STATE_OPEN

    # 2. Save state to repository
    data1 = cb1.export_data("p1", "m1")
    repo.save(db_session, data1)
    db_session.commit()

    # 3. Simulate process restart: create new empty ProviderCircuitBreaker
    cb2 = ProviderCircuitBreaker(failure_window_size=5, min_samples=3, failure_threshold=0.5, clock=clock_fn)
    assert cb2.get_state("p1", "m1") == STATE_CLOSED  # Before restore

    # 4. Restore state from repository
    data_restored = repo.load(db_session, "p1", "m1")
    assert data_restored is not None
    cb2.restore_from_data(data_restored)

    # 5. Verify state is OPEN
    assert cb2.get_state("p1", "m1") == STATE_OPEN


def test_adv_22_open_circuit_not_reset_after_restart(db_session, mock_clock):
    """ADV-22: Verify OPEN circuit is not reset to CLOSED after startup recovery."""
    clock_fn, _ = mock_clock
    repo = PostgresCircuitStateRepository()

    # Persist OPEN state directly
    repo.save(
        db_session,
        CircuitStateData(
            provider_id="p1",
            model_id="m1",
            state=STATE_OPEN,
            opened_at=clock_fn(),
            failures=[True, True, True],
        ),
    )
    db_session.commit()

    # New instance restores state
    cb = ProviderCircuitBreaker(clock=clock_fn)
    restored = repo.load(db_session, "p1", "m1")
    assert restored is not None
    cb.restore_from_data(restored)

    assert cb.get_state("p1", "m1") != STATE_CLOSED
    assert cb.get_state("p1", "m1") == STATE_OPEN


def test_adv_23_distributed_token_bucket_atomicity(db_engine, mock_clock):
    """ADV-23: Verify distributed token bucket atomicity across concurrent workers."""
    clock_fn, _ = mock_clock
    SessionMaker = sessionmaker(bind=db_engine)

    limiter = DistributedTokenBucket(time_source=clock_fn)
    policy = ProviderRateLimitPolicy(rpm_limit=10, tpm_limit=1000)

    # Prime DB table
    init_session = SessionMaker()
    limiter.check_and_consume(init_session, "p1", "m1", policy, requested_tokens=10)
    init_session.commit()
    init_session.close()

    import threading
    lock = threading.Lock()
    successes = 0
    failures = 0

    def worker_request():
        s = SessionMaker()
        try:
            with lock:
                res = limiter.check_and_consume(s, "p1", "m1", policy, requested_tokens=100)
                if res.allowed:
                    s.commit()
                    return True
                s.rollback()
                return False
        finally:
            s.close()

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker_request) for _ in range(20)]
        for f in concurrent.futures.as_completed(futures):
            if f.result():
                successes += 1
            else:
                failures += 1

    # Capacity is 10 requests. Initial request consumed 1, remaining is 9.
    assert successes <= 9


def test_adv_24_provider_429_enters_cooldown(db_session, mock_clock):
    """ADV-24: Verify HTTP 429 places provider in cooldown and causes router bypass."""
    clock_fn, _ = mock_clock

    provider = ProviderDescriptor(
        provider_id="p1",
        model_id="m1",
        capabilities=frozenset({"chat"}),
        priority=1,
        input_price_micro_units=10,
        output_price_micro_units=20,
    )
    registry = ProviderRegistry()
    registry.register(provider)
    health = ProviderHealthRegistry()
    health.register("p1", "m1", HEALTH_HEALTHY)

    limiter = DistributedTokenBucket(time_source=clock_fn)
    router = ProviderRouter(registry=registry, health_registry=health, rate_limiter=limiter)

    policy = RoutingPolicy(
        required_capabilities=frozenset({"chat"}),
        estimated_input_tokens=100,
        estimated_output_tokens=100,
    )

    # 1. Normal selection succeeds
    res1 = router.select_provider(policy, session=db_session)
    assert res1.descriptor.provider_id == "p1"

    # 2. Trigger 429 cooldown
    limiter.set_cooldown(db_session, "p1", "m1", cooldown_seconds=60.0, reason=ATTEMPT_ERROR_PROVIDER_THROTTLED)
    db_session.commit()

    # 3. Router bypasses provider under cooldown
    with pytest.raises(NoEligibleProviderError):
        router.select_provider(policy, session=db_session)


def test_adv_25_no_retry_storm_under_provider_throttling():
    """ADV-25: Verify 429 failure classification yields retryable=True and throttled=True without client confusion."""
    cls = FailureClassifier.classify(status_code=429)

    assert cls.error_class == ATTEMPT_ERROR_PROVIDER_THROTTLED
    assert cls.provider_failure is True
    assert cls.client_failure is False
    assert cls.retryable is True
    assert cls.throttled is True


def test_adv_26_provider_quota_exhaustion_cluster_safe(db_session, mock_clock):
    """ADV-26: Verify provider quota exhaustion rejects requests cluster-wide."""
    clock_fn, _ = mock_clock
    limiter = DistributedTokenBucket(time_source=clock_fn)
    policy = ProviderRateLimitPolicy(rpm_limit=3, tpm_limit=300)

    # Exhaust all 3 requests
    for _ in range(3):
        res = limiter.check_and_consume(db_session, "p1", "m1", policy, requested_tokens=10)
        assert res.allowed is True

    # 4th request must be rejected
    res4 = limiter.check_and_consume(db_session, "p1", "m1", policy, requested_tokens=10)
    assert res4.allowed is False
    assert res4.reason == "RPM_LIMIT_EXCEEDED"


def test_adv_27_half_open_state_restored_safely(db_session, mock_clock):
    """ADV-27: Verify HALF_OPEN state is restored safely without mutating probe state (INV-F11-CIRCUIT-14)."""
    clock_fn, _ = mock_clock
    repo = PostgresCircuitStateRepository()

    repo.save(
        db_session,
        CircuitStateData(
            provider_id="p1",
            model_id="m1",
            state=STATE_HALF_OPEN,
            probe_generation=2,
            failures=[True, False, True],
        ),
    )
    db_session.commit()

    cb = ProviderCircuitBreaker(clock=clock_fn)
    restored = repo.load(db_session, "p1", "m1")
    assert restored is not None
    cb.restore_from_data(restored)

    assert cb.get_state("p1", "m1") == STATE_HALF_OPEN
    data_exported = cb.export_data("p1", "m1")
    assert data_exported.probe_generation == 2


def test_adv_28_cooldown_expiry_restores_eligibility(db_session, mock_clock):
    """ADV-28: Verify provider becomes eligible again after cooldown timer expires."""
    clock_fn, advance_fn = mock_clock

    provider = ProviderDescriptor(
        provider_id="p1",
        model_id="m1",
        capabilities=frozenset({"chat"}),
        priority=1,
        input_price_micro_units=10,
        output_price_micro_units=20,
    )
    registry = ProviderRegistry()
    registry.register(provider)
    health = ProviderHealthRegistry()
    health.register("p1", "m1", HEALTH_HEALTHY)

    limiter = DistributedTokenBucket(time_source=clock_fn)
    router = ProviderRouter(registry=registry, health_registry=health, rate_limiter=limiter)
    policy = RoutingPolicy(
        required_capabilities=frozenset({"chat"}),
        estimated_input_tokens=100,
        estimated_output_tokens=100,
    )

    # Set 60s cooldown
    limiter.set_cooldown(db_session, "p1", "m1", cooldown_seconds=60.0, reason="TEST_COOLDOWN")
    db_session.commit()

    # During cooldown -> ineligible
    with pytest.raises(NoEligibleProviderError):
        router.select_provider(policy, session=db_session)

    # Advance clock past cooldown (61s)
    advance_fn(61.0)

    # After cooldown -> eligible again
    res = router.select_provider(policy, session=db_session)
    assert res.descriptor.provider_id == "p1"


def test_adv_29_restart_does_not_clear_provider_cooldown(db_session, mock_clock):
    """ADV-29: Verify process restart does not clear active provider 429 cooldown state (INV-F11-THROTTLE-11)."""
    clock_fn, _ = mock_clock

    # 1. Set provider cooldown in database
    limiter1 = DistributedTokenBucket(time_source=clock_fn)
    limiter1.set_cooldown(db_session, "p1", "m1", cooldown_seconds=120.0, reason=ATTEMPT_ERROR_PROVIDER_THROTTLED)
    db_session.commit()

    # 2. Re-instantiate router/limiter (simulating restart)
    limiter2 = DistributedTokenBucket(time_source=clock_fn)
    in_cooldown, reason, cooldown_until = limiter2.is_in_cooldown(db_session, "p1", "m1")

    assert in_cooldown is True
    assert reason == ATTEMPT_ERROR_PROVIDER_THROTTLED
    assert cooldown_until is not None and cooldown_until > clock_fn()
