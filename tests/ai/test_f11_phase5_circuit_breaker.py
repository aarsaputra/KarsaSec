"""Unit and adversarial tests for Sprint F11.5 Provider Circuit Breaker (INV-F11-CIRCUIT-05, ADV-05)."""

import hashlib
from typing import Any
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from karsasec.ai.circuit_breaker import (
    STATE_CLOSED,
    STATE_HALF_OPEN,
    STATE_OPEN,
    ProviderCircuitBreaker,
)
from karsasec.ai.execution import (
    ProviderExecutionRequest,
    ProviderExecutionResponse,
    ProviderExecutionService,
)
from karsasec.ai.failure_classifier import FailureClassification
from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.provider import (
    ATTEMPT_ERROR_INVALID_REQUEST,
    ATTEMPT_ERROR_UNAVAILABLE,
    ProviderDescriptor,
)
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.retry import RetryPolicy
from karsasec.ai.router import NoEligibleProviderError, ProviderRouter
from karsasec.ai.routing_policy import RoutingPolicy
from karsasec.persistence.models import AIBudgetModel, Base


class MockClock:
    """Deterministic injectable clock for testing time-dependent circuit state transitions."""

    def __init__(self, start_time: float = 1000.0) -> None:
        self.current_time = start_time

    def now(self) -> float:
        return self.current_time

    def advance(self, seconds: float) -> None:
        self.current_time += seconds


class MultiProviderExecutor:
    """Mock executor tracking invocation count per provider."""

    def __init__(self, failure_configs: dict[str, Any] | None = None) -> None:
        self.failure_configs = failure_configs or {}
        self.invocation_counts: dict[str, int] = {}

    def execute_attempt(
        self,
        descriptor: ProviderDescriptor,
        request: ProviderExecutionRequest,
        attempt_number: int,
    ) -> ProviderExecutionResponse:
        self.invocation_counts[descriptor.provider_id] = self.invocation_counts.get(descriptor.provider_id, 0) + 1
        cfg = self.failure_configs.get(descriptor.provider_id, {})

        should_fail = cfg.get("should_fail", False)
        error_class = cfg.get("error_class", ATTEMPT_ERROR_UNAVAILABLE)

        if should_fail:
            return ProviderExecutionResponse(
                request_id=request.request_id,
                attempt_number=attempt_number,
                provider_id=descriptor.provider_id,
                model_id=descriptor.model_id,
                success=False,
                error_class=error_class,
            )

        return ProviderExecutionResponse(
            request_id=request.request_id,
            attempt_number=attempt_number,
            provider_id=descriptor.provider_id,
            model_id=descriptor.model_id,
            success=True,
            content=f"Successful response from {descriptor.provider_id}",
        )


@pytest.fixture
def db_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


def test_circuit_breaker_states_and_transitions() -> None:
    """Unit test for CLOSED -> OPEN -> HALF_OPEN -> CLOSED lifecycle."""
    clock = MockClock(100.0)
    cb = ProviderCircuitBreaker(
        failure_window_size=5,
        failure_threshold=0.5,
        min_samples=4,
        cooldown_seconds=30.0,
        half_open_max_probes=1,
        clock=clock.now,
    )

    # Initial state CLOSED
    assert cb.get_state("openai", "gpt-4o") == STATE_CLOSED
    assert cb.is_open("openai", "gpt-4o") is False

    # 3 failures out of 4 samples (75% failure rate >= 50% threshold)
    prov_failure = FailureClassification(
        error_class=ATTEMPT_ERROR_UNAVAILABLE,
        client_failure=False,
        provider_failure=True,
        retryable=True,
    )
    cb.record_failure("openai", "gpt-4o", prov_failure)
    cb.record_failure("openai", "gpt-4o", prov_failure)
    cb.record_success("openai", "gpt-4o")
    cb.record_failure("openai", "gpt-4o", prov_failure)

    # Should trip to OPEN
    assert cb.get_state("openai", "gpt-4o") == STATE_OPEN
    assert cb.is_open("openai", "gpt-4o") is True

    # Advance clock past cooldown (30s)
    clock.advance(35.0)

    # Probe 1 in HALF_OPEN
    assert cb.is_open("openai", "gpt-4o") is False  # First probe allowed!
    assert cb.get_state("openai", "gpt-4o") == STATE_HALF_OPEN

    # Concurrent second probe in HALF_OPEN blocked
    assert cb.is_open("openai", "gpt-4o") is True

    # Probe succeeds -> transitions to CLOSED
    cb.record_success("openai", "gpt-4o")
    assert cb.get_state("openai", "gpt-4o") == STATE_CLOSED
    assert cb.is_open("openai", "gpt-4o") is False


def test_4xx_poisoning_defense() -> None:
    """INV-F11-FAILURE-15: 20 HTTP 400 client errors must NOT trip the circuit breaker."""
    cb = ProviderCircuitBreaker(
        failure_window_size=10,
        failure_threshold=0.5,
        min_samples=5,
    )

    client_failure = FailureClassification(
        error_class=ATTEMPT_ERROR_INVALID_REQUEST,
        client_failure=True,
        provider_failure=False,
        retryable=False,
    )

    # Inject 20 client failures
    for _ in range(20):
        cb.record_failure("openai", "gpt-4o", client_failure)

    # Circuit MUST remain CLOSED
    assert cb.get_state("openai", "gpt-4o") == STATE_CLOSED
    assert cb.is_open("openai", "gpt-4o") is False


def test_half_open_failure_reopens_circuit() -> None:
    """HALF_OPEN failure test: Failed probe transitions HALF_OPEN -> OPEN immediately."""
    clock = MockClock(100.0)
    cb = ProviderCircuitBreaker(
        min_samples=2,
        failure_threshold=0.5,
        cooldown_seconds=30.0,
        clock=clock.now,
    )

    prov_failure = FailureClassification(
        error_class=ATTEMPT_ERROR_UNAVAILABLE,
        client_failure=False,
        provider_failure=True,
        retryable=True,
    )
    cb.record_failure("openai", "gpt-4o", prov_failure)
    cb.record_failure("openai", "gpt-4o", prov_failure)

    assert cb.get_state("openai", "gpt-4o") == STATE_OPEN

    # Cooldown expires
    clock.advance(31.0)
    assert cb.is_open("openai", "gpt-4o") is False  # enters HALF_OPEN, probe allowed

    # Probe fails
    cb.record_failure("openai", "gpt-4o", prov_failure)
    assert cb.get_state("openai", "gpt-4o") == STATE_OPEN
    assert cb.is_open("openai", "gpt-4o") is True


def test_adv_05_circuit_breaker_trips_open_on_5xx_threshold(db_session: Session) -> None:
    """ADV-05: Verifies that circuit breaker trips OPEN on 5xx threshold, skipping executor & falling back."""
    budget = AIBudgetModel(
        budget_id="b-adv05",
        tenant_id="tenant-1",
        token_limit=5000,
        cost_limit_micro_units=50000,
    )
    db_session.add(budget)
    db_session.flush()

    desc_a = ProviderDescriptor(
        provider_id="provider-a",
        model_id="model-a",
        capabilities=frozenset({"chat"}),
        priority=1,
        input_price_micro_units=10,
        output_price_micro_units=20,
    )
    desc_b = ProviderDescriptor(
        provider_id="provider-b",
        model_id="model-b",
        capabilities=frozenset({"chat"}),
        priority=2,
        input_price_micro_units=10,
        output_price_micro_units=20,
    )

    reg = ProviderRegistry()
    reg.register(desc_a)
    reg.register(desc_b)

    health_reg = ProviderHealthRegistry()
    health_reg.register("provider-a", "model-a")
    health_reg.register("provider-b", "model-b")

    clock = MockClock(100.0)
    cb = ProviderCircuitBreaker(
        failure_window_size=10,
        failure_threshold=0.5,
        min_samples=3,
        cooldown_seconds=30.0,
        clock=clock.now,
    )

    router = ProviderRouter(registry=reg, health_registry=health_reg, circuit_breaker=cb)

    # Provider A configured to fail with HTTP 500; Provider B works normally
    executor = MultiProviderExecutor(
        failure_configs={
            "provider-a": {"should_fail": True, "error_class": ATTEMPT_ERROR_UNAVAILABLE},
            "provider-b": {"should_fail": False},
        }
    )

    service = ProviderExecutionService(
        router=router,
        executor=executor,
        retry_policy=RetryPolicy(max_attempts=1),
        circuit_breaker=cb,
    )

    policy = RoutingPolicy(
        required_capabilities=frozenset({"chat"}),
        estimated_input_tokens=50,
        estimated_output_tokens=50,
    )

    # Execute 3 requests to trigger 3 provider failures on provider-a
    for i in range(3):
        prompt = f"Request {i}"
        req = ProviderExecutionRequest(
            request_id=f"req-a-{i}",
            task_id="task-1",
            budget_id="b-adv05",
            prompt=prompt,
            prompt_hash=hashlib.sha256(prompt.encode()).hexdigest(),
            context_hash=hashlib.sha256(b"ctx").hexdigest(),
            max_attempts=1,
        )
        service.execute(session=db_session, policy=policy, request=req)

    # Assert provider-a circuit is now OPEN
    assert cb.get_state("provider-a", "model-a") == STATE_OPEN
    assert executor.invocation_counts["provider-a"] == 3

    # Next request: provider-a MUST be bypassed by ProviderRouter, falling back to provider-b
    prompt_fallback = "Fallback Request"
    req_fallback = ProviderExecutionRequest(
        request_id="req-fallback",
        task_id="task-1",
        budget_id="b-adv05",
        prompt=prompt_fallback,
        prompt_hash=hashlib.sha256(prompt_fallback.encode()).hexdigest(),
        context_hash=hashlib.sha256(b"ctx").hexdigest(),
        max_attempts=1,
    )

    resp = service.execute(session=db_session, policy=policy, request=req_fallback)

    # ADV-05 Assertions
    assert resp.success is True
    assert resp.provider_id == "provider-b"
    assert executor.invocation_counts["provider-a"] == 3, "OPEN provider-a MUST NOT receive network calls"
    assert executor.invocation_counts["provider-b"] == 1, "Fallback provider-b MUST be executed"


def test_open_circuit_all_providers_bypassed_raises_no_eligible(db_session: Session) -> None:
    """OPEN bypass test: When all providers are OPEN, ProviderRouter immediately raises NoEligibleProviderError."""
    budget = AIBudgetModel(
        budget_id="b-no-elig",
        tenant_id="tenant-1",
        token_limit=5000,
        cost_limit_micro_units=50000,
    )
    db_session.add(budget)
    db_session.flush()

    desc = ProviderDescriptor(
        provider_id="provider-sole",
        model_id="model-sole",
        capabilities=frozenset({"chat"}),
        priority=1,
        input_price_micro_units=10,
        output_price_micro_units=20,
    )
    reg = ProviderRegistry()
    reg.register(desc)
    health_reg = ProviderHealthRegistry()
    health_reg.register("provider-sole", "model-sole")

    cb = ProviderCircuitBreaker(min_samples=1, failure_threshold=0.5)
    # Manually trip circuit
    prov_failure = FailureClassification(
        error_class=ATTEMPT_ERROR_UNAVAILABLE,
        client_failure=False,
        provider_failure=True,
        retryable=True,
    )
    cb.record_failure("provider-sole", "model-sole", prov_failure)

    router = ProviderRouter(registry=reg, health_registry=health_reg, circuit_breaker=cb)
    executor = MultiProviderExecutor()
    service = ProviderExecutionService(router=router, executor=executor, circuit_breaker=cb)

    policy = RoutingPolicy(
        required_capabilities=frozenset({"chat"}),
        estimated_input_tokens=50,
        estimated_output_tokens=50,
    )
    prompt = "Test open sole provider"
    req = ProviderExecutionRequest(
        request_id="req-sole-open",
        task_id="task-1",
        budget_id="b-no-elig",
        prompt=prompt,
        prompt_hash=hashlib.sha256(prompt.encode()).hexdigest(),
        context_hash=hashlib.sha256(b"ctx").hexdigest(),
    )

    with pytest.raises(NoEligibleProviderError):
        service.execute(session=db_session, policy=policy, request=req)

    assert executor.invocation_counts.get("provider-sole", 0) == 0, "Executor MUST NOT be called when circuit OPEN"


def test_concurrent_half_open_probe_stampede_protection() -> None:
    """Verifies that in HALF_OPEN state, only allowed probe count executes and prevents probe stampede."""
    clock = MockClock(100.0)
    cb = ProviderCircuitBreaker(
        min_samples=1,
        failure_threshold=0.5,
        cooldown_seconds=30.0,
        half_open_max_probes=1,
        clock=clock.now,
    )

    prov_failure = FailureClassification(
        error_class=ATTEMPT_ERROR_UNAVAILABLE,
        client_failure=False,
        provider_failure=True,
        retryable=True,
    )
    cb.record_failure("openai", "gpt-4o", prov_failure)
    assert cb.get_state("openai", "gpt-4o") == STATE_OPEN

    # Cooldown expires
    clock.advance(35.0)

    # First worker checks eligibility -> allowed as probe
    assert cb.is_open("openai", "gpt-4o") is False
    assert cb.get_state("openai", "gpt-4o") == STATE_HALF_OPEN

    # Simultaneous concurrent workers check eligibility -> probe limit reached, blocked!
    assert cb.is_open("openai", "gpt-4o") is True
    assert cb.is_open("openai", "gpt-4o") is True

    # Probe finishes with success -> CLOSED
    cb.record_success("openai", "gpt-4o")
    assert cb.get_state("openai", "gpt-4o") == STATE_CLOSED
    assert cb.is_open("openai", "gpt-4o") is False
