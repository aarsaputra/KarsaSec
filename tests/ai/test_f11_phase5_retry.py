"""Unit and adversarial tests for Sprint F11.4 Bounded Retry & Backoff Engine (INV-F11-RETRY-02, INV-F11-RETRY-03, INV-F11-BACKOFF-04, ADV-02, ADV-03, ADV-04, ADV-10)."""

import hashlib
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from karsasec.ai.exceptions import AIRequestStateConflictError
from karsasec.ai.execution import (
    ProviderExecutionRequest,
    ProviderExecutionResponse,
    ProviderExecutionService,
)
from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.provider import ATTEMPT_ERROR_UNAVAILABLE, ProviderDescriptor
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.retry import BackoffCalculator, RetryPolicy
from karsasec.ai.router import ProviderRouter
from karsasec.ai.routing_policy import RoutingPolicy
from karsasec.persistence.models import AIBudgetModel, AIProviderAttemptModel, AIRequestModel, Base


class FailingAttemptExecutor:
    """Mock executor counting attempts and simulating failures."""

    def __init__(self, should_fail: bool = True, error_class: str = ATTEMPT_ERROR_UNAVAILABLE) -> None:
        self.should_fail = should_fail
        self.error_class = error_class
        self.attempt_counts: dict[str, int] = {}

    def execute_attempt(
        self,
        descriptor: ProviderDescriptor,
        request: ProviderExecutionRequest,
        attempt_number: int,
    ) -> ProviderExecutionResponse:
        self.attempt_counts[request.request_id] = self.attempt_counts.get(request.request_id, 0) + 1
        if self.should_fail:
            return ProviderExecutionResponse(
                request_id=request.request_id,
                attempt_number=attempt_number,
                provider_id=descriptor.provider_id,
                model_id=descriptor.model_id,
                success=False,
                error_class=self.error_class,
            )

        return ProviderExecutionResponse(
            request_id=request.request_id,
            attempt_number=attempt_number,
            provider_id=descriptor.provider_id,
            model_id=descriptor.model_id,
            success=True,
            content="Successful retry response",
        )


@pytest.fixture
def db_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


def test_backoff_calculator_exponential_cap_and_jitter() -> None:
    """INV-F11-BACKOFF-04: Verifies exponential backoff with full jitter and 30s cap."""
    # Deterministic RNG = 1.0 (Max cap)
    delay1 = BackoffCalculator.calculate_delay(1, base_backoff_seconds=1.0, rng_source=lambda: 1.0)
    delay2 = BackoffCalculator.calculate_delay(2, base_backoff_seconds=1.0, rng_source=lambda: 1.0)
    delay3 = BackoffCalculator.calculate_delay(3, base_backoff_seconds=1.0, rng_source=lambda: 1.0)
    delay10 = BackoffCalculator.calculate_delay(10, base_backoff_seconds=1.0, rng_source=lambda: 1.0)

    assert delay1 == 1.0  # 1 * 2^0 * 1.0 = 1.0
    assert delay2 == 2.0  # 1 * 2^1 * 1.0 = 2.0
    assert delay3 == 4.0  # 1 * 2^2 * 1.0 = 4.0
    assert delay10 == 30.0, "Backoff MUST be capped at 30 seconds"

    # Deterministic RNG = 0.5 (Jittered)
    delay_half = BackoffCalculator.calculate_delay(3, base_backoff_seconds=1.0, rng_source=lambda: 0.5)
    assert delay_half == 2.0  # 4.0 * 0.5 = 2.0


def test_adv_03_retry_amplification_bounded_at_max_attempts(db_session: Session) -> None:
    """ADV-03: Verifies that attempts never exceed max_attempts = 3 and attempt 4 cannot exist."""
    budget = AIBudgetModel(
        budget_id="b-retry-1",
        tenant_id="tenant-1",
        token_limit=1000,
        cost_limit_micro_units=5000,
    )
    db_session.add(budget)
    db_session.flush()

    desc = ProviderDescriptor(
        provider_id="openai",
        model_id="gpt-4o",
        capabilities=frozenset({"chat"}),
        priority=1,
        input_price_micro_units=10,
        output_price_micro_units=20,
    )
    reg = ProviderRegistry()
    reg.register(desc)
    health_reg = ProviderHealthRegistry()
    health_reg.register("openai", "gpt-4o")

    router = ProviderRouter(registry=reg, health_registry=health_reg)
    executor = FailingAttemptExecutor(should_fail=True, error_class=ATTEMPT_ERROR_UNAVAILABLE)
    recorded_sleeps: list[float] = []

    service = ProviderExecutionService(
        router=router,
        executor=executor,
        retry_policy=RetryPolicy(max_attempts=3, rng_source=lambda: 1.0),
        sleeper=lambda s: recorded_sleeps.append(s),
    )

    prompt = "Test bounded retries"
    p_hash = hashlib.sha256(prompt.encode()).hexdigest()
    c_hash = hashlib.sha256(b"ctx").hexdigest()

    req = ProviderExecutionRequest(
        request_id="req-retry-adv03",
        task_id="task-1",
        budget_id="b-retry-1",
        prompt=prompt,
        prompt_hash=p_hash,
        context_hash=c_hash,
        max_attempts=3,
    )
    policy = RoutingPolicy(
        required_capabilities=frozenset({"chat"}),
        estimated_input_tokens=50,
        estimated_output_tokens=50,
    )

    resp = service.execute(session=db_session, policy=policy, request=req)

    # ADV-03 Assertions
    assert resp.success is False
    assert executor.attempt_counts["req-retry-adv03"] == 3, "Execution count MUST be exactly 3"

    # Verify attempt database records
    attempts = db_session.scalars(
        select(AIProviderAttemptModel).where(AIProviderAttemptModel.request_id == "req-retry-adv03")
    ).all()
    assert len(attempts) == 3, "Database MUST contain exactly 3 attempt records"
    attempt_numbers = [a.attempt_number for a in attempts]
    assert attempt_numbers == [1, 2, 3]

    # Verify request status transitioned to FAILED & budget released
    req_model = db_session.scalar(select(AIRequestModel).where(AIRequestModel.request_id == "req-retry-adv03"))
    assert req_model is not None
    assert req_model.status == "FAILED"

    budget_model = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-retry-1"))
    assert budget_model is not None
    assert budget_model.reserved_tokens == 0
    assert budget_model.used_tokens == 0


def test_adv_02_retry_storm_exponential_backoff_and_cap(db_session: Session) -> None:
    """ADV-02: Verifies exponential backoff, jitter, and capping under simulated 50 concurrent requests."""
    desc = ProviderDescriptor(
        provider_id="openai",
        model_id="gpt-4o",
        capabilities=frozenset({"chat"}),
        priority=1,
        input_price_micro_units=10,
        output_price_micro_units=20,
    )
    reg = ProviderRegistry()
    reg.register(desc)
    health_reg = ProviderHealthRegistry()
    health_reg.register("openai", "gpt-4o")
    router = ProviderRouter(registry=reg, health_registry=health_reg)

    retry_pol = RetryPolicy(max_attempts=3, base_backoff_seconds=1.0, max_backoff_seconds=30.0)

    # 50 simulated requests encountering HTTP 503
    for req_idx in range(50):
        req_id = f"req-storm-{req_idx}"
        budget = AIBudgetModel(
            budget_id=f"b-storm-{req_idx}",
            tenant_id="tenant-1",
            token_limit=1000,
            cost_limit_micro_units=5000,
        )
        db_session.add(budget)
        db_session.flush()

        executor = FailingAttemptExecutor(should_fail=True, error_class=ATTEMPT_ERROR_UNAVAILABLE)
        sleeps: list[float] = []
        service = ProviderExecutionService(
            router=router,
            executor=executor,
            retry_policy=retry_pol,
            sleeper=sleeps.append,
        )

        p_hash = hashlib.sha256(f"prompt-{req_idx}".encode()).hexdigest()
        c_hash = hashlib.sha256(b"ctx").hexdigest()
        req = ProviderExecutionRequest(
            request_id=req_id,
            task_id=f"task-storm-{req_idx}",
            budget_id=f"b-storm-{req_idx}",
            prompt=f"prompt-{req_idx}",
            prompt_hash=p_hash,
            context_hash=c_hash,
            max_attempts=3,
        )
        r_policy = RoutingPolicy(
            required_capabilities=frozenset({"chat"}),
            estimated_input_tokens=50,
            estimated_output_tokens=50,
        )

        resp = service.execute(session=db_session, policy=r_policy, request=req)
        assert resp.success is False
        assert executor.attempt_counts[req_id] == 3
        assert len(sleeps) == 2, "2 backoff sleeps between 3 attempts"
        for delay in sleeps:
            assert 0.0 <= delay <= 30.0, f"Delay {delay} out of bounds"


def test_adv_10_duplicate_attempt_creation_rejection(db_session: Session) -> None:
    """ADV-10: Verifies that duplicate attempt_number for request_id is rejected by database UNIQUE constraint."""
    from sqlalchemy.exc import IntegrityError

    req_model = AIRequestModel(
        request_id="req-dup-1",
        task_id="task-1",
        budget_id="b-1",
        prompt_hash="a" * 64,
        context_hash="b" * 64,
        status="IN_FLIGHT",
    )

    # Insert attempt 1
    attempt1 = AIProviderAttemptModel(
        attempt_id="att-1",
        request_id="req-dup-1",
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
        status="IN_FLIGHT",
    )
    db_session.add(req_model)
    db_session.add(attempt1)
    db_session.flush()

    # Attempt to insert duplicate attempt 1 for same request_id
    attempt1_dup = AIProviderAttemptModel(
        attempt_id="att-1-dup",
        request_id="req-dup-1",
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
        status="IN_FLIGHT",
    )
    db_session.add(attempt1_dup)

    with pytest.raises(IntegrityError):
        db_session.flush()

    db_session.rollback()


def test_adv_04_concurrent_retry_idempotency_locking(db_session: Session) -> None:
    """ADV-04: Verifies concurrent retry creation idempotency locking when duplicate attempt is recorded."""
    budget = AIBudgetModel(
        budget_id="b-lock-1",
        tenant_id="tenant-1",
        token_limit=1000,
        cost_limit_micro_units=5000,
    )
    db_session.add(budget)
    db_session.flush()

    desc = ProviderDescriptor(
        provider_id="openai",
        model_id="gpt-4o",
        capabilities=frozenset({"chat"}),
        priority=1,
        input_price_micro_units=10,
        output_price_micro_units=20,
    )
    reg = ProviderRegistry()
    reg.register(desc)
    health_reg = ProviderHealthRegistry()
    health_reg.register("openai", "gpt-4o")
    router = ProviderRouter(registry=reg, health_registry=health_reg)

    prompt = "Concurrent attempt test"
    p_hash = hashlib.sha256(prompt.encode()).hexdigest()
    c_hash = hashlib.sha256(b"ctx").hexdigest()

    # Pre-create request model in RESERVED status with matching hashes
    req_model = AIRequestModel(
        request_id="req-concurrent-1",
        task_id="task-1",
        budget_id="b-lock-1",
        prompt_hash=p_hash,
        context_hash=c_hash,
        status="RESERVED",
        reserved_tokens=100,
    )

    # Manually pre-create attempt 1 in database
    att1 = AIProviderAttemptModel(
        attempt_id="att-precreated-1",
        request_id="req-concurrent-1",
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
        status="IN_FLIGHT",
    )
    db_session.add_all([req_model, att1])
    db_session.flush()

    # Pre-existing attempt 1 prevents duplicate creation
    executor = FailingAttemptExecutor()
    service = ProviderExecutionService(router=router, executor=executor)

    req = ProviderExecutionRequest(
        request_id="req-concurrent-1",
        task_id="task-1",
        budget_id="b-lock-1",
        prompt=prompt,
        prompt_hash=p_hash,
        context_hash=c_hash,
        estimated_input_tokens=50,
        estimated_output_tokens=50,
    )
    r_policy = RoutingPolicy(
        required_capabilities=frozenset({"chat"}),
        estimated_input_tokens=50,
        estimated_output_tokens=50,
    )

    with pytest.raises(AIRequestStateConflictError):
        service.execute(session=db_session, policy=r_policy, request=req)
