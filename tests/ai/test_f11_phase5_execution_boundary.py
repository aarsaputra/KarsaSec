"""Unit and adversarial tests for Sprint F11.1 Provider Execution Boundary and F11.2 Hard Timeout Isolation (INV-F11-TIMEOUT-01, ADV-01)."""

import asyncio
import hashlib
import time

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from karsasec.ai.execution import (
    DummyAttemptExecutor,
    ProviderExecutionRequest,
    ProviderExecutionResponse,
    ProviderExecutionService,
)
from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.provider import ATTEMPT_ERROR_TIMEOUT, ProviderDescriptor
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.router import ProviderRouter
from karsasec.ai.routing_policy import RoutingPolicy
from karsasec.persistence.models import AIBudgetModel, AIRequestModel, Base


class HangingAttemptExecutor:
    """Mock executor that hangs indefinitely until cancelled (ADV-01 setup)."""

    def __init__(self) -> None:
        self.cancelled = False

    async def execute_attempt(
        self,
        descriptor: ProviderDescriptor,
        request: ProviderExecutionRequest,
        attempt_number: int,
    ) -> ProviderExecutionResponse:
        try:
            # Hang for 10 seconds (well beyond per_attempt_timeout_seconds)
            await asyncio.sleep(10.0)
            return ProviderExecutionResponse(
                request_id=request.request_id,
                attempt_number=attempt_number,
                provider_id=descriptor.provider_id,
                model_id=descriptor.model_id,
                success=True,
                content="Late completion should never happen",
            )
        except asyncio.CancelledError:
            self.cancelled = True
            raise


@pytest.fixture
def db_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


def test_provider_execution_request_validation() -> None:
    prompt = "Analyze finding KS-PHP-0002"
    prompt_hash = hashlib.sha256(prompt.encode()).hexdigest()
    context_hash = hashlib.sha256(b"context").hexdigest()

    req = ProviderExecutionRequest(
        request_id="req-101",
        task_id="task-101",
        budget_id="budget-101",
        prompt=prompt,
        prompt_hash=prompt_hash,
        context_hash=context_hash,
    )
    assert req.request_id == "req-101"
    assert req.per_attempt_timeout_seconds == 30.0

    with pytest.raises(ValueError, match="request_id must be a non-empty string"):
        ProviderExecutionRequest(
            request_id="",
            task_id="task-101",
            budget_id="budget-101",
            prompt=prompt,
            prompt_hash=prompt_hash,
            context_hash=context_hash,
        )


def test_provider_execution_service_successful_flow(db_session: Session) -> None:
    # 1. Setup budget
    budget = AIBudgetModel(
        budget_id="b-100",
        tenant_id="tenant-1",
        token_limit=1000,
        cost_limit_micro_units=5000,
    )
    db_session.add(budget)
    db_session.flush()

    # 2. Setup provider & router
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
    service = ProviderExecutionService(router=router, executor=DummyAttemptExecutor())

    prompt = "Hello"
    p_hash = hashlib.sha256(prompt.encode()).hexdigest()
    c_hash = hashlib.sha256(b"ctx").hexdigest()

    req = ProviderExecutionRequest(
        request_id="req-success-1",
        task_id="task-1",
        budget_id="b-100",
        prompt=prompt,
        prompt_hash=p_hash,
        context_hash=c_hash,
        estimated_input_tokens=50,
        estimated_output_tokens=50,
    )

    policy = RoutingPolicy(
        required_capabilities=frozenset({"chat"}),
        estimated_input_tokens=50,
        estimated_output_tokens=50,
    )
    resp = service.execute(session=db_session, policy=policy, request=req)

    assert isinstance(resp, ProviderExecutionResponse)
    assert resp.success is True
    assert resp.provider_id == "openai"
    assert resp.content == "Mock AI response content"


def test_hard_timeout_aborts_hanging_worker(db_session: Session) -> None:
    """ADV-01: Verifies that a hanging provider is aborted at the per_attempt_timeout boundary (INV-F11-TIMEOUT-01)."""
    # 1. Setup budget
    budget = AIBudgetModel(
        budget_id="b-timeout-1",
        tenant_id="tenant-1",
        token_limit=1000,
        cost_limit_micro_units=5000,
    )
    db_session.add(budget)
    db_session.flush()

    # 2. Setup provider & router
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
    hanging_executor = HangingAttemptExecutor()
    service = ProviderExecutionService(router=router, executor=hanging_executor)

    prompt = "Hanging request test"
    p_hash = hashlib.sha256(prompt.encode()).hexdigest()
    c_hash = hashlib.sha256(b"ctx").hexdigest()

    req = ProviderExecutionRequest(
        request_id="req-timeout-1",
        task_id="task-1",
        budget_id="b-timeout-1",
        prompt=prompt,
        prompt_hash=p_hash,
        context_hash=c_hash,
        estimated_input_tokens=50,
        estimated_output_tokens=50,
        per_attempt_timeout_seconds=0.05,  # Deterministic 50ms hard timeout
    )

    policy = RoutingPolicy(
        required_capabilities=frozenset({"chat"}),
        estimated_input_tokens=50,
        estimated_output_tokens=50,
    )

    start_time = time.monotonic()
    resp = service.execute(session=db_session, policy=policy, request=req)
    elapsed = time.monotonic() - start_time

    # Assertions for ADV-01
    assert elapsed < 1.0, f"Execution took too long: {elapsed:.2f}s (should be ~0.05s)"
    assert resp.success is False
    assert resp.error_class == ATTEMPT_ERROR_TIMEOUT
    assert hanging_executor.cancelled is True, "Provider execution task was not cancelled"

    # Budget reservation safety assertion
    updated_budget = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-timeout-1"))
    assert updated_budget is not None
    assert updated_budget.reserved_tokens == 0, "Reserved tokens must be released on timeout"
    assert updated_budget.used_tokens == 0, "No tokens should be charged on timeout"

    # State machine status assertion
    ai_request = db_session.scalar(select(AIRequestModel).where(AIRequestModel.request_id == "req-timeout-1"))
    assert ai_request is not None
    assert ai_request.status == "FAILED"
