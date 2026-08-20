"""Unit tests for Sprint F11.1 Provider Execution Boundary Abstractions."""

import hashlib
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from karsasec.ai.execution import (
    DummyAttemptExecutor,
    ProviderExecutionRequest,
    ProviderExecutionResponse,
    ProviderExecutionService,
)
from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.provider import ProviderDescriptor
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.router import ProviderRouter
from karsasec.ai.routing_policy import RoutingPolicy
from karsasec.persistence.models import AIBudgetModel, Base


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
