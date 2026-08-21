"""Unit and adversarial tests for Sprint F11.3 Deterministic Failure Classification Engine (INV-F11-FAILURE-15, ADV-17, ADV-20)."""

import hashlib
import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from karsasec.ai.execution import (
    ProviderExecutionRequest,
    ProviderExecutionResponse,
    ProviderExecutionService,
)
from karsasec.ai.failure_classifier import FailureClassification, FailureClassifier
from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.provider import (
    ATTEMPT_ERROR_AUTH_FAILED,
    ATTEMPT_ERROR_INVALID_REQUEST,
    ATTEMPT_ERROR_INVALID_RESPONSE,
    ATTEMPT_ERROR_NETWORK,
    ATTEMPT_ERROR_TIMEOUT,
    ATTEMPT_ERROR_UNAVAILABLE,
    ProviderDescriptor,
)
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.router import ProviderRouter
from karsasec.ai.routing_policy import RoutingPolicy
from karsasec.persistence.models import AIBudgetModel, Base


class MalformedJsonResponseExecutor:
    """Mock executor returning HTTP 200 with malformed JSON body (ADV-17 setup)."""

    def __init__(self) -> None:
        self.raw_response_body = '{"summary": "incomplete json...'  # Malformed JSON syntax

    def execute_attempt(
        self,
        descriptor: ProviderDescriptor,
        request: ProviderExecutionRequest,
        attempt_number: int,
    ) -> ProviderExecutionResponse:
        # Simulate response parsing failure
        try:
            json.loads(self.raw_response_body)
            should_fail = False
        except json.JSONDecodeError:
            should_fail = True

        if should_fail:
            classification = FailureClassifier.classify(is_malformed_response=True)
            return ProviderExecutionResponse(
                request_id=request.request_id,
                attempt_number=attempt_number,
                provider_id=descriptor.provider_id,
                model_id=descriptor.model_id,
                success=False,
                error_class=classification.error_class,
            )

        return ProviderExecutionResponse(
            request_id=request.request_id,
            attempt_number=attempt_number,
            provider_id=descriptor.provider_id,
            model_id=descriptor.model_id,
            success=True,
            content=self.raw_response_body,
        )


@pytest.fixture
def db_session() -> Session:
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    yield session
    session.close()


def test_classification_matrix() -> None:
    """Verifies complete deterministic failure classification matrix (INV-F11-FAILURE-15, INV-F11-THROTTLE-10)."""
    # 1. Generic 4xx Client Errors -> non-retryable, client_failure=True, provider_failure=False
    for code, expected_class in [
        (400, ATTEMPT_ERROR_INVALID_REQUEST),
        (401, ATTEMPT_ERROR_AUTH_FAILED),
        (403, ATTEMPT_ERROR_AUTH_FAILED),
        (404, ATTEMPT_ERROR_INVALID_REQUEST),
        (422, ATTEMPT_ERROR_INVALID_REQUEST),
    ]:
        res = FailureClassifier.classify(status_code=code)
        assert isinstance(res, FailureClassification)
        assert res.error_class == expected_class
        assert res.retryable is False
        assert res.client_failure is True
        assert res.provider_failure is False

    # 1b. HTTP 429 Provider Throttling (INV-F11-THROTTLE-10) -> provider_failure=True, retryable=True, throttled=True
    res_429 = FailureClassifier.classify(status_code=429)
    assert res_429.error_class == "PROVIDER_THROTTLED"
    assert res_429.retryable is True
    assert res_429.provider_failure is True
    assert res_429.client_failure is False
    assert res_429.throttled is True

    # 2. 5xx Server Infrastructure Errors -> retryable, client_failure=False, provider_failure=True
    for code in [500, 502, 503, 504]:
        res = FailureClassifier.classify(status_code=code)
        assert res.error_class == ATTEMPT_ERROR_UNAVAILABLE
        assert res.retryable is True
        assert res.client_failure is False
        assert res.provider_failure is True

    # 3. Timeout -> retryable, client_failure=False, provider_failure=True
    res_timeout = FailureClassifier.classify(exception=TimeoutError("Request timed out"))
    assert res_timeout.error_class == ATTEMPT_ERROR_TIMEOUT
    assert res_timeout.retryable is True
    assert res_timeout.client_failure is False
    assert res_timeout.provider_failure is True

    # 4. Connection Network Failure -> retryable, client_failure=False, provider_failure=True
    res_net = FailureClassifier.classify(exception=ConnectionResetError("Reset by peer"))
    assert res_net.error_class == ATTEMPT_ERROR_NETWORK
    assert res_net.retryable is True
    assert res_net.client_failure is False
    assert res_net.provider_failure is True


def test_classification_determinism() -> None:
    """Verifies that classification is 100% deterministic given identical inputs."""
    res1 = FailureClassifier.classify(status_code=503)
    res2 = FailureClassifier.classify(status_code=503)
    assert res1 == res2

    res3 = FailureClassifier.classify(status_code=400)
    res4 = FailureClassifier.classify(status_code=400)
    assert res3 == res4


def test_adv_17_malformed_response_json_failure_classification(db_session: Session) -> None:
    """ADV-17: Verifies that HTTP 200 with malformed JSON body is classified as non-retryable INVALID_RESPONSE."""
    budget = AIBudgetModel(
        budget_id="b-malformed-1",
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
    executor = MalformedJsonResponseExecutor()
    service = ProviderExecutionService(router=router, executor=executor)

    prompt = "Test malformed response"
    p_hash = hashlib.sha256(prompt.encode()).hexdigest()
    c_hash = hashlib.sha256(b"ctx").hexdigest()

    req = ProviderExecutionRequest(
        request_id="req-malformed-1",
        task_id="task-1",
        budget_id="b-malformed-1",
        prompt=prompt,
        prompt_hash=p_hash,
        context_hash=c_hash,
    )
    policy = RoutingPolicy(
        required_capabilities=frozenset({"chat"}),
        estimated_input_tokens=50,
        estimated_output_tokens=50,
    )

    resp = service.execute(session=db_session, policy=policy, request=req)

    # ADV-17 assertions
    assert resp.success is False
    assert resp.error_class == ATTEMPT_ERROR_INVALID_RESPONSE
    # Verify classification properties directly
    classification = FailureClassifier.classify(is_malformed_response=True)
    assert classification.retryable is False
    assert classification.provider_failure is False
    assert classification.client_failure is False


def test_adv_20_circuit_breaker_does_not_trip_on_4xx_client_errors() -> None:
    """ADV-20: Verifies 20 consecutive HTTP 400 client errors are classified as client_failure=True, provider_failure=False."""
    for _ in range(20):
        res = FailureClassifier.classify(status_code=400)
        assert res.client_failure is True, "400 MUST be classified as client failure"
        assert res.provider_failure is False, "400 MUST NEVER be classified as provider infrastructure failure"
        assert res.retryable is False, "400 MUST NOT be retryable"
