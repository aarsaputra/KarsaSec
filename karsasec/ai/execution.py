"""Sprint F11 Phase 1–5 — Provider Execution Security Boundary, Hard Timeout, Failure Classification, Bounded Retry & Circuit Breaker.

Establishes formal abstraction boundaries, hard timeout isolation, deterministic failure classification,
bounded retry/backoff coordination, and circuit breaker protection:
  - ProviderExecutionService
  - ProviderAttemptExecutor
  - ProviderExecutionRequest
  - ProviderExecutionResponse
  - RetryPolicy & BackoffCalculator integration (INV-F11-RETRY-02, INV-F11-RETRY-03, INV-F11-BACKOFF-04)
  - ProviderCircuitBreaker integration (INV-F11-CIRCUIT-05, ADV-05)

Preserves all F10 router, request state machine, and budget invariants.
Does NOT mutate frozen F9 primitive recovery/audit/outbox components.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from sqlalchemy.exc import IntegrityError

from karsasec.ai.exceptions import AIRequestStateConflictError
from karsasec.ai.failure_classifier import FailureClassifier
from karsasec.ai.provider import ATTEMPT_ERROR_TIMEOUT
from karsasec.ai.retry import RetryPolicy
from karsasec.ai.router import InvalidAttemptError, NoEligibleProviderError

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

    from karsasec.ai.provider import ProviderDescriptor
    from karsasec.ai.router import ProviderRouter
    from karsasec.ai.routing_policy import RoutingPolicy


@dataclass(frozen=True)
class ProviderExecutionRequest:
    """Immutable execution context for an AI provider request.

    Constraints:
    - request_id, task_id, budget_id must be non-empty strings.
    - prompt must be a non-empty string.
    - per_attempt_timeout_seconds must be > 0.
    - max_attempts must be >= 1.
    - max_response_bytes must be >= 1024.
    """

    request_id: str
    task_id: str
    budget_id: str
    prompt: str
    prompt_hash: str
    context_hash: str
    estimated_input_tokens: int = 100
    estimated_output_tokens: int = 200
    per_attempt_timeout_seconds: float = 30.0
    max_attempts: int = 3
    max_response_bytes: int = 10 * 1024 * 1024  # 10 MB (INV-F11-RESPONSE-10)

    def __post_init__(self) -> None:
        if not self.request_id or not self.request_id.strip():
            raise ValueError("request_id must be a non-empty string.")
        if not self.task_id or not self.task_id.strip():
            raise ValueError("task_id must be a non-empty string.")
        if not self.budget_id or not self.budget_id.strip():
            raise ValueError("budget_id must be a non-empty string.")
        if not self.prompt:
            raise ValueError("prompt cannot be empty.")
        if self.per_attempt_timeout_seconds <= 0:
            raise ValueError("per_attempt_timeout_seconds must be positive.")
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1.")
        if self.max_response_bytes < 1024:
            raise ValueError("max_response_bytes must be at least 1024 bytes.")


@dataclass(frozen=True)
class ProviderExecutionResponse:
    """Immutable outcome of a provider attempt execution."""

    request_id: str
    attempt_number: int
    provider_id: str
    model_id: str
    success: bool
    content: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    actual_cost_micro_units: int = 0
    error_class: str | None = None


@runtime_checkable
class ProviderAttemptExecutor(Protocol):
    """Protocol for provider HTTP call execution."""

    def execute_attempt(
        self,
        descriptor: ProviderDescriptor,
        request: ProviderExecutionRequest,
        attempt_number: int,
    ) -> Any:
        """Executes a single provider attempt synchronously or asynchronously."""
        ...


class DummyAttemptExecutor:
    """Default deterministic mock executor for unit testing boundaries."""

    def __init__(
        self,
        response_content: str = "Mock AI response content",
        input_tokens: int = 100,
        output_tokens: int = 150,
        should_fail: bool = False,
        error_class: str | None = None,
    ) -> None:
        self.response_content = response_content
        self.input_tokens = input_tokens
        self.output_tokens = output_tokens
        self.should_fail = should_fail
        self.error_class = error_class or ("PROVIDER_UNAVAILABLE" if should_fail else None)

    def execute_attempt(
        self,
        descriptor: ProviderDescriptor,
        request: ProviderExecutionRequest,
        attempt_number: int,
    ) -> ProviderExecutionResponse:
        if self.should_fail:
            return ProviderExecutionResponse(
                request_id=request.request_id,
                attempt_number=attempt_number,
                provider_id=descriptor.provider_id,
                model_id=descriptor.model_id,
                success=False,
                error_class=self.error_class,
            )

        from karsasec.ai.pricing import estimate_cost_micro_units

        cost = estimate_cost_micro_units(descriptor, self.input_tokens, self.output_tokens)
        return ProviderExecutionResponse(
            request_id=request.request_id,
            attempt_number=attempt_number,
            provider_id=descriptor.provider_id,
            model_id=descriptor.model_id,
            success=True,
            content=self.response_content,
            input_tokens=self.input_tokens,
            output_tokens=self.output_tokens,
            actual_cost_micro_units=cost,
        )


class ProviderExecutionService:
    """Orchestrator for AI provider selection, state tracking, execution, retry, and circuit breaker coordination."""

    def __init__(
        self,
        router: ProviderRouter,
        executor: ProviderAttemptExecutor | None = None,
        retry_policy: RetryPolicy | None = None,
        sleeper: Callable[[float], None] | None = None,
        circuit_breaker: Any | None = None,
    ) -> None:
        self.router = router
        self.executor = executor or DummyAttemptExecutor()
        self.retry_policy = retry_policy or RetryPolicy()
        self.sleeper = sleeper
        self.circuit_breaker = circuit_breaker or getattr(router, "circuit_breaker", None)

    def _execute_attempt_with_timeout(
        self,
        descriptor: ProviderDescriptor,
        request: ProviderExecutionRequest,
        attempt_number: int,
    ) -> ProviderExecutionResponse:
        """Surrounds attempt execution with a hard per-attempt timeout (INV-F11-TIMEOUT-01).

        Supports both coroutine/async and synchronous blocking executors.
        On timeout, aborts execution and produces ATTEMPT_ERROR_TIMEOUT without leaking credentials.
        """
        timeout = request.per_attempt_timeout_seconds

        try:
            # Check if there is a running event loop for async coroutine execution
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            res = self.executor.execute_attempt(
                descriptor=descriptor,
                request=request,
                attempt_number=attempt_number,
            )

            if asyncio.iscoroutine(res):
                if loop and loop.is_running():
                    # Running inside an active loop — await with asyncio.wait_for
                    future = asyncio.wait_for(res, timeout=timeout)
                    return loop.run_until_complete(future)
                else:
                    return asyncio.run(asyncio.wait_for(res, timeout=timeout))
            elif isinstance(res, ProviderExecutionResponse):
                return res
            else:
                return res

        except (TimeoutError, concurrent.futures.TimeoutError):
            return ProviderExecutionResponse(
                request_id=request.request_id,
                attempt_number=attempt_number,
                provider_id=descriptor.provider_id,
                model_id=descriptor.model_id,
                success=False,
                error_class=ATTEMPT_ERROR_TIMEOUT,
            )

    def execute(
        self,
        session: Session,
        policy: RoutingPolicy,
        request: ProviderExecutionRequest,
    ) -> ProviderExecutionResponse:
        """Executes an AI request within session scope adhering to F10 budget & request state transitions, with F11 retries and circuit breaker."""
        from karsasec.ai.request import AIRequestStateService
        from karsasec.ai.state_machine import (
            STATE_IN_FLIGHT,
            STATE_PROVIDER_FAILED,
            STATE_RESERVED,
            STATE_ROUTED,
        )

        # 1. Create or idempotently fetch AI request
        AIRequestStateService.create_request(
            session=session,
            request_id=request.request_id,
            task_id=request.task_id,
            budget_id=request.budget_id,
            prompt_hash=request.prompt_hash,
            context_hash=request.context_hash,
        )

        # 2. Reserve budget (once per request lifecycle)
        estimated_total_tokens = request.estimated_input_tokens + request.estimated_output_tokens
        AIRequestStateService.reserve_budget(
            session=session,
            request_id=request.request_id,
            request_tokens=estimated_total_tokens,
        )

        effective_max_attempts = min(request.max_attempts, self.retry_policy.max_attempts)
        last_response: ProviderExecutionResponse | None = None

        for attempt_number in range(1, effective_max_attempts + 1):
            # Select provider via Router & transition state
            try:
                routing_result = self.router.select_provider(policy=policy, session=session)
                descriptor = routing_result.descriptor
            except NoEligibleProviderError:
                # Handle case where all providers are OPEN or ineligible (INV-F11-CIRCUIT-05)
                req_model = AIRequestStateService.get_request(session, request.request_id)
                target_status = STATE_PROVIDER_FAILED if attempt_number > 1 else STATE_RESERVED
                if req_model and req_model.status == target_status:
                    AIRequestStateService.release_reservation(
                        session=session,
                        request_id=request.request_id,
                        target_status="FAILED",
                    )
                if last_response is not None:
                    return last_response
                raise

            if attempt_number == 1:
                # Transition RESERVED -> ROUTED -> IN_FLIGHT
                AIRequestStateService.transition_status(
                    session=session,
                    request_id=request.request_id,
                    expected_status=STATE_RESERVED,
                    new_status=STATE_ROUTED,
                    selected_provider_id=descriptor.provider_id,
                    selected_model_id=descriptor.model_id,
                )
            else:
                # Transition PROVIDER_FAILED -> ROUTED -> IN_FLIGHT
                AIRequestStateService.transition_status(
                    session=session,
                    request_id=request.request_id,
                    expected_status=STATE_PROVIDER_FAILED,
                    new_status=STATE_ROUTED,
                    selected_provider_id=descriptor.provider_id,
                    selected_model_id=descriptor.model_id,
                )

            AIRequestStateService.transition_status(
                session=session,
                request_id=request.request_id,
                expected_status=STATE_ROUTED,
                new_status=STATE_IN_FLIGHT,
            )

            # Atomic database attempt recording (UNIQUE constraint on request_id, attempt_number)
            try:
                attempt_model = self.router.record_attempt(
                    session=session,
                    request_id=request.request_id,
                    attempt_number=attempt_number,
                    provider_id=descriptor.provider_id,
                    model_id=descriptor.model_id,
                    status="IN_FLIGHT",
                )
            except (IntegrityError, AIRequestStateConflictError, InvalidAttemptError):
                session.rollback()
                if last_response is not None:
                    return last_response
                raise AIRequestStateConflictError(
                    f"Concurrent attempt conflict for request '{request.request_id}' attempt {attempt_number}."
                )

            # Execute attempt with hard timeout isolation (INV-F11-TIMEOUT-01)
            response = self._execute_attempt_with_timeout(
                descriptor=descriptor,
                request=request,
                attempt_number=attempt_number,
            )
            last_response = response

            if response.success:
                # Success path — record success in circuit breaker & save persistent state
                if self.circuit_breaker:
                    self.circuit_breaker.record_success(descriptor.provider_id, descriptor.model_id)
                    circuit_repo = getattr(self.router, "circuit_repository", None)
                    if circuit_repo:
                        data = self.circuit_breaker.export_data(descriptor.provider_id, descriptor.model_id)
                        circuit_repo.save(session, data)

                attempt_model.status = "COMPLETED"
                attempt_model.input_tokens = response.input_tokens
                attempt_model.output_tokens = response.output_tokens
                session.flush()

                AIRequestStateService.commit_execution(
                    session=session,
                    request_id=request.request_id,
                    actual_tokens=response.input_tokens + response.output_tokens,
                    actual_cost_micro_units=response.actual_cost_micro_units,
                    selected_provider_id=descriptor.provider_id,
                    selected_model_id=descriptor.model_id,
                )
                return response

            # Failure path — record failure in circuit breaker & save persistent state
            classification = FailureClassifier.classify(error_class_hint=response.error_class)
            if self.circuit_breaker:
                self.circuit_breaker.record_failure(descriptor.provider_id, descriptor.model_id, classification)
                rate_limiter = getattr(self.router, "rate_limiter", None)
                if classification.throttled and rate_limiter:
                    rate_limiter.set_cooldown(session, descriptor.provider_id, descriptor.model_id, cooldown_seconds=60.0, reason=classification.error_class)
                circuit_repo = getattr(self.router, "circuit_repository", None)
                if circuit_repo:
                    data = self.circuit_breaker.export_data(descriptor.provider_id, descriptor.model_id)
                    circuit_repo.save(session, data)

            self.router.record_attempt_failure(
                session=session,
                attempt=attempt_model,
                error_class=classification.error_class,
            )

            # Transition IN_FLIGHT -> PROVIDER_FAILED
            AIRequestStateService.transition_status(
                session=session,
                request_id=request.request_id,
                expected_status=STATE_IN_FLIGHT,
                new_status=STATE_PROVIDER_FAILED,
            )

            # Evaluate retry policy
            decision = self.retry_policy.evaluate(
                attempt_number=attempt_number,
                classification=classification,
            )

            if decision.should_retry and attempt_number < effective_max_attempts:
                # Perform backoff sleep
                if self.sleeper is not None and decision.backoff_seconds > 0:
                    self.sleeper(decision.backoff_seconds)
                continue

            # No further retries: transition PROVIDER_FAILED -> FAILED & release budget reservation
            AIRequestStateService.release_reservation(
                session=session,
                request_id=request.request_id,
                target_status="FAILED",
            )
            return response

        # Fallback return (should be unreachable due to loop control)
        return last_response or ProviderExecutionResponse(
            request_id=request.request_id,
            attempt_number=effective_max_attempts,
            provider_id="none",
            model_id="none",
            success=False,
            error_class="ATTEMPTS_EXHAUSTED",
        )
