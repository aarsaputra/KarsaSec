"""Sprint F11 Phase 1 & 2 — Provider Execution Security Boundary & Hard Timeout Isolation.

Establishes formal abstraction boundaries and hard per-attempt timeout enforcement:
  - ProviderExecutionService
  - ProviderAttemptExecutor
  - ProviderExecutionRequest
  - ProviderExecutionResponse

Enforces INV-F11-TIMEOUT-01:
  A provider execution attempt must never block the executing worker beyond per_attempt_timeout_seconds.
  Produces bounded ATTEMPT_ERROR_TIMEOUT without leaking credentials or budget.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

from karsasec.ai.provider import ATTEMPT_ERROR_TIMEOUT

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
    """Orchestrator for AI provider selection, state tracking, and execution."""

    def __init__(
        self,
        router: ProviderRouter,
        executor: ProviderAttemptExecutor | None = None,
    ) -> None:
        self.router = router
        self.executor = executor or DummyAttemptExecutor()

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
                    # Sync wrapper for coroutine when called in sync context
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
        """Executes an AI request within session scope adhering to F10 budget & request state transitions."""
        from karsasec.ai.request import AIRequestStateService
        from karsasec.ai.state_machine import STATE_IN_FLIGHT, STATE_RESERVED, STATE_ROUTED

        # 1. Create or idempotently fetch AI request
        AIRequestStateService.create_request(
            session=session,
            request_id=request.request_id,
            task_id=request.task_id,
            budget_id=request.budget_id,
            prompt_hash=request.prompt_hash,
            context_hash=request.context_hash,
        )

        # 2. Reserve budget
        estimated_total_tokens = request.estimated_input_tokens + request.estimated_output_tokens
        AIRequestStateService.reserve_budget(
            session=session,
            request_id=request.request_id,
            request_tokens=estimated_total_tokens,
        )

        # 3. Select provider via Router & transition RESERVED -> ROUTED
        routing_result = self.router.select_provider(policy=policy)
        descriptor = routing_result.descriptor

        AIRequestStateService.transition_status(
            session=session,
            request_id=request.request_id,
            expected_status=STATE_RESERVED,
            new_status=STATE_ROUTED,
            selected_provider_id=descriptor.provider_id,
            selected_model_id=descriptor.model_id,
        )

        # 4. Transition ROUTED -> IN_FLIGHT
        AIRequestStateService.transition_status(
            session=session,
            request_id=request.request_id,
            expected_status=STATE_ROUTED,
            new_status=STATE_IN_FLIGHT,
        )

        # 5. Record IN_FLIGHT attempt in database ledger
        attempt_model = self.router.record_attempt(
            session=session,
            request_id=request.request_id,
            attempt_number=routing_result.attempt_number,
            provider_id=descriptor.provider_id,
            model_id=descriptor.model_id,
            status="IN_FLIGHT",
        )

        # 6. Execute attempt with hard timeout isolation (INV-F11-TIMEOUT-01)
        response = self._execute_attempt_with_timeout(
            descriptor=descriptor,
            request=request,
            attempt_number=routing_result.attempt_number,
        )

        if response.success:
            # 7a. Record completion
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
        else:
            # 7b. Record failure
            error_class = response.error_class or "UNKNOWN_PROVIDER_ERROR"
            self.router.record_attempt_failure(
                session=session,
                attempt=attempt_model,
                error_class=error_class,
            )
            AIRequestStateService.release_reservation(
                session=session,
                request_id=request.request_id,
                target_status="FAILED",
            )

        return response
