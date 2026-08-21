"""Sprint F10 & F11 — Deterministic Multi-Provider Router, Circuit Breaker & Rate Limiter Integration.

Executes deterministic multi-stage provider selection with zero wall-clock or random jitter dependence:
  - Priority-based deterministic ordering
  - Financial budget cost ceilings
  - Fail-closed eligibility validation
  - Process-local & persistent Circuit Breaker checks (INV-F11-CIRCUIT-05, INV-F11-CIRCUIT-06)
  - Hardening 8 Filter Ordering: Health -> Circuit -> Cooldown -> Rate Limit -> Capability -> Cost
  - Hardening 7 (INV-F11-CIRCUIT-14): Non-mutating startup recovery

Preserves all budget fencing & PostgreSQL authority invariants.
Does NOT mutate frozen F9 primitive recovery/audit/outbox components.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.pricing import PricingError, is_within_cost_ceiling
from karsasec.ai.provider import (
    ELIGIBLE_HEALTH_STATES,
    HEALTH_DEGRADED,
    HEALTH_UNKNOWN,
    ProviderDescriptor,
)
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.routing_policy import RoutingPolicy
from karsasec.persistence.models import AIProviderAttemptModel

if TYPE_CHECKING:
    from karsasec.ai.circuit_repository import CircuitStateRepository
    from karsasec.ai.provider_rate_limiter import DistributedTokenBucket, ProviderRateLimitPolicy


class RouterError(Exception):
    """Base exception for router failures."""

    pass


class NoEligibleProviderError(RouterError):
    """Raised when no provider satisfies all policy constraints and health criteria."""

    pass


class InvalidAttemptError(RouterError):
    """Raised when attempt recording violates idempotency or ordering constraints."""

    pass


@dataclass(frozen=True)
class RoutingResult:
    """Immutable outcome of a provider routing selection."""

    descriptor: ProviderDescriptor
    estimated_cost_micro_units: int
    attempt_number: int = 1


class ProviderRouter:
    """Deterministic Provider Selection & Rate Limiter Router (INV-F10-ROUTER-01..09, INV-F11-CIRCUIT-05, INV-F11-RATELIMIT-08)."""

    def __init__(
        self,
        registry: ProviderRegistry,
        health_registry: ProviderHealthRegistry | None = None,
        circuit_breaker: Any | None = None,
        circuit_repository: CircuitStateRepository | None = None,
        rate_limiter: DistributedTokenBucket | None = None,
        rate_limit_policy: ProviderRateLimitPolicy | None = None,
    ) -> None:
        self.registry = registry
        self.health_registry = health_registry or ProviderHealthRegistry()
        self.circuit_breaker = circuit_breaker
        self.circuit_repository = circuit_repository
        self.rate_limiter = rate_limiter
        self.rate_limit_policy = rate_limit_policy

    def restore_circuit_states(self, session: Session) -> None:
        """Restores circuit states from repository on service startup without mutating state (INV-F11-CIRCUIT-14)."""
        if self.circuit_repository and self.circuit_breaker:
            persisted_states = self.circuit_repository.list_all(session)
            for state_data in persisted_states:
                self.circuit_breaker.restore_from_data(state_data)

    def _filter_eligible(
        self,
        policy: RoutingPolicy,
        excluded: frozenset[tuple[str, str]],
        session: Session | None = None,
    ) -> list[tuple[ProviderDescriptor, int]]:
        """Runs the deterministic multi-stage eligibility filter adhering to Hardening 8 Filter Ordering:

        Stages applied:
        [1] Exclusion list (prior failed attempts)
        [2] Health eligibility (INV-F10-ROUTER-05)
        [3] Circuit breaker state check (INV-F11-CIRCUIT-05)
        [4] Cooldown check (INV-F11-THROTTLE-11)
        [5] Rate Limit / Token Bucket check (INV-F11-RATELIMIT-08/13)
        [6] Capability compatibility check (INV-F10-ROUTER-06)
        [7] Cost ceiling check (INV-F10-ROUTER-03/04)

        Providers that fail any stage are silently excluded from the candidate set.
        """
        candidates: list[tuple[ProviderDescriptor, int]] = []
        all_providers = self.registry.list_all()

        for descriptor in all_providers:
            key = (descriptor.provider_id, descriptor.model_id)

            # Stage 1 — Exclusion list
            if key in excluded:
                continue

            # Stage 2 — Health eligibility (INV-F10-ROUTER-05)
            active_health = self.health_registry.get_health(descriptor.provider_id, descriptor.model_id)
            if active_health == HEALTH_UNKNOWN:
                continue
            if active_health not in ELIGIBLE_HEALTH_STATES:
                continue
            if active_health == HEALTH_DEGRADED and not policy.allow_degraded:
                continue

            # Stage 3 — Circuit breaker state check (INV-F11-CIRCUIT-05)
            if self.circuit_breaker and self.circuit_breaker.is_open(descriptor.provider_id, descriptor.model_id):
                continue

            # Stage 4 — Cooldown check (INV-F11-THROTTLE-11)
            if session is not None and self.rate_limiter is not None:
                in_cooldown, _, _ = self.rate_limiter.is_in_cooldown(
                    session, descriptor.provider_id, descriptor.model_id
                )
                if in_cooldown:
                    continue

            # Stage 5 — Distributed Rate Limiter / Token Bucket check (INV-F11-RATELIMIT-08/13)
            if session is not None and self.rate_limiter is not None and self.rate_limit_policy is not None:
                requested_tokens = policy.estimated_input_tokens + policy.estimated_output_tokens
                rl_res = self.rate_limiter.check_and_consume(
                    session=session,
                    provider_id=descriptor.provider_id,
                    model_id=descriptor.model_id,
                    policy=self.rate_limit_policy,
                    requested_tokens=requested_tokens,
                )
                if not rl_res.allowed:
                    continue

            # Stage 6 — Capability compatibility (INV-F10-ROUTER-06)
            if not policy.required_capabilities.issubset(descriptor.capabilities):
                continue

            # Stage 7 — Cost ceiling (INV-F10-ROUTER-03/04)
            try:
                if policy.max_request_cost_micro_units is not None:
                    within, estimated = is_within_cost_ceiling(
                        descriptor,
                        policy.estimated_input_tokens,
                        policy.estimated_output_tokens,
                        policy.max_request_cost_micro_units,
                    )
                    if not within:
                        continue
                else:
                    from karsasec.ai.pricing import estimate_cost_micro_units

                    estimated = estimate_cost_micro_units(
                        descriptor, policy.estimated_input_tokens, policy.estimated_output_tokens
                    )
            except PricingError:
                continue

            candidates.append((descriptor, estimated))

        # Priority sort + stable lexical tie-break (INV-F10-ROUTER-07)
        candidates.sort(key=lambda pair: pair[0].sort_key)
        return candidates

    def select_provider(
        self,
        policy: RoutingPolicy,
        excluded: frozenset[tuple[str, str]] | None = None,
        session: Session | None = None,
    ) -> RoutingResult:
        """Deterministically selects the best eligible provider for a routing pass."""
        effective_excluded = excluded if excluded is not None else frozenset()
        candidates = self._filter_eligible(policy, effective_excluded, session=session)

        if not candidates:
            raise NoEligibleProviderError(
                f"No eligible AI provider found matching policy requirements (capabilities={policy.required_capabilities})."
            )

        selected_descriptor, estimated_cost = candidates[0]
        return RoutingResult(
            descriptor=selected_descriptor,
            estimated_cost_micro_units=estimated_cost,
            attempt_number=len(effective_excluded) + 1,
        )

    def record_attempt(
        self,
        session: Session,
        request_id: str,
        attempt_number: int,
        provider_id: str,
        model_id: str,
        status: str = "IN_FLIGHT",
        error_class: str | None = None,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> AIProviderAttemptModel:
        """Records an attempt atomically in the database."""
        if attempt_number < 1:
            raise InvalidAttemptError("attempt_number must be >= 1.")

        if error_class is not None:
            from karsasec.ai.provider import KNOWN_ERROR_CLASSES

            if error_class not in KNOWN_ERROR_CLASSES:
                raise InvalidAttemptError(
                    f"Invalid error_class '{error_class}'. Must be a bounded taxonomy string in KNOWN_ERROR_CLASSES."
                )

        attempt_id = str(uuid.uuid4())
        attempt = AIProviderAttemptModel(
            attempt_id=attempt_id,
            request_id=request_id,
            attempt_number=attempt_number,
            provider_id=provider_id,
            model_id=model_id,
            status=status,
            error_class=error_class,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
        )
        session.add(attempt)
        try:
            session.flush()
        except IntegrityError as exc:
            session.rollback()
            raise InvalidAttemptError(
                f"Duplicate attempt for request '{request_id}' attempt {attempt_number}."
            ) from exc

        return attempt

    def record_attempt_failure(
        self,
        session: Session,
        attempt: AIProviderAttemptModel,
        error_class: str,
    ) -> None:
        """Updates attempt status to FAILED and records bounded failure classification."""
        from karsasec.ai.provider import KNOWN_ERROR_CLASSES

        if error_class not in KNOWN_ERROR_CLASSES:
            raise InvalidAttemptError(
                f"Invalid error_class '{error_class}'. Must be a bounded taxonomy string in KNOWN_ERROR_CLASSES."
            )

        attempt.status = "FAILED"
        attempt.error_class = error_class
        session.flush()
