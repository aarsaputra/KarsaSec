"""Sprint F10 Phase 3 — Deterministic Cost-Aware AI Provider Router (INV-F10-ROUTER-01 through INV-F10-ROUTER-10).

Implements a deterministic multi-stage provider selection pipeline.
Integrates with AIRequestStateService and AIProviderAttemptModel for attempt ledger recording.

No random selection, no wall-clock-time-based routing, no process-local financial authority.

Selection pipeline (INV-F10-ROUTER-01):
  [1] Policy eligibility  — providers with unknown/malformed pricing rejected
  [2] Capability check    — INV-F10-ROUTER-06
  [3] Health eligibility  — INV-F10-ROUTER-05 (UNKNOWN/UNAVAILABLE = fail-closed)
  [4] Cost ceiling        — INV-F10-ROUTER-03/INV-F10-ROUTER-04
  [5] Priority sort       — lower priority value = higher preference
  [6] Lexical tie-break   — (provider_id, model_id) stable sort (INV-F10-ROUTER-07)

Failover (INV-F10-ROUTER-02):
  When the selected provider fails, the router re-runs selection excluding all previously
  attempted (provider_id, model_id) pairs, in attempt_number order (INV-F10-ROUTER-10).

Authority boundaries (INV-F10-ROUTER-09):
  Router NEVER mutates ai_budgets directly.
  Budget operations must be delegated to AIBudgetService by the caller.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Any

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from karsasec.ai.exceptions import KarsaSecAIError
from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.pricing import PricingError, is_within_cost_ceiling
from karsasec.ai.provider import (
    ELIGIBLE_HEALTH_STATES,
    HEALTH_DEGRADED,
    HEALTH_UNKNOWN,
    KNOWN_ERROR_CLASSES,
    ProviderDescriptor,
)
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.routing_policy import RoutingPolicy
from karsasec.persistence.models import AIProviderAttemptModel


class NoEligibleProviderError(KarsaSecAIError):
    """Raised when no provider satisfies all eligibility criteria for a routing pass (INV-F10-ROUTER-01)."""

    pass


class InvalidAttemptError(KarsaSecAIError):
    """Raised when an attempt record cannot be created due to uniqueness or validation failure."""

    pass


@dataclass(frozen=True)
class RoutingResult:
    """Result of a successful provider selection pass.

    Attributes:
        descriptor: Selected ProviderDescriptor.
        attempt_number: 1-indexed attempt number for this routing pass.
        estimated_cost_micro_units: Estimated request cost in integer micro-units.
    """

    descriptor: ProviderDescriptor
    attempt_number: int
    estimated_cost_micro_units: int


class ProviderRouter:
    """Deterministic cost-aware AI provider router (INV-F10-ROUTER-01 through INV-F10-ROUTER-10).

    Responsibility:
    - Select the optimal provider deterministically given routing policy constraints.
    - Record provider attempt identity in AIProviderAttemptModel (INV-F10-ROUTER-08).
    - Enforce capability, health, and cost filters strictly.
    - Delegate all budget mutations to the caller (never mutate ai_budgets directly).

    Does NOT:
    - Mutate AIBudgetModel directly (INV-F10-ROUTER-09).
    - Use random.choice(), random.shuffle(), or wall-clock time as routing criteria.
    - Use process-local state as authoritative financial accounting.
    """

    def __init__(
        self,
        registry: ProviderRegistry,
        health_registry: ProviderHealthRegistry | None = None,
        circuit_breaker: Any | None = None,
    ) -> None:
        self.registry = registry
        self.health_registry = health_registry or ProviderHealthRegistry()
        self.circuit_breaker = circuit_breaker

    def _filter_eligible(
        self,
        policy: RoutingPolicy,
        excluded: frozenset[tuple[str, str]],
    ) -> list[tuple[ProviderDescriptor, int]]:
        """Runs the deterministic multi-stage eligibility filter.

        Returns a list of (descriptor, estimated_cost_micro_units) tuples for all eligible providers,
        in stable selection order (priority ASC, provider_id ASC, model_id ASC).

        Stages applied:
        [1] Exclusion list (prior failed attempts)
        [2] Capability check (INV-F10-ROUTER-06)
        [3] Health eligibility (INV-F10-ROUTER-05)
        [3.5] Circuit breaker state (INV-F11-CIRCUIT-05)
        [4] Cost ceiling (INV-F10-ROUTER-03/04)

        Providers that fail any stage are silently excluded from the candidate set.
        Unknown pricing on the descriptor causes fail-closed exclusion (INV-F10-ROUTER-04).
        """
        candidates: list[tuple[ProviderDescriptor, int]] = []

        all_providers = self.registry.list_all()  # Already stable-sorted by (provider_id, model_id)

        for descriptor in all_providers:
            key = (descriptor.provider_id, descriptor.model_id)

            # Stage 1 — Exclusion list (prior failed attempts)
            if key in excluded:
                continue

            # Stage 2 — Capability compatibility (INV-F10-ROUTER-06)
            if not policy.required_capabilities.issubset(descriptor.capabilities):
                continue

            # Stage 3 — Health eligibility (INV-F10-ROUTER-05)
            active_health = self.health_registry.get_health(descriptor.provider_id, descriptor.model_id)
            if active_health == HEALTH_UNKNOWN:
                continue  # fail-closed — health never registered
            if active_health not in ELIGIBLE_HEALTH_STATES:
                continue  # UNAVAILABLE = rejected
            if active_health == HEALTH_DEGRADED and not policy.allow_degraded:
                continue  # Policy disallows degraded providers

            # Stage 3.5 — Circuit breaker state (INV-F11-CIRCUIT-05)
            if self.circuit_breaker and self.circuit_breaker.is_open(descriptor.provider_id, descriptor.model_id):
                continue  # OPEN circuit — bypass provider immediately without executing network calls

            # Stage 4 — Cost ceiling (INV-F10-ROUTER-03/04)
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
                continue  # Malformed or unknown pricing — fail-closed (INV-F10-ROUTER-04)

            candidates.append((descriptor, estimated))

        # Stage 5/6 — Priority sort + stable lexical tie-break (INV-F10-ROUTER-07)
        # sort_key = (priority ASC, provider_id ASC, model_id ASC)
        candidates.sort(key=lambda pair: pair[0].sort_key)
        return candidates

    def select_provider(
        self,
        policy: RoutingPolicy,
        excluded: frozenset[tuple[str, str]] | None = None,
    ) -> RoutingResult:
        """Deterministically selects the best eligible provider for a routing pass.

        Args:
            policy: Active routing constraints and requirements.
            excluded: Set of (provider_id, model_id) tuples to exclude (prior failed attempts).

        Returns:
            RoutingResult with the selected descriptor and estimated cost.

        Raises:
            NoEligibleProviderError: If no provider satisfies all eligibility criteria (fail-closed).
        """
        excluded = excluded or frozenset()
        attempt_number = len(excluded) + 1  # 1-indexed (INV-F10-ROUTER-10)

        candidates = self._filter_eligible(policy, excluded)
        if not candidates:
            raise NoEligibleProviderError(
                f"No eligible provider found for policy "
                f"(capabilities={sorted(policy.required_capabilities)}, "
                f"max_cost={policy.max_request_cost_micro_units}, "
                f"allow_degraded={policy.allow_degraded}, "
                f"excluded={sorted(excluded)})."
            )

        descriptor, estimated_cost = candidates[0]
        return RoutingResult(
            descriptor=descriptor,
            attempt_number=attempt_number,
            estimated_cost_micro_units=estimated_cost,
        )

    def record_attempt(
        self,
        session: Session,
        request_id: str,
        attempt_number: int,
        provider_id: str,
        model_id: str,
        status: str = "IN_FLIGHT",
        input_tokens: int = 0,
        output_tokens: int = 0,
        error_class: str | None = None,
    ) -> AIProviderAttemptModel:
        """Creates an attempt record in the AIProviderAttemptModel ledger (INV-F10-ROUTER-08).

        Constraints enforced:
        - UNIQUE(request_id, attempt_number) — database constraint prevents duplicates.
        - error_class must be a bounded taxonomy string or None (INV-F10-ROUTER-09).
        - No raw exception payloads or credentials are stored.

        Raises:
            InvalidAttemptError: If attempt creation fails due to uniqueness or validation.
        """
        if error_class is not None and error_class not in KNOWN_ERROR_CLASSES:
            raise InvalidAttemptError(
                f"error_class '{error_class}' is not a known bounded taxonomy string. "
                f"Use one of: {sorted(KNOWN_ERROR_CLASSES)}."
            )
        if input_tokens < 0 or output_tokens < 0:
            raise InvalidAttemptError(
                f"input_tokens and output_tokens must be non-negative "
                f"(got input={input_tokens}, output={output_tokens})."
            )

        attempt_id = str(uuid.uuid4())
        attempt = AIProviderAttemptModel(
            attempt_id=attempt_id,
            request_id=request_id,
            attempt_number=attempt_number,
            provider_id=provider_id,
            model_id=model_id,
            status=status,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            error_class=error_class,
        )
        session.add(attempt)
        try:
            session.flush()
        except IntegrityError as exc:
            session.rollback()
            raise InvalidAttemptError(
                f"Failed to record attempt #{attempt_number} for request '{request_id}': "
                f"UNIQUE constraint violation (duplicate attempt_number). "
                f"Concurrent worker may have created this attempt already."
            ) from exc

        return attempt

    def record_attempt_failure(
        self,
        session: Session,
        attempt: AIProviderAttemptModel,
        error_class: str,
    ) -> None:
        """Updates an existing IN_FLIGHT attempt to FAILED status with a bounded error class.

        Raises:
            InvalidAttemptError: If error_class is not in the bounded taxonomy.
        """
        if error_class not in KNOWN_ERROR_CLASSES:
            raise InvalidAttemptError(f"error_class '{error_class}' is not a known bounded taxonomy string.")
        attempt.status = "FAILED"
        attempt.error_class = error_class
        session.flush()
