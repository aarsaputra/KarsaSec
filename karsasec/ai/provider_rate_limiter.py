"""Sprint F11 Phase 6 — Distributed Rate Limiter & Token Bucket Engine (INV-F11-RATELIMIT-08, INV-F11-RATELIMIT-09, INV-F11-RATELIMIT-13).

Provides atomic, cluster-safe rate limiting with separate Request Buckets (RPM) and Token Buckets (TPM):
  - Hardening 3: Injectable ClockProvider / time_source for deterministic testing.
  - Hardening 4: DB-authoritative row locking (SELECT ... FOR UPDATE) for INV-F11-RATELIMIT-13 token acquisition atomicity.
  - Hardening 5: Separate RPM (request_bucket) and TPM (token_bucket) capacity tracking.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from sqlalchemy.orm import Session

from karsasec.persistence.models import AIProviderRateLimitModel

DEFAULT_COOLDOWN_SECONDS: Final[float] = 60.0


@dataclass(frozen=True)
class ProviderRateLimitPolicy:
    """Immutable configuration policy for provider rate limiting."""

    rpm_limit: float = 60.0  # Requests Per Minute
    tpm_limit: float = 60000.0  # Tokens Per Minute
    daily_request_limit: float | None = None
    burst_multiplier: float = 1.0  # Bucket capacity multiplier (1.0 = strict capacity)

    def __post_init__(self) -> None:
        if self.rpm_limit <= 0:
            raise ValueError("rpm_limit must be positive.")
        if self.tpm_limit <= 0:
            raise ValueError("tpm_limit must be positive.")
        if self.burst_multiplier < 1.0:
            raise ValueError("burst_multiplier must be at least 1.0.")


@dataclass(frozen=True)
class RateLimitResult:
    """Outcome of a rate limit acquisition check."""

    allowed: bool
    reason: str | None = None
    cooldown_until: float | None = None
    retry_after_seconds: float = 0.0


class DistributedTokenBucket:
    """Database-authoritative atomic token bucket rate limiter (INV-F11-RATELIMIT-13).

    Guarantees cluster-wide rate limit enforcement without quota amplification across concurrent workers.
    """

    def __init__(
        self,
        time_source: Callable[[], float] | None = None,
    ) -> None:
        self.time_source = time_source or time.time

    def check_and_consume(
        self,
        session: Session,
        provider_id: str,
        model_id: str,
        policy: ProviderRateLimitPolicy,
        requested_tokens: int = 1,
    ) -> RateLimitResult:
        """Atomically checks and consumes 1 request slot + requested_tokens from DB state.

        Uses `SELECT ... FOR UPDATE` (or SQLite fallback) for atomic row locking (INV-F11-RATELIMIT-13).
        """
        now = self.time_source()

        # Execute row lookup with DB lock for atomicity
        query = session.query(AIProviderRateLimitModel).filter(
            AIProviderRateLimitModel.provider_id == provider_id,
            AIProviderRateLimitModel.model_id == model_id,
        )

        try:
            row = query.with_for_update().one_or_none()
        except Exception:
            row = query.one_or_none()

        max_req = policy.rpm_limit * policy.burst_multiplier
        max_tok = policy.tpm_limit * policy.burst_multiplier
        rpm_refill_rate = policy.rpm_limit / 60.0  # requests per second
        tpm_refill_rate = policy.tpm_limit / 60.0  # tokens per second

        if row is None:
            # Initialize bucket row
            row = AIProviderRateLimitModel(
                provider_id=provider_id,
                model_id=model_id,
                requests_remaining=max_req,
                max_requests=max_req,
                rpm_refill_rate=rpm_refill_rate,
                last_request_refill_at=now,
                tokens_remaining=max_tok,
                max_tokens=max_tok,
                tpm_refill_rate=tpm_refill_rate,
                last_token_refill_at=now,
            )
            session.add(row)
            try:
                session.flush()
            except Exception:
                session.rollback()
                row = session.query(AIProviderRateLimitModel).filter(
                    AIProviderRateLimitModel.provider_id == provider_id,
                    AIProviderRateLimitModel.model_id == model_id,
                ).one()

        # Check if provider is currently in cooldown (INV-F11-THROTTLE-11)
        if row.cooldown_until is not None and now < row.cooldown_until:
            return RateLimitResult(
                allowed=False,
                reason=row.cooldown_reason or "PROVIDER_COOLDOWN",
                cooldown_until=row.cooldown_until,
                retry_after_seconds=row.cooldown_until - now,
            )

        # Refill Request Bucket (RPM)
        elapsed_req = max(0.0, now - row.last_request_refill_at)
        row.requests_remaining = min(
            row.max_requests,
            row.requests_remaining + (elapsed_req * row.rpm_refill_rate),
        )
        row.last_request_refill_at = now

        # Refill Token Bucket (TPM)
        elapsed_tok = max(0.0, now - row.last_token_refill_at)
        row.tokens_remaining = min(
            row.max_tokens,
            row.tokens_remaining + (elapsed_tok * row.tpm_refill_rate),
        )
        row.last_token_refill_at = now

        # Evaluate RPM availability
        if row.requests_remaining < 1.0:
            deficit = 1.0 - row.requests_remaining
            retry_after = deficit / row.rpm_refill_rate if row.rpm_refill_rate > 0 else 1.0
            return RateLimitResult(
                allowed=False,
                reason="RPM_LIMIT_EXCEEDED",
                retry_after_seconds=retry_after,
            )

        # Evaluate TPM availability
        if row.tokens_remaining < requested_tokens:
            deficit = requested_tokens - row.tokens_remaining
            retry_after = deficit / row.tpm_refill_rate if row.tpm_refill_rate > 0 else 1.0
            return RateLimitResult(
                allowed=False,
                reason="TPM_LIMIT_EXCEEDED",
                retry_after_seconds=retry_after,
            )

        # Consume 1 request + requested_tokens
        row.requests_remaining -= 1.0
        row.tokens_remaining -= requested_tokens
        session.flush()

        return RateLimitResult(allowed=True)

    def set_cooldown(
        self,
        session: Session,
        provider_id: str,
        model_id: str,
        cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS,
        reason: str = "PROVIDER_THROTTLED",
    ) -> None:
        """Sets provider cooldown in persistent database ledger (INV-F11-THROTTLE-11)."""
        now = self.time_source()
        cooldown_until = now + cooldown_seconds

        query = session.query(AIProviderRateLimitModel).filter(
            AIProviderRateLimitModel.provider_id == provider_id,
            AIProviderRateLimitModel.model_id == model_id,
        )

        try:
            row = query.with_for_update().one_or_none()
        except Exception:
            row = query.one_or_none()

        if row is None:
            row = AIProviderRateLimitModel(
                provider_id=provider_id,
                model_id=model_id,
                requests_remaining=0.0,
                max_requests=60.0,
                rpm_refill_rate=1.0,
                last_request_refill_at=now,
                tokens_remaining=0.0,
                max_tokens=60000.0,
                tpm_refill_rate=1000.0,
                last_token_refill_at=now,
                cooldown_until=cooldown_until,
                cooldown_reason=reason,
            )
            session.add(row)
        else:
            row.cooldown_until = cooldown_until
            row.cooldown_reason = reason

        session.flush()

    def is_in_cooldown(
        self,
        session: Session,
        provider_id: str,
        model_id: str,
    ) -> tuple[bool, str | None, float | None]:
        """Checks if provider is currently in active cooldown state."""
        now = self.time_source()
        row = (
            session.query(AIProviderRateLimitModel)
            .filter(
                AIProviderRateLimitModel.provider_id == provider_id,
                AIProviderRateLimitModel.model_id == model_id,
            )
            .one_or_none()
        )

        if row is not None and row.cooldown_until is not None:
            if now < row.cooldown_until:
                return True, row.cooldown_reason, row.cooldown_until

        return False, None, None
