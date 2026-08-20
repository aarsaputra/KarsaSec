"""Sprint F11 Phase 4 — Bounded Retry & Backoff Engine (INV-F11-RETRY-02, INV-F11-RETRY-03, INV-F11-BACKOFF-04).

Provides:
  - RetryPolicy: Hard limit N_max <= 3, retry eligibility based on FailureClassifier.
  - BackoffCalculator: Exponential backoff with full jitter, capped at max_backoff_seconds.
  - Deterministic RNG & clock injection for testing.
"""

from __future__ import annotations

import random
from collections.abc import Callable
from dataclasses import dataclass
from typing import Final

from karsasec.ai.failure_classifier import FailureClassification

DEFAULT_MAX_ATTEMPTS: Final[int] = 3
DEFAULT_BASE_BACKOFF_SECONDS: Final[float] = 1.0
DEFAULT_MAX_BACKOFF_SECONDS: Final[float] = 30.0


@dataclass(frozen=True)
class RetryDecision:
    """Immutable outcome of a retry policy evaluation."""

    should_retry: bool
    attempt_number: int
    max_attempts: int
    backoff_seconds: float = 0.0
    reason: str = ""


class BackoffCalculator:
    """Calculates exponential backoff with full jitter (INV-F11-BACKOFF-04)."""

    @classmethod
    def calculate_delay(
        cls,
        attempt_number: int,
        base_backoff_seconds: float = DEFAULT_BASE_BACKOFF_SECONDS,
        max_backoff_seconds: float = DEFAULT_MAX_BACKOFF_SECONDS,
        rng_source: Callable[[], float] | None = None,
    ) -> float:
        """Calculates bounded exponential backoff delay with full jitter.

        Formula:
          cap = min(max_backoff_seconds, base_backoff_seconds * 2^(attempt_number - 1))
          delay = rng_source() * cap

        Where rng_source returns a float in [0.0, 1.0].
        """
        if attempt_number <= 0:
            raise ValueError("attempt_number must be positive.")
        if base_backoff_seconds <= 0:
            raise ValueError("base_backoff_seconds must be positive.")
        if max_backoff_seconds < base_backoff_seconds:
            raise ValueError("max_backoff_seconds must be >= base_backoff_seconds.")

        # Exponential upper bound
        exponent = min(attempt_number - 1, 30)  # Prevent math overflow
        exponential_cap = min(max_backoff_seconds, base_backoff_seconds * (2**exponent))

        # Full jitter multiplier in [0.0, 1.0]
        rng = rng_source if rng_source is not None else random.random
        jitter_factor = rng()
        # Clamp jitter factor to [0.0, 1.0] for safety
        jitter_factor = max(0.0, min(1.0, jitter_factor))

        delay = jitter_factor * exponential_cap
        return max(0.0, min(max_backoff_seconds, delay))


@dataclass(frozen=True)
class RetryPolicy:
    """Authoritative retry policy enforcing N_max hard limit and failure eligibility."""

    max_attempts: int = DEFAULT_MAX_ATTEMPTS
    base_backoff_seconds: float = DEFAULT_BASE_BACKOFF_SECONDS
    max_backoff_seconds: float = DEFAULT_MAX_BACKOFF_SECONDS
    rng_source: Callable[[], float] | None = None

    def __post_init__(self) -> None:
        if self.max_attempts < 1:
            raise ValueError("max_attempts must be at least 1.")
        if self.base_backoff_seconds <= 0:
            raise ValueError("base_backoff_seconds must be positive.")
        if self.max_backoff_seconds < self.base_backoff_seconds:
            raise ValueError("max_backoff_seconds must be >= base_backoff_seconds.")

    def evaluate(
        self,
        attempt_number: int,
        classification: FailureClassification,
    ) -> RetryDecision:
        """Evaluates whether another attempt should be executed.

        Enforces:
        - attempt_number < max_attempts (INV-F11-RETRY-03)
        - classification.retryable is True (INV-F11-RETRY-02)
        - classification.provider_failure is True
        """
        if attempt_number >= self.max_attempts:
            return RetryDecision(
                should_retry=False,
                attempt_number=attempt_number,
                max_attempts=self.max_attempts,
                reason="EXHAUSTED_MAX_ATTEMPTS",
            )

        if not classification.retryable or not classification.provider_failure:
            return RetryDecision(
                should_retry=False,
                attempt_number=attempt_number,
                max_attempts=self.max_attempts,
                reason=f"NON_RETRYABLE_FAILURE_{classification.error_class}",
            )

        next_attempt_number = attempt_number + 1
        backoff = BackoffCalculator.calculate_delay(
            attempt_number=attempt_number,
            base_backoff_seconds=self.base_backoff_seconds,
            max_backoff_seconds=self.max_backoff_seconds,
            rng_source=self.rng_source,
        )

        return RetryDecision(
            should_retry=True,
            attempt_number=next_attempt_number,
            max_attempts=self.max_attempts,
            backoff_seconds=backoff,
            reason="ELIGIBLE_RETRY",
        )
