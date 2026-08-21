"""Sprint F11 Phase 3 & Phase 6 — Deterministic Failure Classification Engine (INV-F11-FAILURE-15, INV-F11-THROTTLE-10).

Authoritative classification layer that deterministically converts provider execution failures
into bounded internal failure categories without leaking credentials or raw exception messages.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
from dataclasses import dataclass

from karsasec.ai.provider import (
    ATTEMPT_ERROR_AUTH_FAILED,
    ATTEMPT_ERROR_INVALID_REQUEST,
    ATTEMPT_ERROR_INVALID_RESPONSE,
    ATTEMPT_ERROR_NETWORK,
    ATTEMPT_ERROR_PROVIDER_THROTTLED,
    ATTEMPT_ERROR_RATE_LIMIT,
    ATTEMPT_ERROR_TIMEOUT,
    ATTEMPT_ERROR_UNAVAILABLE,
    ATTEMPT_ERROR_UNKNOWN,
)


@dataclass(frozen=True)
class FailureClassification:
    """Immutable, deterministic classification outcome for a provider attempt failure.

    Attributes:
        error_class: Bounded taxonomy string (one of KNOWN_ERROR_CLASSES).
        retryable: True if failure is eligible for automatic retry (5xx, timeout, network, 429 throttling).
        provider_failure: True if failure is caused by provider infrastructure or quota throttling.
        client_failure: True if failure is caused by client request (400, 401, 403, 404, 422).
        throttled: True if failure is caused by provider rate limiting / HTTP 429 quota exhaustion (INV-F11-THROTTLE-10).
    """

    error_class: str
    retryable: bool
    provider_failure: bool
    client_failure: bool
    throttled: bool = False


class FailureClassifier:
    """Authoritative deterministic failure classification engine for AI provider attempts."""

    @classmethod
    def classify(
        cls,
        status_code: int | None = None,
        exception: Exception | None = None,
        error_class_hint: str | None = None,
        is_malformed_response: bool = False,
    ) -> FailureClassification:
        """Classifies a failure into an immutable, bounded FailureClassification.

        Classification Precedence (Hardening Rule 6):
        1. Malformed response check (INV-F11-RESPONSE-10)
        2. Timeout check (INV-F11-TIMEOUT-01)
        3. Network / Connection exception check
        4. 5xx Server Unavailable check (500, 502, 503, 504)
        5. HTTP 429 / Provider Throttling check (INV-F11-THROTTLE-10) -> provider_failure=True, retryable=True, throttled=True
        6. Generic 4xx Client Error check (400, 401, 403, 404, 422) -> client_failure=True, retryable=False
        """
        # 1. Explicit malformed response check
        if is_malformed_response or error_class_hint == ATTEMPT_ERROR_INVALID_RESPONSE:
            return FailureClassification(
                error_class=ATTEMPT_ERROR_INVALID_RESPONSE,
                retryable=False,
                provider_failure=False,
                client_failure=False,
                throttled=False,
            )

        # 2. Timeout check (INV-F11-TIMEOUT-01)
        if error_class_hint == ATTEMPT_ERROR_TIMEOUT or isinstance(
            exception, (TimeoutError, asyncio.TimeoutError, concurrent.futures.TimeoutError)
        ):
            return FailureClassification(
                error_class=ATTEMPT_ERROR_TIMEOUT,
                retryable=True,
                provider_failure=True,
                client_failure=False,
                throttled=False,
            )

        # 3. Connection / Network Exception Classification
        if isinstance(exception, (ConnectionError, OSError)) or error_class_hint == ATTEMPT_ERROR_NETWORK:
            return FailureClassification(
                error_class=ATTEMPT_ERROR_NETWORK,
                retryable=True,
                provider_failure=True,
                client_failure=False,
                throttled=False,
            )

        # 4. HTTP 5xx Server Errors & Hints
        if (status_code is not None and status_code in (500, 502, 503, 504)) or error_class_hint == ATTEMPT_ERROR_UNAVAILABLE:
            return FailureClassification(
                error_class=ATTEMPT_ERROR_UNAVAILABLE,
                retryable=True,
                provider_failure=True,
                client_failure=False,
                throttled=False,
            )

        # 5. HTTP 429 / Provider Throttling (INV-F11-THROTTLE-10) — Precedes generic 4xx!
        if (status_code == 429) or error_class_hint in (ATTEMPT_ERROR_PROVIDER_THROTTLED, ATTEMPT_ERROR_RATE_LIMIT):
            return FailureClassification(
                error_class=ATTEMPT_ERROR_PROVIDER_THROTTLED,
                retryable=True,
                provider_failure=True,
                client_failure=False,
                throttled=True,
            )

        # 6. Generic HTTP 4xx Client Errors & Hints
        if status_code is not None:
            if status_code in (400, 404, 422):
                return FailureClassification(
                    error_class=ATTEMPT_ERROR_INVALID_REQUEST,
                    retryable=False,
                    provider_failure=False,
                    client_failure=True,
                    throttled=False,
                )
            elif status_code in (401, 403):
                return FailureClassification(
                    error_class=ATTEMPT_ERROR_AUTH_FAILED,
                    retryable=False,
                    provider_failure=False,
                    client_failure=True,
                    throttled=False,
                )

        if error_class_hint in (ATTEMPT_ERROR_AUTH_FAILED, ATTEMPT_ERROR_INVALID_REQUEST):
            return FailureClassification(
                error_class=error_class_hint,
                retryable=False,
                provider_failure=False,
                client_failure=True,
                throttled=False,
            )

        # 7. Default Fallback (Unknown)
        return FailureClassification(
            error_class=ATTEMPT_ERROR_UNKNOWN,
            retryable=False,
            provider_failure=False,
            client_failure=False,
            throttled=False,
        )
