"""Sprint F11 Phase 3 — Deterministic Failure Classification Engine (INV-F11-FAILURE-15).

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
        retryable: True if failure is eligible for automatic retry (5xx, timeout, network).
        provider_failure: True if failure is caused by provider infrastructure (5xx, timeout, network).
        client_failure: True if failure is caused by client request (4xx: 400, 401, 403, 404, 422, 429).
    """

    error_class: str
    retryable: bool
    provider_failure: bool
    client_failure: bool


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

        Guarantees:
        - 100% deterministic (same input -> same output).
        - 4xx client errors MUST NEVER be classified as provider_failure or retryable (4xx security rule).
        - 5xx server errors and timeouts MUST be classified as provider_failure and retryable.
        - Malformed responses MUST be classified as NON_RETRYABLE with ATTEMPT_ERROR_INVALID_RESPONSE.
        - Zero raw exception or header text is leaked.
        """
        # 1. Explicit malformed response check
        if is_malformed_response or error_class_hint == ATTEMPT_ERROR_INVALID_RESPONSE:
            return FailureClassification(
                error_class=ATTEMPT_ERROR_INVALID_RESPONSE,
                retryable=False,
                provider_failure=False,
                client_failure=False,
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
            )

        # 3. HTTP Status Code Classification
        if status_code is not None:
            if status_code in (400, 404, 422):
                return FailureClassification(
                    error_class=ATTEMPT_ERROR_INVALID_REQUEST,
                    retryable=False,
                    provider_failure=False,
                    client_failure=True,
                )
            elif status_code in (401, 403):
                return FailureClassification(
                    error_class=ATTEMPT_ERROR_AUTH_FAILED,
                    retryable=False,
                    provider_failure=False,
                    client_failure=True,
                )
            elif status_code == 429:
                return FailureClassification(
                    error_class=ATTEMPT_ERROR_RATE_LIMIT,
                    retryable=False,
                    provider_failure=False,
                    client_failure=True,
                )
            elif status_code in (500, 502, 503, 504):
                return FailureClassification(
                    error_class=ATTEMPT_ERROR_UNAVAILABLE,
                    retryable=True,
                    provider_failure=True,
                    client_failure=False,
                )

        # 4. Error class hint classification
        if error_class_hint == ATTEMPT_ERROR_RATE_LIMIT:
            return FailureClassification(
                error_class=ATTEMPT_ERROR_RATE_LIMIT,
                retryable=False,
                provider_failure=False,
                client_failure=True,
            )
        elif error_class_hint in (ATTEMPT_ERROR_AUTH_FAILED, ATTEMPT_ERROR_INVALID_REQUEST):
            return FailureClassification(
                error_class=error_class_hint,
                retryable=False,
                provider_failure=False,
                client_failure=True,
            )
        elif error_class_hint in (ATTEMPT_ERROR_UNAVAILABLE, ATTEMPT_ERROR_NETWORK):
            return FailureClassification(
                error_class=error_class_hint,
                retryable=True,
                provider_failure=True,
                client_failure=False,
            )

        # 5. Connection / Network Exception Classification
        if isinstance(exception, (ConnectionError, OSError)):
            return FailureClassification(
                error_class=ATTEMPT_ERROR_NETWORK,
                retryable=True,
                provider_failure=True,
                client_failure=False,
            )

        # 6. Default Fallback (Unknown)
        return FailureClassification(
            error_class=ATTEMPT_ERROR_UNKNOWN,
            retryable=False,
            provider_failure=False,
            client_failure=False,
        )
