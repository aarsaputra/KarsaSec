"""Sprint F11 Phase 5 — Provider Circuit Breaker (INV-F11-CIRCUIT-05, ADV-05).

Provides process-local thread-safe circuit breaker state machine:
  - STATES: CLOSED, OPEN, HALF_OPEN
  - Sliding failure window with configurable threshold & min samples
  - Cooldown timer for OPEN -> HALF_OPEN state transition
  - Atomic HALF_OPEN probe count limiting (prevents probe stampedes)
  - 4xx Poisoning Protection: Only FailureClassification.provider_failure == True items trip the circuit.
"""

from __future__ import annotations

import time

from collections.abc import Callable
from dataclasses import dataclass, field
from threading import Lock
from typing import Final

from karsasec.ai.failure_classifier import FailureClassification

STATE_CLOSED: Final[str] = "CLOSED"
STATE_OPEN: Final[str] = "OPEN"
STATE_HALF_OPEN: Final[str] = "HALF_OPEN"

KNOWN_CIRCUIT_STATES: Final[set[str]] = {
    STATE_CLOSED,
    STATE_OPEN,
    STATE_HALF_OPEN,
}

DEFAULT_FAILURE_WINDOW_SIZE: Final[int] = 10
DEFAULT_FAILURE_THRESHOLD: Final[float] = 0.5
DEFAULT_MIN_SAMPLES: Final[int] = 5
DEFAULT_COOLDOWN_SECONDS: Final[float] = 30.0
DEFAULT_HALF_OPEN_MAX_PROBES: Final[int] = 1


@dataclass
class ProviderCircuitState:
    """Internal mutable tracking state for a specific (provider_id, model_id) circuit."""

    provider_id: str
    model_id: str
    state: str = STATE_CLOSED
    failures: list[bool] = field(default_factory=list)  # Sliding window: True for provider failure, False for success
    opened_at: float | None = None
    active_probes: int = 0


class ProviderCircuitBreaker:
    """Thread-safe Provider Circuit Breaker Engine (INV-F11-CIRCUIT-05).

    Manages provider execution health state transitions (CLOSED -> OPEN -> HALF_OPEN -> CLOSED).
    Protects downstream infrastructure from cascading failures while excluding 4xx client errors.
    """

    def __init__(
        self,
        failure_window_size: int = DEFAULT_FAILURE_WINDOW_SIZE,
        failure_threshold: float = DEFAULT_FAILURE_THRESHOLD,
        min_samples: int = DEFAULT_MIN_SAMPLES,
        cooldown_seconds: float = DEFAULT_COOLDOWN_SECONDS,
        half_open_max_probes: int = DEFAULT_HALF_OPEN_MAX_PROBES,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if failure_window_size < 1:
            raise ValueError("failure_window_size must be at least 1.")
        if not (0.0 < failure_threshold <= 1.0):
            raise ValueError("failure_threshold must be in range (0.0, 1.0].")
        if min_samples < 1:
            raise ValueError("min_samples must be at least 1.")
        if cooldown_seconds <= 0:
            raise ValueError("cooldown_seconds must be positive.")
        if half_open_max_probes < 1:
            raise ValueError("half_open_max_probes must be at least 1.")

        self.failure_window_size = failure_window_size
        self.failure_threshold = failure_threshold
        self.min_samples = min_samples
        self.cooldown_seconds = cooldown_seconds
        self.half_open_max_probes = half_open_max_probes
        self.clock = clock or time.monotonic

        self._states: dict[tuple[str, str], ProviderCircuitState] = {}
        self._lock = Lock()

    def _get_or_create_state(self, provider_id: str, model_id: str) -> ProviderCircuitState:
        key = (provider_id, model_id)
        if key not in self._states:
            self._states[key] = ProviderCircuitState(provider_id=provider_id, model_id=model_id)
        return self._states[key]

    def get_state(self, provider_id: str, model_id: str) -> str:
        """Returns active circuit state string ('CLOSED', 'OPEN', or 'HALF_OPEN')."""
        with self._lock:
            st = self._get_or_create_state(provider_id, model_id)
            now = self.clock()

            if st.state == STATE_OPEN:
                if st.opened_at is not None and (now - st.opened_at) >= self.cooldown_seconds:
                    # Transition OPEN -> HALF_OPEN on cooldown expiry
                    st.state = STATE_HALF_OPEN
                    st.active_probes = 0

            return st.state

    def is_open(self, provider_id: str, model_id: str) -> bool:
        """Checks if circuit is OPEN (or HALF_OPEN probe limit reached), bypassing provider execution (INV-F11-CIRCUIT-05).

        Returns:
            True: If provider circuit is OPEN and MUST be bypassed by ProviderRouter.
            False: If provider circuit is CLOSED or HALF_OPEN with available probe slot.
        """
        with self._lock:
            st = self._get_or_create_state(provider_id, model_id)
            now = self.clock()

            if st.state == STATE_CLOSED:
                return False

            if st.state == STATE_OPEN:
                if st.opened_at is not None and (now - st.opened_at) >= self.cooldown_seconds:
                    # Cooldown elapsed: transition OPEN -> HALF_OPEN
                    st.state = STATE_HALF_OPEN
                    st.active_probes = 0
                else:
                    # Cooldown active: circuit is OPEN
                    return True

            if st.state == STATE_HALF_OPEN:
                if st.active_probes < self.half_open_max_probes:
                    st.active_probes += 1
                    return False  # Allow this probe request to execute
                # Probe limit reached: bypass subsequent concurrent requests
                return True

            return False

    def record_success(self, provider_id: str, model_id: str) -> None:
        """Records a successful execution outcome."""
        with self._lock:
            st = self._get_or_create_state(provider_id, model_id)
            now = self.clock()

            if st.state == STATE_OPEN and st.opened_at is not None and (now - st.opened_at) >= self.cooldown_seconds:
                st.state = STATE_HALF_OPEN
                st.active_probes = 0

            if st.state == STATE_HALF_OPEN:
                # Successful probe transitions HALF_OPEN -> CLOSED
                st.state = STATE_CLOSED
                st.failures.clear()
                st.active_probes = 0
                st.opened_at = None

            elif st.state == STATE_CLOSED:
                # Add success to sliding failure window
                st.failures.append(False)
                if len(st.failures) > self.failure_window_size:
                    st.failures.pop(0)

    def record_failure(
        self,
        provider_id: str,
        model_id: str,
        classification: FailureClassification,
    ) -> None:
        """Records an attempt failure outcome.

        Security Requirement (INV-F11-FAILURE-15):
        Only provider infrastructure failures (classification.provider_failure == True) count towards circuit tripping.
        4xx client errors (classification.client_failure == True) are ignored to prevent circuit poisoning.
        """
        if not classification.provider_failure:
            return  # Ignore 4xx client errors, invalid payloads, auth failures

        with self._lock:
            st = self._get_or_create_state(provider_id, model_id)
            now = self.clock()

            if st.state == STATE_OPEN and st.opened_at is not None and (now - st.opened_at) >= self.cooldown_seconds:
                st.state = STATE_HALF_OPEN
                st.active_probes = 0

            if st.state == STATE_HALF_OPEN:
                # Failed probe transitions HALF_OPEN -> OPEN
                st.state = STATE_OPEN
                st.opened_at = now
                st.active_probes = 0

            elif st.state == STATE_CLOSED:
                st.failures.append(True)
                if len(st.failures) > self.failure_window_size:
                    st.failures.pop(0)

                # Evaluate sliding window threshold
                if len(st.failures) >= self.min_samples:
                    failure_count = sum(1 for f in st.failures if f)
                    failure_rate = failure_count / len(st.failures)
                    if failure_rate >= self.failure_threshold:
                        st.state = STATE_OPEN
                        st.opened_at = now
                        st.active_probes = 0
