"""Sprint F11 Phase 5 & Phase 6 — Provider Circuit Breaker Engine (INV-F11-CIRCUIT-05, INV-F11-CIRCUIT-06, INV-F11-CIRCUIT-07, INV-F11-CIRCUIT-14, ADV-05).

Provides process-local thread-safe circuit breaker state machine:
  - STATES: CLOSED, OPEN, HALF_OPEN
  - Sliding failure window with configurable threshold & min samples
  - Cooldown timer for OPEN -> HALF_OPEN state transition
  - Atomic HALF_OPEN probe count limiting (prevents probe stampedes)
  - 4xx Poisoning Protection: Only FailureClassification.provider_failure == True items trip the circuit.
  - Hardening 7 (INV-F11-CIRCUIT-14): Non-mutating startup recovery from persistent repository.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from threading import Lock
from typing import TYPE_CHECKING, Final

from karsasec.ai.failure_classifier import FailureClassification

if TYPE_CHECKING:
    from karsasec.ai.circuit_repository import CircuitStateData

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
    cooldown_until: float | None = None
    cooldown_reason: str | None = None
    probe_generation: int = 0
    active_probes: int = 0


class ProviderCircuitBreaker:
    """Thread-safe Provider Circuit Breaker Engine (INV-F11-CIRCUIT-05, INV-F11-CIRCUIT-14).

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

    def restore_from_data(self, data: CircuitStateData) -> None:
        """Restores circuit state from persistent data snapshot without mutating state (INV-F11-CIRCUIT-14)."""
        with self._lock:
            st = self._get_or_create_state(data.provider_id, data.model_id)
            st.state = data.state
            st.failures = list(data.failures)
            st.opened_at = data.opened_at
            st.cooldown_until = data.cooldown_until
            st.cooldown_reason = data.cooldown_reason
            st.probe_generation = data.probe_generation
            st.active_probes = 0

    def export_data(self, provider_id: str, model_id: str) -> CircuitStateData:
        """Exports an immutable snapshot of circuit state data for persistence."""
        from karsasec.ai.circuit_repository import CircuitStateData

        with self._lock:
            st = self._get_or_create_state(provider_id, model_id)
            return CircuitStateData(
                provider_id=st.provider_id,
                model_id=st.model_id,
                state=st.state,
                failure_count=sum(1 for f in st.failures if f),
                success_count=sum(1 for f in st.failures if not f),
                failures=list(st.failures),
                opened_at=st.opened_at,
                cooldown_until=st.cooldown_until,
                cooldown_reason=st.cooldown_reason,
                probe_generation=st.probe_generation,
            )

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
        """Checks if circuit is OPEN (or HALF_OPEN probe limit reached), bypassing provider execution (INV-F11-CIRCUIT-05)."""
        with self._lock:
            st = self._get_or_create_state(provider_id, model_id)
            now = self.clock()

            # Check if active cooldown is present
            if st.cooldown_until is not None:
                if now < st.cooldown_until:
                    return True
                else:
                    st.cooldown_until = None
                    st.cooldown_reason = None

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

    def record_throttling(
        self,
        provider_id: str,
        model_id: str,
        cooldown_seconds: float = 60.0,
        reason: str = "PROVIDER_THROTTLED",
    ) -> None:
        """Records provider 429 throttling and activates cooldown without tripping main circuit (INV-F11-THROTTLE-11)."""
        with self._lock:
            st = self._get_or_create_state(provider_id, model_id)
            now = self.clock()
            st.cooldown_until = now + cooldown_seconds
            st.cooldown_reason = reason

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
        """Records an attempt failure outcome."""
        if not classification.provider_failure:
            return  # Ignore 4xx client errors, invalid payloads, auth failures

        with self._lock:
            st = self._get_or_create_state(provider_id, model_id)
            now = self.clock()

            # Handle throttling 429 (INV-F11-THROTTLE-10 / INV-F11-THROTTLE-11)
            if classification.throttled:
                st.cooldown_until = now + self.cooldown_seconds
                st.cooldown_reason = classification.error_class

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
