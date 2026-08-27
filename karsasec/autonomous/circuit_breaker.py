import threading
import time

from karsasec.autonomous.models import CircuitBreakerBudget


class CircuitBreakerEngine:
    """Monitors operational limits and trips circuit breaker when blast radius boundaries are exceeded."""

    def __init__(self, budget: CircuitBreakerBudget | None = None) -> None:
        self.budget = budget or CircuitBreakerBudget.create()
        self._lock = threading.Lock()
        self._auto_block_count = 0
        self._action_count = 0
        self._retry_count = 0
        self._start_time = time.time()
        self._window_start_time = time.time()
        self._is_tripped = False

    @property
    def is_tripped(self) -> bool:
        """Returns whether circuit breaker is currently tripped."""
        with self._lock:
            return self._is_tripped

    def check_and_consume(self, is_auto_block: bool = False, is_retry: bool = False) -> tuple[bool, str]:
        """Checks budget availability and consumes single action unit if allowed.

        Returns (allowed, reason).
        """
        with self._lock:
            if self._is_tripped:
                return False, "CIRCUIT_TRIPPED: Circuit breaker is currently tripped"

            now = time.time()

            # Enforce time_budget_seconds: total execution time window
            if self.budget.time_budget_seconds > 0 and (now - self._start_time) > self.budget.time_budget_seconds:
                self._is_tripped = True
                return False, f"CIRCUIT_TRIPPED: Time budget limit ({self.budget.time_budget_seconds}s) exceeded"

            # Enforce retry_budget
            if is_retry:
                if self._retry_count >= self.budget.retry_budget:
                    self._is_tripped = True
                    return False, f"CIRCUIT_TRIPPED: Retry budget limit ({self.budget.retry_budget}) reached"
                self._retry_count += 1

            # Rolling window reset for max_auto_block_per_window
            if now - self._window_start_time > 3600:
                self._window_start_time = now
                self._auto_block_count = 0

            if self._action_count >= self.budget.action_budget:
                self._is_tripped = True
                return False, f"CIRCUIT_TRIPPED: Action budget limit ({self.budget.action_budget}) reached"

            if is_auto_block and self._auto_block_count >= self.budget.max_auto_block_per_window:
                self._is_tripped = True
                return False, f"CIRCUIT_TRIPPED: Max auto-block limit ({self.budget.max_auto_block_per_window}) reached"

            self._action_count += 1
            if is_auto_block:
                self._auto_block_count += 1

            return True, "BUDGET_AVAILABLE"
