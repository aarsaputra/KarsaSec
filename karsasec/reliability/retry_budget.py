"""Task Retry Budget Manager for Sprint F6C.

Invariants:
  - INV-F6-RETRY-01: max_attempts is strictly task-bound and immutable once created.
  - INV-F6-RETRY-02: Zero process-local retry state. PostgreSQL is sole source of truth.
  - INV-F6-RETRY-03: attempts is incremented exactly once upon transition from QUEUED to RUNNING.
  - INV-F6-RETRY-04: Task execution failure returning task to QUEUED does not increment attempts.
  - INV-F6-RETRY-05: Task state transitions to FAILED when attempts >= max_attempts.
"""

from __future__ import annotations

from karsasec.workers.task import RemediationTask


class TaskRetryBudget:
    """Task-bound retry budget evaluator."""

    @staticmethod
    def can_retry(task: RemediationTask) -> bool:
        """Evaluate if task has remaining retry budget."""
        return task.attempts < task.max_attempts

    @staticmethod
    def remaining_attempts(task: RemediationTask) -> int:
        """Return remaining attempt budget for task."""
        remaining = task.max_attempts - task.attempts
        return max(0, remaining)

    @staticmethod
    def is_exhausted(task: RemediationTask) -> bool:
        """Return True if retry budget is exhausted."""
        return task.attempts >= task.max_attempts
