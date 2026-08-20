"""Task Domain Model and State Machine for Sprint F2.

Defines the RemediationTask, TaskState enum, and transition rules.
Enforces Invariant R1-R6 (Determinism) and L7 (Zero Security Authority).
"""

from __future__ import annotations

import time
from enum import StrEnum
from typing import Any


class StaleLeaseVersionError(Exception):
    """Raised when task mutation is attempted with a stale fencing lease version."""

    pass


class InvalidTaskStateError(Exception):
    """Raised when task state transition is attempted from an unexpected or invalid state."""

    pass


class WorkerFencedError(Exception):
    """Raised when task mutation is attempted by a worker whose fencing token is stale or status is FENCED/OFFLINE."""

    pass


class InvalidWorkerStateError(Exception):
    """Raised when task operation is attempted for a worker in an invalid status (e.g. DRAINING/DRAINED)."""

    pass


class TaskState(StrEnum):
    """Lifecycle states for asynchronous remediation tasks."""

    PENDING = "PENDING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    FAILED_RETRYABLE = "FAILED_RETRYABLE"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class RemediationTask:
    """Domain model tracking remediation task state, retries, and lease metrics.

    Does not use uuid/random/time for identity generation; task_id is mapped
    from deterministic payload fingerprints to enforce determinism.
    """

    def __init__(
        self,
        task_id: str,
        finding_id: str,
        approval_token_id: str,
        token: str,
        fingerprint: str,
        state: TaskState = TaskState.PENDING,
        attempts: int = 0,
        max_attempts: int = 3,
        lease_seconds: int = 300,
    ) -> None:
        self.task_id = task_id
        self.finding_id = finding_id
        self.approval_token_id = approval_token_id
        self.token = token
        self.fingerprint = fingerprint
        self._state = state
        self.attempts = attempts
        self.max_attempts = max_attempts
        self.lease_seconds = lease_seconds
        self.started_at: float | None = None
        self.error_message: str | None = None
        self.receipt_id: str | None = None
        self.receipt_fingerprint: str | None = None
        self.security_verification_status: str | None = None
        self.receipt: Any | None = None
        self.lease_version: int = 1  # Fencing Token Pattern to prevent split-brain double commits

    def increment_lease_version(self) -> int:
        """Increment fencing token version when task is recovered/requeued."""
        self.lease_version += 1
        return self.lease_version

    def validate_lease_version(self, submitted_version: int) -> bool:
        """Validate if worker's lease version matches active task fencing token."""
        return submitted_version == self.lease_version

    @property
    def state(self) -> TaskState:
        return self._state

    def transition_to(self, new_state: TaskState, reason: str | None = None) -> None:
        """Validates and executes task state transition."""
        allowed = self._get_allowed_transitions(self._state)
        if new_state not in allowed:
            raise ValueError(f"Invalid transition from {self._state} to {new_state}")

        self._state = new_state
        if new_state == TaskState.RUNNING:
            # We track time using a monotonic clock to prevent system time jump interference.
            # To maintain determinism in tests, started_at can be stubbed or simulated.
            self.started_at = time.monotonic()
            self.attempts += 1
        elif new_state in (TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED, TaskState.QUEUED):
            self.started_at = None

    def is_lease_expired(self, current_time: float) -> bool:
        """Check if lease has expired while running."""
        if self._state != TaskState.RUNNING or self.started_at is None:
            return False
        return (current_time - self.started_at) > self.lease_seconds

    @staticmethod
    def _get_allowed_transitions(state: TaskState) -> set[TaskState]:
        """Defines state machine transition rules."""
        rules = {
            TaskState.PENDING: {TaskState.QUEUED},
            TaskState.QUEUED: {TaskState.RUNNING, TaskState.CANCELLED},
            TaskState.RUNNING: {
                TaskState.COMPLETED,
                TaskState.FAILED_RETRYABLE,
                TaskState.FAILED,
                TaskState.CANCELLED,
                TaskState.QUEUED,
            },
            TaskState.FAILED_RETRYABLE: {TaskState.QUEUED, TaskState.FAILED},
            TaskState.COMPLETED: set(),
            TaskState.FAILED: set(),
            TaskState.CANCELLED: set(),
        }
        return rules.get(state, set())

    def to_dict(self) -> dict[str, Any]:
        """Serialize task metadata cleanly without source code or credentials."""
        return {
            "task_id": self.task_id,
            "finding_id": self.finding_id,
            "approval_token_id": self.approval_token_id,
            "state": str(self._state),
            "attempts": self.attempts,
            "max_attempts": self.max_attempts,
            "lease_seconds": self.lease_seconds,
            "lease_version": self.lease_version,
            "error_message": self.error_message,
            "receipt_id": self.receipt_id,
            "receipt_fingerprint": self.receipt_fingerprint,
            "security_verification_status": self.security_verification_status,
        }
