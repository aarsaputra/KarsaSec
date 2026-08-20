"""Task Repository Interface and In-Memory Implementation for Sprint F2.

Provides persistence of task state separated from Redis queue transport.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod

from karsasec.workers.task import (
    RemediationTask,
    TaskState,
    StaleLeaseVersionError,
    InvalidTaskStateError,
)


class TaskRepository(ABC):
    """Abstract Base Class for Task storage."""

    @abstractmethod
    def create_task(self, task: RemediationTask) -> None:
        """Saves a new task to persistence."""
        pass

    @abstractmethod
    def get_task(self, task_id: str) -> RemediationTask | None:
        """Retrieves a task by ID."""
        pass

    @abstractmethod
    def update_task(self, task_id: str, **kwargs) -> RemediationTask:
        """Updates task fields atomically."""
        pass

    @abstractmethod
    def atomic_transition(
        self,
        task_id: str,
        expected_lease_version: int,
        expected_states: list[TaskState],
        new_state: TaskState,
        **kwargs,
    ) -> RemediationTask:
        """Atomically validates lease version and expected state before executing transition.

        Prevents TOCTOU races between task lease validation and state mutation.
        In SQL persistence (Sprint F5), this maps to conditional execution:
          UPDATE remediation_tasks SET state = ?, ...
          WHERE task_id = ? AND lease_version = ? AND state IN (...);
        returning rowcount == 1 as proof of authoritative commit.
        """
        pass

    @abstractmethod
    def get_active_task_by_fingerprint(self, fingerprint: str) -> RemediationTask | None:
        """Finds any non-terminal task matching the request fingerprint."""
        pass

    @abstractmethod
    def list_tasks(self, states: list[TaskState] | None = None, limit: int = 100) -> list[RemediationTask]:
        """List tasks optionally filtered by state."""
        pass

    @abstractmethod
    def assign_task(self, task_id: str, worker_id: str) -> RemediationTask:
        """Assigns a task to a worker and transitions state to RUNNING."""
        pass

    @abstractmethod
    def complete_task(
        self,
        task_id: str,
        expected_lease_version: int,
        worker_id: str,
        worker_fencing_token: int = 1,
        receipt_id: str | None = None,
        receipt_fingerprint: str | None = None,
        security_verification_status: str | None = None,
    ) -> RemediationTask:
        """Completes a task atomically and transitions state to COMPLETED."""
        pass

    @abstractmethod
    def record_execution_failure(
        self,
        task_id: str,
        expected_lease_version: int,
        worker_id: str,
        worker_fencing_token: int = 1,
        error_message: str = "",
    ) -> RemediationTask:
        """Records execution failure, re-queuing or transitioning to FAILED if max_attempts reached."""
        pass


class InMemoryTaskRepository(TaskRepository):
    """Process-local thread-safe in-memory task repository.

    Note: `threading.Lock()` provides process-local synchronization for single-process node.
    In multi-node distributed deployments (Sprint F5), PostgreSQL conditional update transactions
    act as the distributed authority.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, RemediationTask] = {}
        self._lock = threading.Lock()

    def create_task(self, task: RemediationTask) -> None:
        with self._lock:
            if task.task_id in self._tasks:
                raise ValueError(f"Task with ID {task.task_id} already exists")
            self._tasks[task.task_id] = task

    def get_task(self, task_id: str) -> RemediationTask | None:
        with self._lock:
            return self._tasks.get(task_id)

    def update_task(self, task_id: str, **kwargs) -> RemediationTask:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                raise ValueError(f"Task with ID {task_id} not found")

            for key, val in kwargs.items():
                if key == "state":
                    task.transition_to(val)
                elif hasattr(task, key):
                    setattr(task, key, val)
                else:
                    raise AttributeError(f"RemediationTask has no attribute '{key}'")
            return task

    def atomic_transition(
        self,
        task_id: str,
        expected_lease_version: int,
        expected_states: list[TaskState],
        new_state: TaskState,
        **kwargs,
    ) -> RemediationTask:
        """Atomically validates lease version & expected states under lock before mutating task."""
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                raise ValueError(f"Task with ID {task_id} not found")

            # INV-04: Validate fencing lease version
            if task.lease_version != expected_lease_version:
                raise StaleLeaseVersionError(
                    f"Task fencing lease version mismatch for '{task_id}'. Expected v{expected_lease_version}, active is v{task.lease_version}."
                )

            # INV-04: Validate expected current state
            if task.state not in expected_states:
                raise InvalidTaskStateError(
                    f"Task state transition rejected for '{task_id}'. Current state '{task.state}' not in expected {expected_states}."
                )

            # Execute state transition
            task.transition_to(new_state)

            for key, val in kwargs.items():
                if key == "state":
                    continue
                elif hasattr(task, key):
                    setattr(task, key, val)
                else:
                    raise AttributeError(f"RemediationTask has no attribute '{key}'")

            return task

    def get_active_task_by_fingerprint(self, fingerprint: str) -> RemediationTask | None:
        with self._lock:
            terminal_states = {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED}
            for task in self._tasks.values():
                if task.fingerprint == fingerprint and task.state not in terminal_states:
                    return task
            return None

    def list_tasks(self, states: list[TaskState] | None = None, limit: int = 100) -> list[RemediationTask]:
        with self._lock:
            res = []
            for task in self._tasks.values():
                if states is None or task.state in states:
                    res.append(task)
                if len(res) >= limit:
                    break
            return res

    def assign_task(self, task_id: str, worker_id: str) -> RemediationTask:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                raise ValueError(f"Task with ID {task_id} not found")
            if task.state in {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED}:
                raise InvalidTaskStateError("Terminal state task cannot be assigned.")
            if task.attempts >= task.max_attempts:
                raise InvalidTaskStateError(f"Task '{task_id}' attempts exhausted.")
            if task.state not in {TaskState.QUEUED, TaskState.PENDING}:
                raise InvalidTaskStateError(f"Task '{task_id}' is in state '{task.state}', expected QUEUED.")
            task.transition_to(TaskState.RUNNING)
            task.increment_lease_version()
            return task

    def complete_task(
        self,
        task_id: str,
        expected_lease_version: int,
        worker_id: str,
        worker_fencing_token: int = 1,
        receipt_id: str | None = None,
        receipt_fingerprint: str | None = None,
        security_verification_status: str | None = None,
    ) -> RemediationTask:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                raise ValueError(f"Task with ID {task_id} not found")
            if task.lease_version != expected_lease_version:
                raise StaleLeaseVersionError(
                    f"Task fencing lease version mismatch for '{task_id}'. Expected v{expected_lease_version}, active is v{task.lease_version}."
                )
            if task.state != TaskState.RUNNING:
                raise InvalidTaskStateError(f"Task state '{task.state}' cannot be completed")
            task.transition_to(TaskState.COMPLETED)
            task.increment_lease_version()
            if receipt_id:
                task.receipt_id = receipt_id
            if receipt_fingerprint:
                task.receipt_fingerprint = receipt_fingerprint
            if security_verification_status:
                task.security_verification_status = security_verification_status
            return task

    def record_execution_failure(
        self,
        task_id: str,
        expected_lease_version: int,
        worker_id: str,
        worker_fencing_token: int = 1,
        error_message: str = "",
    ) -> RemediationTask:
        with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                raise ValueError(f"Task with ID {task_id} not found")
            if task.lease_version != expected_lease_version:
                raise StaleLeaseVersionError(
                    f"Task fencing lease version mismatch for '{task_id}'. Expected v{expected_lease_version}, active is v{task.lease_version}."
                )
            if task.state != TaskState.RUNNING:
                raise InvalidTaskStateError(f"Task state '{task.state}' cannot be recorded as failure.")
            task.error_message = error_message
            if task.attempts >= task.max_attempts:
                task.transition_to(TaskState.FAILED)
            else:
                task.transition_to(TaskState.QUEUED)
            task.increment_lease_version()
            return task
