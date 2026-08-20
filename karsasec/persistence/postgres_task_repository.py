"""PostgreSQL-backed Authoritative Task Repository for Sprint F5.

Provides atomic CAS task state transitions, persistent fencing version tracking,
and database-enforced state machine semantics adhering to INV-F5-01 and INV-F5-02.
"""

from __future__ import annotations

from typing import List, Optional, Any
from sqlalchemy import update, select
from sqlalchemy.orm import Session

from karsasec.persistence.db import DatabaseSessionFactory, get_session_factory
from karsasec.persistence.models import TaskModel
from karsasec.workers.repository import TaskRepository
from karsasec.workers.task import (
    RemediationTask,
    TaskState,
    StaleLeaseVersionError,
    InvalidTaskStateError,
)


class PostgresTaskRepository(TaskRepository):
    """Authoritative PostgreSQL Task Repository enforcing atomic CAS & fencing version invariants."""

    def __init__(self, session_factory: DatabaseSessionFactory | None = None) -> None:
        self._session_factory = session_factory or get_session_factory()

    def _model_to_domain(self, model: TaskModel) -> RemediationTask:
        """Map TaskModel ORM object to domain RemediationTask."""
        state = TaskState(model.state)
        task = RemediationTask(
            task_id=model.task_id,
            finding_id=model.finding_id,
            approval_token_id=model.approval_token_id,
            token="",  # Token is not persisted for privacy
            fingerprint=model.fingerprint,
            state=state,
            attempts=model.attempts,
            max_attempts=model.max_attempts,
            lease_seconds=model.lease_seconds,
        )
        task.lease_version = model.lease_version
        task.error_message = model.error_message
        task.receipt_id = model.receipt_id
        task.receipt_fingerprint = model.receipt_fingerprint
        task.security_verification_status = model.security_verification_status
        return task

    def create_task(self, task: RemediationTask) -> None:
        """Saves a new task to PostgreSQL persistence."""
        with self._session_factory.session_scope() as session:
            existing = session.scalar(select(TaskModel).where(TaskModel.task_id == task.task_id))
            if existing:
                raise ValueError(f"Task with ID {task.task_id} already exists")

            model = TaskModel(
                task_id=task.task_id,
                finding_id=task.finding_id,
                approval_token_id=task.approval_token_id,
                fingerprint=task.fingerprint,
                state=task.state.value if isinstance(task.state, TaskState) else str(task.state),
                attempts=task.attempts,
                max_attempts=task.max_attempts,
                lease_seconds=task.lease_seconds,
                lease_version=task.lease_version,
                error_message=task.error_message,
                receipt_id=task.receipt_id,
                receipt_fingerprint=task.receipt_fingerprint,
                security_verification_status=task.security_verification_status,
            )
            session.add(model)

    def get_task(self, task_id: str) -> Optional[RemediationTask]:
        """Retrieves a task by ID from PostgreSQL."""
        session = self._session_factory.get_session()
        try:
            model = session.scalar(select(TaskModel).where(TaskModel.task_id == task_id))
            if not model:
                return None
            return self._model_to_domain(model)
        finally:
            session.close()

    def update_task(self, task_id: str, **kwargs) -> RemediationTask:
        """Updates task fields atomically in PostgreSQL."""
        if "state" in kwargs:
            new_state = kwargs.pop("state")
            new_state_obj = TaskState(new_state) if isinstance(new_state, str) else new_state
            current = self.get_task(task_id)
            if not current:
                raise ValueError(f"Task with ID {task_id} not found")
            return self.atomic_transition(
                task_id=task_id,
                expected_lease_version=current.lease_version,
                expected_states=[current.state],
                new_state=new_state_obj,
                **kwargs,
            )

        with self._session_factory.session_scope() as session:
            model = session.scalar(select(TaskModel).where(TaskModel.task_id == task_id).with_for_update())
            if not model:
                raise ValueError(f"Task with ID {task_id} not found")

            for key, val in kwargs.items():
                if hasattr(model, key):
                    setattr(model, key, val)
                else:
                    raise AttributeError(f"TaskModel has no attribute '{key}'")
            session.flush()
            return self._model_to_domain(model)

    def atomic_transition(
        self,
        task_id: str,
        expected_lease_version: int,
        expected_states: List[TaskState],
        new_state: TaskState,
        **kwargs,
    ) -> RemediationTask:
        """Atomically validates lease_version & state via single SQL UPDATE statement (INV-F5-02).

        SQL Equivalent:
            UPDATE tasks SET state = :new_state, lease_version = :next_version ...
            WHERE task_id = :task_id AND lease_version = :expected_version AND state IN (:expected_states)
        """
        expected_state_strs = [
            s.value if isinstance(s, TaskState) else str(s) for s in expected_states
        ]
        target_state_str = new_state.value if isinstance(new_state, TaskState) else str(new_state)

        next_lease_version = kwargs.get("lease_version", expected_lease_version + 1)

        # Terminal state resurrection check (INV-F5-08)
        terminal_states = {TaskState.COMPLETED.value, TaskState.FAILED.value, TaskState.CANCELLED.value}
        if target_state_str in {TaskState.QUEUED.value, TaskState.RUNNING.value}:
            if any(s in terminal_states for s in expected_state_strs):
                raise InvalidTaskStateError(
                    f"Terminal state task '{task_id}' cannot be resurrected to '{target_state_str}'."
                )

        update_values: dict[str, Any] = {
            "state": target_state_str,
            "lease_version": next_lease_version,
        }

        if "error_message" in kwargs:
            update_values["error_message"] = kwargs["error_message"]
        if "assigned_worker_id" in kwargs:
            update_values["assigned_worker_id"] = kwargs["assigned_worker_id"]
        if "recovery_fencing_token" in kwargs:
            update_values["recovery_fencing_token"] = kwargs["recovery_fencing_token"]
        if target_state_str == TaskState.RUNNING.value:
            # Increment attempts on transition to RUNNING
            update_values["attempts"] = TaskModel.attempts + 1

        with self._session_factory.session_scope() as session:
            stmt = (
                update(TaskModel)
                .where(
                    TaskModel.task_id == task_id,
                    TaskModel.lease_version == expected_lease_version,
                    TaskModel.state.in_(expected_state_strs),
                )
                .values(**update_values)
            )

            result = session.execute(stmt)
            if getattr(result, "rowcount", 0) == 1:
                session.flush()
                model = session.scalar(select(TaskModel).where(TaskModel.task_id == task_id))
                if not model:
                    raise ValueError(f"Task with ID '{task_id}' not found after update")
                return self._model_to_domain(model)

            # Zero rows updated — analyze cause for authoritative domain exception
            current_model = session.scalar(select(TaskModel).where(TaskModel.task_id == task_id))
            if not current_model:
                raise ValueError(f"Task with ID '{task_id}' not found")

            # Check terminal state resurrection guard
            if current_model.state in terminal_states:
                raise InvalidTaskStateError(
                    f"Terminal state task '{task_id}' (state='{current_model.state}') cannot be resurrected to '{target_state_str}'."
                )

            if current_model.lease_version != expected_lease_version:
                raise StaleLeaseVersionError(
                    f"Task fencing lease version mismatch for '{task_id}'. Expected v{expected_lease_version}, active is v{current_model.lease_version}."
                )

            if current_model.state not in expected_state_strs:
                raise InvalidTaskStateError(
                    f"Task state transition rejected for '{task_id}'. Current state '{current_model.state}' not in expected {expected_state_strs}."
                )

            raise InvalidTaskStateError(
                f"Atomic state transition failed for task '{task_id}'."
            )

    def get_active_task_by_fingerprint(self, fingerprint: str) -> Optional[RemediationTask]:
        """Finds any non-terminal task matching the fingerprint."""
        terminal_states = [
            TaskState.COMPLETED.value,
            TaskState.FAILED.value,
            TaskState.CANCELLED.value,
        ]
        session = self._session_factory.get_session()
        try:
            model = session.scalar(
                select(TaskModel).where(
                    TaskModel.fingerprint == fingerprint,
                    ~TaskModel.state.in_(terminal_states),
                )
            )
            if not model:
                return None
            return self._model_to_domain(model)
        finally:
            session.close()

    def list_tasks(
        self, states: Optional[list[TaskState]] = None, limit: int = 100
    ) -> list[RemediationTask]:
        """List tasks optionally filtered by state."""
        session = self._session_factory.get_session()
        try:
            query = select(TaskModel)
            if states:
                state_strs = [s.value if isinstance(s, TaskState) else str(s) for s in states]
                query = query.where(TaskModel.state.in_(state_strs))
            query = query.limit(limit)

            models = session.scalars(query).all()
            return [self._model_to_domain(m) for m in models]
        finally:
            session.close()
