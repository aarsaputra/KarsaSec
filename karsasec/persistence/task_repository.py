"""PostgresTaskRepository — Production implementation of TaskRepository for Sprint F3.

Implements the TaskRepository contract using SQLAlchemy 2.x + PostgreSQL.

Invariants:
  - L7: security_verification_status is never set by this layer — only stored from
    upstream RTPValidator output.
  - Determinism: list_tasks() uses deterministic ORDER BY to avoid insertion-order flakiness.
  - Privacy: token field is intentionally not stored. Only metadata is persisted.
  - Transactions: all writes are atomic within a single session scope.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, UTC
from typing import Generator, List, Optional

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from karsasec.persistence.db import DatabaseSessionFactory, get_session_factory
from karsasec.persistence.models import TaskModel
from karsasec.workers.repository import TaskRepository
from karsasec.workers.task import RemediationTask, TaskState


def _model_to_domain(model: TaskModel) -> RemediationTask:
    """Map a TaskModel ORM row back to a domain RemediationTask."""
    task = RemediationTask(
        task_id=model.task_id,
        finding_id=model.finding_id,
        approval_token_id=model.approval_token_id,
        # token is not persisted — reconstruct as empty sentinel
        token="",
        fingerprint=model.fingerprint,
        state=TaskState(model.state),
        attempts=model.attempts,
        max_attempts=model.max_attempts,
        lease_seconds=model.lease_seconds,
    )
    task.error_message = model.error_message
    task.receipt_id = model.receipt_id
    task.receipt_fingerprint = model.receipt_fingerprint
    task.security_verification_status = model.security_verification_status
    # Reconstruct lease wall-clock time as monotonic approximation
    if model.lease_started_at is not None:
        import time
        # Approximation: offset from now
        elapsed = (datetime.now(UTC) - model.lease_started_at).total_seconds()
        task.started_at = time.monotonic() - elapsed
    return task


class PostgresTaskRepository(TaskRepository):
    """Production PostgreSQL implementation of the TaskRepository interface.

    One instance per application process; uses a shared DatabaseSessionFactory.
    """

    def __init__(self, factory: DatabaseSessionFactory | None = None) -> None:
        self._factory = factory or get_session_factory()

    @contextmanager
    def _session(self) -> Generator[Session, None, None]:
        yield from self._factory.session_scope()

    # ------------------------------------------------------------------
    # Write operations
    # ------------------------------------------------------------------

    def create_task(self, task: RemediationTask) -> None:
        """Persist a new task. Raises ValueError on duplicate task_id."""
        with self._session() as session:
            existing = session.scalar(
                select(TaskModel).where(TaskModel.task_id == task.task_id)
            )
            if existing:
                raise ValueError(f"Task '{task.task_id}' already exists.")
            model = TaskModel(
                task_id=task.task_id,
                finding_id=task.finding_id,
                approval_token_id=task.approval_token_id,
                # token is intentionally not persisted (R7-R9 privacy)
                fingerprint=task.fingerprint,
                state=str(task.state),
                attempts=task.attempts,
                max_attempts=task.max_attempts,
                lease_seconds=task.lease_seconds,
                error_message=task.error_message,
                receipt_id=task.receipt_id,
                receipt_fingerprint=task.receipt_fingerprint,
                security_verification_status=task.security_verification_status,
            )
            session.add(model)

    def update_task(self, task_id: str, **kwargs) -> RemediationTask:
        """Atomically update task fields. Handles state transitions via domain model."""
        with self._session() as session:
            model = session.scalar(
                select(TaskModel).where(TaskModel.task_id == task_id)
            )
            if not model:
                raise ValueError(f"Task '{task_id}' not found.")

            # Reconstruct domain object for state-transition validation
            domain_task = _model_to_domain(model)

            for key, val in kwargs.items():
                if key == "state":
                    domain_task.transition_to(val)
                    model.state = str(domain_task.state)
                    model.attempts = domain_task.attempts
                    # persist lease start time in wall-clock UTC
                    if domain_task.started_at is not None:
                        import time
                        elapsed = time.monotonic() - domain_task.started_at
                        model.lease_started_at = datetime(
                            *datetime.now(UTC).timetuple()[:6],
                            tzinfo=UTC,
                        )
                    else:
                        model.lease_started_at = None
                elif hasattr(model, key):
                    setattr(model, key, val)
                    # keep domain in sync for return value
                    setattr(domain_task, key, val)
                else:
                    raise AttributeError(f"TaskModel has no attribute '{key}'")

            model.updated_at = datetime.now(UTC)
            return domain_task

    # ------------------------------------------------------------------
    # Read operations
    # ------------------------------------------------------------------

    def get_task(self, task_id: str) -> Optional[RemediationTask]:
        with self._session() as session:
            model = session.scalar(
                select(TaskModel).where(TaskModel.task_id == task_id)
            )
            return _model_to_domain(model) if model else None

    def list_tasks(
        self,
        states: list[str] | None = None,
        limit: int = 100,
    ) -> List[RemediationTask]:
        """Deterministic listing of tasks, ordered by created_at, task_id."""
        with self._session() as session:
            stmt = select(TaskModel)
            if states:
                stmt = stmt.where(TaskModel.state.in_(states))
            stmt = stmt.order_by(TaskModel.created_at.asc(), TaskModel.task_id.asc()).limit(limit)
            rows = session.scalars(stmt).all()
            return [_model_to_domain(r) for r in rows]

    def get_active_task_by_fingerprint(self, fingerprint: str) -> Optional[RemediationTask]:
        """Find any non-terminal task matching a given request fingerprint (idempotency)."""
        terminal = {str(s) for s in (TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED)}
        with self._session() as session:
            model = session.scalar(
                select(TaskModel)
                .where(
                    TaskModel.fingerprint == fingerprint,
                    TaskModel.state.not_in(terminal),
                )
                .order_by(TaskModel.created_at.asc())
                .limit(1)
            )
            return _model_to_domain(model) if model else None

    def find_expired_running_tasks(self, lease_timeout_seconds: int = 300) -> List[RemediationTask]:
        """Return all RUNNING tasks whose wall-clock lease has expired.

        Used by StartupRecoveryEngine on service boot.
        """
        from sqlalchemy import text
        with self._session() as session:
            stmt = select(TaskModel).where(
                TaskModel.state == "RUNNING",
                TaskModel.lease_started_at.is_not(None),
                text(
                    f"EXTRACT(EPOCH FROM (NOW() - lease_started_at)) > {int(lease_timeout_seconds)}"
                ),
            )
            rows = session.scalars(stmt).all()
            return [_model_to_domain(r) for r in rows]
