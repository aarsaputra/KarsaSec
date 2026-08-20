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

from datetime import datetime, UTC


from karsasec.persistence.models import TaskModel
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
