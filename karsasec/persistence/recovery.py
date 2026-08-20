"""Startup Recovery Engine for KarsaSec Sprint F3.

Runs at application startup to recover tasks that were in RUNNING state
when the process was interrupted (crash, restart, SIGKILL).

Algorithm (O(n) where n = number of active tasks):
  FOR each task:
    IF state == RUNNING AND now - lease_started_at > lease_timeout:
      state = QUEUED
      enqueue(task_id)
      audit(TASK_RECOVERED)
"""

from __future__ import annotations

import time
from datetime import datetime, UTC, timedelta
from typing import TYPE_CHECKING

from karsasec.persistence.audit_repository import AuditEvent, AuditEventType
from karsasec.persistence.task_repository import PostgresTaskRepository
from karsasec.workers.task import TaskState
from karsasec.workers.queue import TaskQueue

if TYPE_CHECKING:
    from karsasec.persistence.audit_repository import AuditRepository


class StartupRecoveryEngine:
    """Recovers stale RUNNING tasks at process startup.

    Uses wall-clock lease times stored in PostgreSQL to detect expired leases.
    This is the complement to CustomWorkerRuntime.recover_stale_tasks() which
    uses monotonic time for in-process detection; this class handles cross-restart
    recovery using persistent timestamps.
    """

    def __init__(
        self,
        task_repository: PostgresTaskRepository,
        queue: TaskQueue,
        audit_repository: "AuditRepository | None" = None,
        lease_timeout_seconds: int = 300,
    ) -> None:
        self._repo = task_repository
        self._queue = queue
        self._audit = audit_repository
        self._lease_timeout = lease_timeout_seconds

    def recover_running_tasks(self) -> list[str]:
        """Scan for expired RUNNING tasks and requeue them.

        Returns the list of task_ids that were recovered.
        """
        recovered_ids: list[str] = []

        expired_tasks = self._repo.find_expired_running_tasks(
            lease_timeout_seconds=self._lease_timeout
        )

        for task in expired_tasks:
            task_id = task.task_id
            try:
                if task.attempts < task.max_attempts:
                    # RUNNING → FAILED_RETRYABLE → QUEUED
                    self._repo.update_task(
                        task_id,
                        state=TaskState.FAILED_RETRYABLE,
                        error_message="Recovered: lease expired at startup",
                    )
                    self._repo.update_task(task_id, state=TaskState.QUEUED)
                    self._queue.enqueue(task_id)
                    recovered_ids.append(task_id)

                    if self._audit:
                        self._audit.append(AuditEvent(
                            task_id=task_id,
                            event_type=AuditEventType.TASK_RECOVERED,
                            details={
                                "reason": "lease_expired_at_startup",
                                "attempts": task.attempts,
                                "max_attempts": task.max_attempts,
                            },
                        ))
                else:
                    # Max retries exhausted → mark FAILED permanently
                    self._repo.update_task(
                        task_id,
                        state=TaskState.FAILED,
                        error_message="Lease expired at startup; max attempts exhausted",
                    )

                    if self._audit:
                        self._audit.append(AuditEvent(
                            task_id=task_id,
                            event_type=AuditEventType.TASK_FAILED,
                            details={
                                "reason": "lease_expired_at_startup_max_retries",
                                "attempts": task.attempts,
                            },
                        ))

            except Exception as exc:
                # Log but do not raise — recovery must be best-effort
                import logging
                logging.getLogger(__name__).error(
                    "Recovery failed for task %s: %s", task_id, exc
                )

        return recovered_ids
