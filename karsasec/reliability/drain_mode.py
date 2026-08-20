"""Worker Drain Mode & Lock Serialization Engine for Sprint F6C.

Invariants:
  - INV-F6-DRAIN-01: Worker state machine ONLINE -> DRAINING -> DRAINED -> FENCED -> OFFLINE is authoritative in PostgreSQL.
  - INV-F6-DRAIN-02: DRAINING worker rejects new task assignments (NewAssignmentAuthority).
  - INV-F6-DRAIN-03: DRAINING worker retains authority to complete/fail active RUNNING tasks (TaskMutationAuthority).
  - INV-F6-DRAIN-04: Transiting to DRAINED requires DB verification that 0 RUNNING tasks remain.
  - INV-F6-LOCK-01: Global lock ordering: Worker Row FOR UPDATE FIRST -> Task Row SECOND.
"""

from __future__ import annotations

import time

from karsasec.persistence.db import DatabaseSessionFactory, get_session_factory
from karsasec.persistence.postgres_worker_repository import PostgresWorkerRepository
from karsasec.workers.worker_registry import WorkerStatus
from karsasec.observability.logger import default_logger


class WorkerDrainController:
    """Controls worker drain mode state transitions in PostgreSQL."""

    def __init__(
        self,
        session_factory: DatabaseSessionFactory | None = None,
        worker_repo: PostgresWorkerRepository | None = None,
    ) -> None:
        self._session_factory = session_factory or get_session_factory()
        self._worker_repo = worker_repo or PostgresWorkerRepository(self._session_factory)

    def initiate_drain(self, worker_id: str) -> None:
        """Transition worker from ONLINE to DRAINING in PostgreSQL under Worker Row lock."""
        self._worker_repo.mark_draining(worker_id)
        default_logger.info(
            "WORKER_DRAIN_INITIATED",
            f"Worker '{worker_id}' entered DRAINING mode.",
            component="drain_controller",
            worker_id=worker_id,
        )

    def check_drain_completed(self, worker_id: str) -> bool:
        """Check if worker active tasks reached zero and attempt transition to DRAINED."""
        return self._worker_repo.mark_drained(worker_id)

    def force_fence(self, worker_id: str) -> None:
        """Force fence worker on drain timeout (DRAINING -> FENCED). Increment worker fencing_token."""
        self._worker_repo.mark_fenced(worker_id)
        default_logger.warning(
            "WORKER_FENCED_ON_TIMEOUT",
            f"Worker '{worker_id}' fenced due to drain timeout.",
            component="drain_controller",
            worker_id=worker_id,
        )

    def wait_for_drain(self, worker_id: str, timeout_seconds: float = 30.0, poll_interval: float = 0.5) -> WorkerStatus:
        """Poll PostgreSQL until worker transitions to DRAINED or timeout triggers FENCED.

        If timeout is exceeded, worker status is set to FENCED in DB and fencing_token is incremented.
        """
        self.initiate_drain(worker_id)

        start_time = time.monotonic()
        while time.monotonic() - start_time < timeout_seconds:
            if self.check_drain_completed(worker_id):
                default_logger.info(
                    "WORKER_DRAIN_COMPLETED",
                    f"Worker '{worker_id}' successfully DRAINED.",
                    component="drain_controller",
                    worker_id=worker_id,
                )
                return WorkerStatus.DRAINED

            time.sleep(poll_interval)

        # Timeout reached — force fencing epoch increment
        self.force_fence(worker_id)
        return WorkerStatus.FENCED
