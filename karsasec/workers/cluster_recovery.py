"""ClusterRecoveryEngine — Distributed Worker Dead-Node Task Recovery Engine (Sprint F4).

Detects RUNNING tasks assigned to dead/OFFLINE workers and safely requeues them.

Transition Rules:
  - RUNNING (assigned to OFFLINE worker) -> FAILED_RETRYABLE -> QUEUED  (if attempts < max_attempts)
  - RUNNING (assigned to OFFLINE worker) -> FAILED                       (if attempts >= max_attempts)

Forbidden Targets:
  - COMPLETED -> NEVER touched
  - FAILED    -> NEVER touched
  - CANCELLED -> NEVER touched

Complexity:
  Time Complexity  : O(n) where n is active running tasks
  Space Complexity : O(1)
"""

from __future__ import annotations

import time
import uuid
import threading
from typing import TYPE_CHECKING

from karsasec.workers.task import TaskState, StaleLeaseVersionError, InvalidTaskStateError
from karsasec.persistence.audit_repository import AuditEvent, AuditEventType, AuditRepository

if TYPE_CHECKING:
    from karsasec.workers.worker_registry import WorkerRegistry
    from karsasec.workers.repository import TaskRepository
    from karsasec.workers.queue import TaskQueue
    from karsasec.observability.metrics import MetricsCollector


class FencedLeaderError(Exception):
    """Raised when a recovery leader node attempts mutation after its lease expired or was superseded."""

    pass


class RecoveryLease:
    """Domain model tracking recovery leader lease and fencing token."""

    __slots__ = ("owner_id", "lease_id", "fencing_token", "acquired_at", "expires_at", "ttl_seconds")

    def __init__(
        self,
        owner_id: str,
        lease_id: str,
        fencing_token: int,
        acquired_at: float,
        ttl_seconds: float = 30.0,
    ) -> None:
        self.owner_id = owner_id
        self.lease_id = lease_id
        self.fencing_token = fencing_token
        self.acquired_at = acquired_at
        self.ttl_seconds = ttl_seconds
        self.expires_at = acquired_at + ttl_seconds

    def is_expired(self, current_time: float | None = None) -> bool:
        now = current_time if current_time is not None else time.time()
        return now >= self.expires_at


class DistributedRecoveryLock:
    """Distributed recovery lock with monotonic fencing tokens, TTL expiration, and lease ownership.

    PROCESS-LOCAL MONOTONICITY & PERSISTENCE BOUNDARY (INV-01):
    ----------------------------------------------------------
    - F4.1 Monotonicity: Fencing counter is monotonically increasing within process lifetime.
      Limitation: On process/node restart, `_fencing_counter` resets to initial value.
    - Distributed Production Model (Sprint F5): Monotonic fencing tokens across node restarts
      are deferred to Sprint F5 (using PostgreSQL atomic sequence or Redis `INCR`).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._current_lease: RecoveryLease | None = None
        self._fencing_counter: int = 0

    def acquire(self, owner_id: str, ttl_seconds: float = 30.0) -> RecoveryLease | None:
        """Attempt to acquire or re-acquire recovery lock for owner_id with strict monotonic fencing token."""
        with self._lock:
            now = time.time()
            if self._current_lease is not None and not self._current_lease.is_expired(now):
                if self._current_lease.owner_id != owner_id:
                    return None
                # Renewal for same owner
                self._current_lease.acquired_at = now
                self._current_lease.expires_at = now + ttl_seconds
                return self._current_lease

            # Expired or new acquisition -> generate strictly newer fencing token (INV-03)
            self._fencing_counter += 1
            lease_id = f"lease_{uuid.uuid4().hex[:12]}"
            lease = RecoveryLease(
                owner_id=owner_id,
                lease_id=lease_id,
                fencing_token=self._fencing_counter,
                acquired_at=now,
                ttl_seconds=ttl_seconds,
            )
            self._current_lease = lease
            return lease

    def renew(self, owner_id: str, lease_id: str, ttl_seconds: float = 30.0) -> bool:
        """Renew active lease if owner_id and lease_id match and lease is not expired."""
        with self._lock:
            now = time.time()
            if (
                self._current_lease is not None
                and self._current_lease.owner_id == owner_id
                and self._current_lease.lease_id == lease_id
                and not self._current_lease.is_expired(now)
            ):
                self._current_lease.acquired_at = now
                self._current_lease.expires_at = now + ttl_seconds
                return True
            return False

    def release(self, owner_id: str, lease_id: str | None = None) -> bool:
        """Release active recovery lease."""
        with self._lock:
            if self._current_lease is None:
                return True
            if self._current_lease.owner_id == owner_id:
                if lease_id is None or self._current_lease.lease_id == lease_id:
                    self._current_lease = None
                    return True
            return False

    def is_valid(
        self,
        owner_id: str,
        lease_id: str | None = None,
        fencing_token: int | None = None,
    ) -> bool:
        """Check if lock is validly held by owner_id and fencing_token."""
        with self._lock:
            now = time.time()
            if self._current_lease is None or self._current_lease.is_expired(now):
                return False
            if self._current_lease.owner_id != owner_id:
                return False
            if lease_id is not None and self._current_lease.lease_id != lease_id:
                return False
            if fencing_token is not None and self._current_lease.fencing_token != fencing_token:
                return False
            return True

    @property
    def current_lease(self) -> RecoveryLease | None:
        with self._lock:
            return self._current_lease


class ClusterRecoveryEngine:
    """Cluster-aware recovery engine targeting orphaned tasks owned by offline workers."""

    def __init__(
        self,
        registry: WorkerRegistry,
        task_repository: TaskRepository,
        queue: TaskQueue,
        metrics_collector: MetricsCollector | None = None,
        audit_repository: AuditRepository | None = None,
        recovery_lock: DistributedRecoveryLock | None = None,
    ) -> None:
        self._registry = registry
        self._repo = task_repository
        self._queue = queue
        self._metrics = metrics_collector
        self._audit = audit_repository
        self._lock = recovery_lock or DistributedRecoveryLock()

    def recover_orphaned_tasks(
        self,
        worker_assignments: dict[str, str] | None = None,
        recovery_node_id: str = "node_leader_1",
        existing_lease: RecoveryLease | None = None,
    ) -> int:
        """Scan running tasks and recover any task owned by an OFFLINE worker.

        Args:
            worker_assignments: Map of task_id -> worker_id.
            recovery_node_id: Identifier of node attempting recovery execution.
            existing_lease: Optional existing recovery lease handle for fencing validation testing.

        Returns:
            Number of tasks successfully recovered (or 0 if lock acquire failed / node fenced).
        """
        lease = existing_lease or self._lock.acquire(recovery_node_id)
        if not lease:
            # Recovery lock held by another active leader node — skip execution
            return 0

        try:
            from karsasec.workers.worker_registry import WorkerStatus

            offline_workers = {w.worker_id for w in self._registry.list_all() if w.status == WorkerStatus.OFFLINE}

            if not offline_workers:
                return 0

            # Fetch RUNNING tasks only
            running_tasks = self._repo.list_tasks(states=[TaskState.RUNNING])
            recovered_count = 0

            for task in running_tasks:
                # Check terminal state protection invariant
                if task.state in (TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELLED):
                    continue

                owner_id = (worker_assignments or {}).get(task.task_id)
                if owner_id and owner_id in offline_workers:
                    # INV-01 & INV-02: Check recovery lease fencing validity BEFORE mutation
                    if not self._lock.is_valid(recovery_node_id, lease.lease_id, lease.fencing_token):
                        raise FencedLeaderError(
                            f"Recovery leader '{recovery_node_id}' is fenced. Lease version expired or superseded during task recovery."
                        )

                    # Compute next lease version for fencing task commits
                    original_lease_version = task.lease_version
                    next_task_lease_version = task.lease_version + 1
                    target_state = TaskState.QUEUED if task.attempts < task.max_attempts else TaskState.FAILED
                    err_msg = (
                        f"Cluster recovery: worker '{owner_id}' offline. Fencing lease bump to v{next_task_lease_version}."
                        if target_state == TaskState.QUEUED
                        else f"Cluster recovery: max attempts reached while worker '{owner_id}' offline."
                    )

                    try:
                        # INV-04: Atomic state transition validating active task lease version
                        updated_task = self._repo.atomic_transition(
                            task_id=task.task_id,
                            expected_lease_version=original_lease_version,
                            expected_states=[TaskState.RUNNING],
                            new_state=target_state,
                            lease_version=next_task_lease_version,
                            error_message=err_msg,
                        )
                    except (StaleLeaseVersionError, InvalidTaskStateError):
                        # Task was already mutated by another actor or completed
                        continue

                    # Verify leader lock validity AGAIN before enqueuing to prevent double requeueing
                    if not self._lock.is_valid(recovery_node_id, lease.lease_id, lease.fencing_token):
                        # COMPENSATING ROLLBACK: Revert task state to RUNNING and restore previous lease version
                        # to prevent partial recovery corruption when recovery leader loses fencing lease.
                        try:
                            self._repo.atomic_transition(
                                task_id=task.task_id,
                                expected_lease_version=next_task_lease_version,
                                expected_states=[target_state],
                                new_state=TaskState.RUNNING,
                                lease_version=original_lease_version,
                                error_message="Recovery rollback: leader fenced post-mutation before enqueue.",
                            )
                        except (StaleLeaseVersionError, InvalidTaskStateError):
                            pass
                        raise FencedLeaderError(
                            f"Recovery leader '{recovery_node_id}' is fenced post-mutation. State rolled back."
                        )

                    if target_state == TaskState.QUEUED:
                        try:
                            self._queue.enqueue(task.task_id)
                        except Exception as eq_err:
                            # COMPENSATING ROLLBACK: Revert state to RUNNING if queue enqueue fails (e.g. backpressure overflow)
                            # to prevent queue/state desynchronization.
                            try:
                                self._repo.atomic_transition(
                                    task_id=task.task_id,
                                    expected_lease_version=next_task_lease_version,
                                    expected_states=[target_state],
                                    new_state=TaskState.RUNNING,
                                    lease_version=original_lease_version,
                                    error_message=f"Recovery rollback: queue enqueue failed ({eq_err}).",
                                )
                            except (StaleLeaseVersionError, InvalidTaskStateError):
                                pass
                            raise eq_err

                    recovered_count += 1

                    if self._metrics:
                        self._metrics.inc_recovery_count(1)

                    if self._audit:
                        self._audit.append(
                            AuditEvent(
                                task_id=task.task_id,
                                event_type=AuditEventType.TASK_FAILED,
                                details={
                                    "action": "cluster_recovery",
                                    "dead_worker_id": owner_id,
                                    "new_state": str(updated_task.state),
                                    "lease_version": updated_task.lease_version,
                                    "recovery_fencing_token": lease.fencing_token,
                                },
                            )
                        )

            return recovered_count
        finally:
            self._lock.release(recovery_node_id, lease.lease_id)
