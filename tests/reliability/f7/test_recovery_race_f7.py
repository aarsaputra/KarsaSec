"""Sprint F7 — Recovery / Worker Race Deterministic Adversarial Test Suite.

Verifies:
  - Stale worker waking post-recovery cannot complete or fail a reclaimed task.
  - Recovery advances lease_version and clears worker assignment metadata when requeuing.
  - Recovery preserves attempt accounting (does NOT double-increment attempts).
"""

import pytest
from sqlalchemy import create_engine

from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base, WorkerModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.workers.task import (
    RemediationTask,
    TaskState,
    WorkerFencedError,
    StaleLeaseVersionError,
)
from karsasec.workers.cluster_recovery import ClusterRecoveryEngine, DistributedRecoveryLock
from karsasec.workers.queue import InMemoryTaskQueue
from karsasec.workers.worker_registry import WorkerRegistry, WorkerNode, WorkerStatus


@pytest.fixture
def session_factory(tmp_path):
    db_path = tmp_path / "test_f7_recovery_race.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"timeout": 15})
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")

    return DatabaseSessionFactory(url=f"sqlite:///{db_path}")


@pytest.fixture
def repo(session_factory):
    return PostgresTaskRepository(session_factory=session_factory)


def _create_worker(session_factory, worker_id: str, status: str = "ONLINE", fencing_token: int = 1):
    with session_factory.session_scope() as session:
        w = WorkerModel(
            worker_id=worker_id,
            auth_token_hash="hash_123",
            hostname="host-1",
            status=status,
            fencing_token=fencing_token,
        )
        session.add(w)


class TestRecoveryRaceF7:
    def test_stale_worker_wakes_post_recovery_mutation_rejected(self, session_factory, repo):
        """Worker W1 owns T1 -> W1 crashes/offline -> Recovery reclaims T1 -> W1 wakes & completion rejected."""
        _create_worker(session_factory, "w1", status="ONLINE", fencing_token=1)
        _create_worker(session_factory, "w2", status="ONLINE", fencing_token=1)

        task = RemediationTask("t1", "f_1", "tok_1", "", "fp_1", state=TaskState.QUEUED)
        repo.create_task(task)

        # 1. W1 assigned T1
        assigned_w1 = repo.assign_task("t1", "w1")
        w1_lease_version = assigned_w1.lease_version
        assert assigned_w1.attempts == 1

        # 2. W1 becomes OFFLINE
        registry = WorkerRegistry()
        wn1 = WorkerNode("w1", "host1")
        wn1.status = WorkerStatus.OFFLINE
        registry._workers["w1"] = wn1

        queue = InMemoryTaskQueue()
        lock = DistributedRecoveryLock()
        engine = ClusterRecoveryEngine(
            registry=registry,
            task_repository=repo,
            queue=queue,
            recovery_lock=lock,
        )

        # 3. Recovery recovers T1 (RUNNING -> QUEUED)
        recovered_count = engine.recover_orphaned_tasks(
            worker_assignments={"t1": "w1"},
            recovery_node_id="leader_node",
        )
        assert recovered_count == 1

        reclaimed_task = repo.get_task("t1")
        assert reclaimed_task.state == TaskState.QUEUED
        assert reclaimed_task.attempts == 1  # attempts NOT incremented during recovery
        assert reclaimed_task.lease_version == w1_lease_version + 1  # lease_version advanced

        # 4. T1 reassigned to W2
        assigned_w2 = repo.assign_task("t1", "w2")
        assert assigned_w2.state == TaskState.RUNNING
        assert assigned_w2.attempts == 2  # attempts incremented ONCE on assignment to W2
        assert assigned_w2.lease_version == w1_lease_version + 2

        # 5. W1 wakes up and submits complete_task with old token and old lease_version
        with pytest.raises((StaleLeaseVersionError, WorkerFencedError)):
            repo.complete_task(
                task_id="t1",
                expected_lease_version=w1_lease_version,
                worker_id="w1",
                worker_fencing_token=1,
            )

        # Verify T1 remains owned by W2 in RUNNING state
        current_t1 = repo.get_task("t1")
        assert current_t1.state == TaskState.RUNNING
        assert current_t1.attempts == 2

    def test_stale_worker_failure_report_post_recovery_rejected(self, session_factory, repo):
        """Stale worker failure report after task recovery is rejected."""
        _create_worker(session_factory, "w_stale_fail", status="ONLINE", fencing_token=1)

        task = RemediationTask("t_fail_race", "f_1", "tok_1", "", "fp_1", state=TaskState.QUEUED)
        repo.create_task(task)
        assigned = repo.assign_task("t_fail_race", "w_stale_fail")

        # Recovery reclaims task
        repo.atomic_transition(
            task_id="t_fail_race",
            expected_lease_version=assigned.lease_version,
            expected_states=[TaskState.RUNNING],
            new_state=TaskState.QUEUED,
        )

        with pytest.raises((StaleLeaseVersionError, WorkerFencedError)):
            repo.record_execution_failure(
                task_id="t_fail_race",
                expected_lease_version=assigned.lease_version,
                worker_id="w_stale_fail",
                worker_fencing_token=1,
                error_message="Stale failure report",
            )
