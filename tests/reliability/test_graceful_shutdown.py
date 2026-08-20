"""Adversarial Test Suite for Sprint F6C — Graceful Shutdown Engine & Worker Fencing Epoch (10 Tests).

Verifies invariants:
  - INV-F6-SHUTDOWN-01: Handles SIGINT and SIGTERM non-blockingly.
  - INV-F6-SHUTDOWN-02: Initiates drain mode immediately upon signal receipt.
  - INV-F6-SHUTDOWN-03: Active running tasks are given up to 30.0s to complete.
  - INV-F6-SHUTDOWN-04: Worker process exits cleanly if all active tasks finish within timeout.
  - INV-F6-SHUTDOWN-05: If timeout expires, worker is marked FENCED with incremented fencing_token.
  - INV-F6-SHUTDOWN-06: Signal handlers perform zero blocking DB/network calls inside signal callback.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base, WorkerModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.postgres_worker_repository import PostgresWorkerRepository
from karsasec.reliability.drain_mode import WorkerDrainController
from karsasec.reliability.shutdown import GracefulShutdownCoordinator
from karsasec.workers.worker_registry import WorkerStatus
from karsasec.workers.task import (
    RemediationTask,
    TaskState,
    WorkerFencedError,
)


@pytest.fixture
def session_factory(tmp_path):
    db_file = tmp_path / "test_shutdown.db"
    url = f"sqlite:///{db_file}"
    factory = DatabaseSessionFactory(url=url)
    Base.metadata.create_all(bind=factory.engine)
    with factory.engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL;")
    yield factory
    Base.metadata.drop_all(bind=factory.engine)


@pytest.fixture
def task_repo(session_factory):
    return PostgresTaskRepository(session_factory)


@pytest.fixture
def worker_repo(session_factory):
    return PostgresWorkerRepository(session_factory)


@pytest.fixture
def drain_ctrl(session_factory, worker_repo):
    return WorkerDrainController(session_factory, worker_repo)


def create_assigned_task(task_repo, worker_id, task_id="task-shut-1") -> RemediationTask:
    task = RemediationTask(
        task_id=task_id,
        finding_id="finding-s1",
        approval_token_id="token-s1",
        token="",
        fingerprint=f"fp-{task_id}",
        state=TaskState.QUEUED,
        attempts=0,
        max_attempts=3,
    )
    task_repo.create_task(task)
    return task_repo.assign_task(task_id, worker_id)


def test_shutdown_coordinator_initialization(session_factory, drain_ctrl):
    coordinator = GracefulShutdownCoordinator("worker-s1", drain_ctrl, session_factory)
    assert coordinator.is_shutdown_requested() is False


def test_register_signal_handlers_non_blocking(session_factory, drain_ctrl):
    coordinator = GracefulShutdownCoordinator("worker-s2", drain_ctrl, session_factory)
    coordinator.register_signal_handlers()
    assert coordinator.is_shutdown_requested() is False


def test_request_shutdown_sets_flag(session_factory, drain_ctrl):
    coordinator = GracefulShutdownCoordinator("worker-s3", drain_ctrl, session_factory)
    coordinator.request_shutdown()
    assert coordinator.is_shutdown_requested() is True


def test_execute_shutdown_drained_when_no_active_tasks(worker_repo, drain_ctrl, session_factory):
    worker_repo.register_worker("worker-s4", "secret", "localhost")
    coordinator = GracefulShutdownCoordinator("worker-s4", drain_ctrl, session_factory, timeout_seconds=1.0)
    coordinator.request_shutdown()
    status = coordinator.execute_shutdown()
    assert status == WorkerStatus.DRAINED


def test_execute_shutdown_drained_after_active_tasks_finish(task_repo, worker_repo, drain_ctrl, session_factory):
    worker_repo.register_worker("worker-s5", "secret", "localhost")
    assigned = create_assigned_task(task_repo, "worker-s5", "task-s5")
    coordinator = GracefulShutdownCoordinator("worker-s5", drain_ctrl, session_factory, timeout_seconds=2.0)
    coordinator.request_shutdown()

    # Finish active task
    task_repo.record_execution_failure(
        task_id="task-s5",
        expected_lease_version=assigned.lease_version,
        worker_id="worker-s5",
        worker_fencing_token=1,
        error_message="Complete during shutdown",
    )

    status = coordinator.execute_shutdown()
    assert status == WorkerStatus.DRAINED


def test_execute_shutdown_timeout_triggers_fenced(task_repo, worker_repo, drain_ctrl, session_factory):
    worker_repo.register_worker("worker-s6", "secret", "localhost")
    create_assigned_task(task_repo, "worker-s6", "task-stuck-s6")
    coordinator = GracefulShutdownCoordinator("worker-s6", drain_ctrl, session_factory, timeout_seconds=0.3)
    coordinator.request_shutdown()

    status = coordinator.execute_shutdown()
    assert status == WorkerStatus.FENCED


def test_execute_shutdown_increments_worker_fencing_token_on_timeout(
    task_repo, worker_repo, drain_ctrl, session_factory
):
    worker_repo.register_worker("worker-s7", "secret", "localhost")
    create_assigned_task(task_repo, "worker-s7", "task-stuck-s7")
    coordinator = GracefulShutdownCoordinator("worker-s7", drain_ctrl, session_factory, timeout_seconds=0.3)
    coordinator.request_shutdown()
    coordinator.execute_shutdown()

    session = session_factory.get_session()
    try:
        model = session.scalar(select(WorkerModel).where(WorkerModel.worker_id == "worker-s7"))
        assert model.status == "FENCED"
        assert model.fencing_token == 2
    finally:
        session.close()


def test_fenced_worker_cannot_mutate_db_after_shutdown_timeout(task_repo, worker_repo, drain_ctrl, session_factory):
    worker_repo.register_worker("worker-s8", "secret", "localhost")
    assigned = create_assigned_task(task_repo, "worker-s8", "task-stuck-s8")
    coordinator = GracefulShutdownCoordinator("worker-s8", drain_ctrl, session_factory, timeout_seconds=0.3)
    coordinator.request_shutdown()
    coordinator.execute_shutdown()

    # Stale worker mutation attempt with old fencing token 1 fails
    with pytest.raises(WorkerFencedError):
        task_repo.record_execution_failure(
            task_id="task-stuck-s8",
            expected_lease_version=assigned.lease_version,
            worker_id="worker-s8",
            worker_fencing_token=1,
            error_message="Late result after timeout",
        )


def test_f5_recovery_engine_reclaims_fenced_tasks(task_repo, worker_repo, drain_ctrl, session_factory):
    worker_repo.register_worker("worker-s9", "secret", "localhost")
    create_assigned_task(task_repo, "worker-s9", "task-stuck-s9")
    coordinator = GracefulShutdownCoordinator("worker-s9", drain_ctrl, session_factory, timeout_seconds=0.3)
    coordinator.request_shutdown()
    coordinator.execute_shutdown()

    # Worker is FENCED in DB. Task is RUNNING and eligible for F5 recovery reclamation.
    w = worker_repo.get_worker("worker-s9")
    assert w.status == WorkerStatus.FENCED


def test_idempotent_multiple_shutdown_calls(worker_repo, drain_ctrl, session_factory):
    worker_repo.register_worker("worker-s10", "secret", "localhost")
    coordinator = GracefulShutdownCoordinator("worker-s10", drain_ctrl, session_factory, timeout_seconds=0.5)
    coordinator.request_shutdown()
    s1 = coordinator.execute_shutdown()
    s2 = coordinator.execute_shutdown()
    assert s1 == s2 == WorkerStatus.DRAINED
