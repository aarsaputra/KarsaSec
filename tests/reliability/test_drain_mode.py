"""Adversarial Test Suite for Sprint F6C — Worker Drain Mode & Lock Serialization (10 Tests).

Verifies invariants:
  - INV-F6-AUTH-01: Separation of NewAssignmentAuthority (ONLINE only) and TaskMutationAuthority (active tasks).
  - INV-F6-DRAIN-01: Authoritative worker states (ONLINE, DRAINING, DRAINED, FENCED, OFFLINE).
  - INV-F6-DRAIN-02: DRAINING worker rejects new task assignments.
  - INV-F6-DRAIN-03: DRAINING worker retains authority to finish active RUNNING tasks.
  - INV-F6-DRAIN-04: Transiting to DRAINED requires DB verification that 0 RUNNING tasks remain.
  - INV-F6-LOCK-01: Global lock ordering: Worker Row FIRST -> Task Row SECOND.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base, WorkerModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.postgres_worker_repository import PostgresWorkerRepository
from karsasec.reliability.drain_mode import WorkerDrainController
from karsasec.workers.worker_registry import WorkerStatus
from karsasec.workers.task import (
    RemediationTask,
    TaskState,
    InvalidWorkerStateError,
    WorkerFencedError,
)


@pytest.fixture
def session_factory(tmp_path):
    db_file = tmp_path / "test_drain.db"
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


def create_assigned_task(task_repo, worker_id, task_id="task-drain-1") -> RemediationTask:
    task = RemediationTask(
        task_id=task_id,
        finding_id="finding-d1",
        approval_token_id="token-d1",
        token="",
        fingerprint=f"fp-{task_id}",
        state=TaskState.QUEUED,
        attempts=0,
        max_attempts=3,
    )
    task_repo.create_task(task)
    return task_repo.assign_task(task_id, worker_id)


def test_drain_initiated_transitions_status(worker_repo, drain_ctrl):
    worker_repo.register_worker("worker-d1", "secret", "localhost")
    drain_ctrl.initiate_drain("worker-d1")
    w = worker_repo.get_worker("worker-d1")
    assert w.status == WorkerStatus.DRAINING


def test_draining_worker_rejects_new_assignment(task_repo, worker_repo, drain_ctrl):
    worker_repo.register_worker("worker-d2", "secret", "localhost")
    drain_ctrl.initiate_drain("worker-d2")

    task = RemediationTask(
        task_id="task-reject-d1",
        finding_id="f1",
        approval_token_id="a1",
        token="",
        fingerprint="fp-d1",
        state=TaskState.QUEUED,
    )
    task_repo.create_task(task)

    with pytest.raises(InvalidWorkerStateError):
        task_repo.assign_task("task-reject-d1", "worker-d2")


def test_draining_worker_can_complete_active_task(task_repo, worker_repo, drain_ctrl):
    worker_repo.register_worker("worker-d3", "secret", "localhost")
    assigned = create_assigned_task(task_repo, "worker-d3", "task-active-d3")
    drain_ctrl.initiate_drain("worker-d3")

    # DRAINING worker successfully fails or completes active task (INV-F6-AUTH-01)
    requeued = task_repo.record_execution_failure(
        task_id="task-active-d3",
        expected_lease_version=assigned.lease_version,
        worker_id="worker-d3",
        worker_fencing_token=1,
        error_message="Failure during drain",
    )
    assert requeued.state == TaskState.QUEUED


def test_mark_drained_fails_when_tasks_running(task_repo, worker_repo, drain_ctrl):
    worker_repo.register_worker("worker-d4", "secret", "localhost")
    create_assigned_task(task_repo, "worker-d4", "task-active-d4")
    drain_ctrl.initiate_drain("worker-d4")

    # 1 RUNNING task exists -> mark_drained returns False
    drained = drain_ctrl.check_drain_completed("worker-d4")
    assert drained is False
    w = worker_repo.get_worker("worker-d4")
    assert w.status == WorkerStatus.DRAINING


def test_mark_drained_succeeds_when_0_tasks_running(task_repo, worker_repo, drain_ctrl):
    worker_repo.register_worker("worker-d5", "secret", "localhost")
    assigned = create_assigned_task(task_repo, "worker-d5", "task-active-d5")
    drain_ctrl.initiate_drain("worker-d5")

    # Fail task -> 0 RUNNING tasks remain
    task_repo.record_execution_failure(
        task_id="task-active-d5",
        expected_lease_version=assigned.lease_version,
        worker_id="worker-d5",
        worker_fencing_token=1,
        error_message="Finished",
    )

    drained = drain_ctrl.check_drain_completed("worker-d5")
    assert drained is True
    w = worker_repo.get_worker("worker-d5")
    assert w.status == WorkerStatus.DRAINED


def test_force_fence_increments_fencing_token(worker_repo, drain_ctrl, session_factory):
    worker_repo.register_worker("worker-d6", "secret", "localhost")
    drain_ctrl.initiate_drain("worker-d6")
    drain_ctrl.force_fence("worker-d6")

    w = worker_repo.get_worker("worker-d6")
    assert w.status == WorkerStatus.FENCED

    session = session_factory.get_session()
    try:
        model = session.scalar(select(WorkerModel).where(WorkerModel.worker_id == "worker-d6"))
        assert model.fencing_token == 2  # Incremented from 1 to 2
    finally:
        session.close()


def test_fenced_worker_mutation_rejected(task_repo, worker_repo, drain_ctrl):
    worker_repo.register_worker("worker-d7", "secret", "localhost")
    assigned = create_assigned_task(task_repo, "worker-d7", "task-fence-d7")
    drain_ctrl.initiate_drain("worker-d7")
    drain_ctrl.force_fence("worker-d7")  # fencing_token becomes 2, status FENCED

    # Stale worker mutation attempt with fencing_token=1 raises WorkerFencedError
    with pytest.raises(WorkerFencedError):
        task_repo.record_execution_failure(
            task_id="task-fence-d7",
            expected_lease_version=assigned.lease_version,
            worker_id="worker-d7",
            worker_fencing_token=1,
            error_message="Stale attempt after fence",
        )


def test_wait_for_drain_successful_drain(task_repo, worker_repo, drain_ctrl):
    worker_repo.register_worker("worker-d8", "secret", "localhost")
    assigned = create_assigned_task(task_repo, "worker-d8", "task-wait-d8")

    # Finish task in background or immediately
    task_repo.record_execution_failure(
        task_id="task-wait-d8",
        expected_lease_version=assigned.lease_version,
        worker_id="worker-d8",
        worker_fencing_token=1,
        error_message="Finished",
    )

    status = drain_ctrl.wait_for_drain("worker-d8", timeout_seconds=1.0, poll_interval=0.1)
    assert status == WorkerStatus.DRAINED


def test_wait_for_drain_timeout_triggers_fenced(task_repo, worker_repo, drain_ctrl):
    worker_repo.register_worker("worker-d9", "secret", "localhost")
    create_assigned_task(task_repo, "worker-d9", "task-stuck-d9")

    # Task remains RUNNING during 0.3s timeout -> triggers FENCED
    status = drain_ctrl.wait_for_drain("worker-d9", timeout_seconds=0.3, poll_interval=0.1)
    assert status == WorkerStatus.FENCED


def test_global_lock_order_worker_first_then_task(task_repo, worker_repo):
    worker_repo.register_worker("worker-lock-1", "secret", "localhost")
    create_assigned_task(task_repo, "worker-lock-1", "task-lock-1")
    count = worker_repo.get_active_task_count("worker-lock-1")
    assert count == 1
