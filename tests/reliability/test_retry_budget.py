"""Adversarial Test Suite for Sprint F6C — Task-Bound Retry Budget (9 Tests).

Verifies invariants:
  - INV-F6-RETRY-01: max_attempts is task-bound.
  - INV-F6-RETRY-03: attempts is incremented exactly once upon transition from QUEUED to RUNNING.
  - INV-F6-RETRY-04: Task execution failure returning task to QUEUED does not increment attempts.
  - INV-F6-RETRY-05: Task state transitions to FAILED when attempts >= max_attempts.
  - INV-F6-RETRY-07: Single attempt increment semantics across retry lifecycle.
  - INV-F6-RETRY-09: Metadata cleared on requeue.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base, TaskModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.postgres_worker_repository import PostgresWorkerRepository
from karsasec.reliability.retry_budget import TaskRetryBudget
from karsasec.workers.task import (
    RemediationTask,
    TaskState,
    InvalidTaskStateError,
)


@pytest.fixture
def session_factory(tmp_path):
    db_file = tmp_path / "test_retry.db"
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
def active_worker(worker_repo):
    return worker_repo.register_worker("worker-1", "secret-worker-token", "localhost")


def create_test_task(task_repo, task_id="task-retry-1", max_attempts=3) -> RemediationTask:
    task = RemediationTask(
        task_id=task_id,
        finding_id="finding-123",
        approval_token_id="token-456",
        token="",
        fingerprint=f"fp-{task_id}",
        state=TaskState.QUEUED,
        attempts=0,
        max_attempts=max_attempts,
    )
    task_repo.create_task(task)
    return task


def test_retry_budget_initial_attempts(task_repo):
    task = create_test_task(task_repo, "task-init-1", max_attempts=3)
    assert task.attempts == 0
    assert task.max_attempts == 3
    assert TaskRetryBudget.can_retry(task) is True
    assert TaskRetryBudget.remaining_attempts(task) == 3


def test_assign_task_increments_attempts_once(task_repo, active_worker):
    create_test_task(task_repo, "task-assign-1", max_attempts=3)
    assigned = task_repo.assign_task("task-assign-1", active_worker.worker_id)
    assert assigned.state == TaskState.RUNNING
    assert assigned.attempts == 1
    assert assigned.lease_version == 2


def test_record_failure_does_not_increment_attempts(task_repo, active_worker, session_factory):
    create_test_task(task_repo, "task-fail-no-inc-1", max_attempts=3)
    assigned = task_repo.assign_task("task-fail-no-inc-1", active_worker.worker_id)
    assert assigned.attempts == 1

    # Record execution failure (attempts remains 1)
    requeued = task_repo.record_execution_failure(
        task_id="task-fail-no-inc-1",
        expected_lease_version=assigned.lease_version,
        worker_id=active_worker.worker_id,
        worker_fencing_token=1,
        error_message="Transient network error",
    )
    assert requeued.state == TaskState.QUEUED
    assert requeued.attempts == 1  # INV-F6-RETRY-07: Unchanged!
    assert requeued.lease_version == 3


def test_reassign_task_increments_attempts(task_repo, active_worker):
    create_test_task(task_repo, "task-reassign-1", max_attempts=3)
    t1 = task_repo.assign_task("task-reassign-1", active_worker.worker_id)
    t2 = task_repo.record_execution_failure(
        task_id="task-reassign-1",
        expected_lease_version=t1.lease_version,
        worker_id=active_worker.worker_id,
        worker_fencing_token=1,
        error_message="Fail 1",
    )
    assert t2.attempts == 1

    t3 = task_repo.assign_task("task-reassign-1", active_worker.worker_id)
    assert t3.state == TaskState.RUNNING
    assert t3.attempts == 2  # Incremented on second assignment


def test_record_failure_exhaustion_transitions_to_failed(task_repo, active_worker):
    create_test_task(task_repo, "task-exhaust-1", max_attempts=2)
    # Attempt 1
    t1 = task_repo.assign_task("task-exhaust-1", active_worker.worker_id)
    t2 = task_repo.record_execution_failure(
        task_id="task-exhaust-1",
        expected_lease_version=t1.lease_version,
        worker_id=active_worker.worker_id,
        worker_fencing_token=1,
        error_message="Fail 1",
    )
    # Attempt 2
    t3 = task_repo.assign_task("task-exhaust-1", active_worker.worker_id)
    t4 = task_repo.record_execution_failure(
        task_id="task-exhaust-1",
        expected_lease_version=t3.lease_version,
        worker_id=active_worker.worker_id,
        worker_fencing_token=1,
        error_message="Fail 2 - Exhausted",
    )
    assert t4.state == TaskState.FAILED
    assert t4.attempts == 2


def test_assigned_worker_metadata_cleared_on_requeue(task_repo, active_worker, session_factory):
    create_test_task(task_repo, "task-clear-meta-1", max_attempts=3)
    t1 = task_repo.assign_task("task-clear-meta-1", active_worker.worker_id)
    t2 = task_repo.record_execution_failure(
        task_id="task-clear-meta-1",
        expected_lease_version=t1.lease_version,
        worker_id=active_worker.worker_id,
        worker_fencing_token=1,
        error_message="Fail 1",
    )
    assert t2.state == TaskState.QUEUED

    # Query DB directly to verify INV-F6-RETRY-09
    session = session_factory.get_session()
    try:
        model = session.scalar(select(TaskModel).where(TaskModel.task_id == "task-clear-meta-1"))
        assert model.assigned_worker_id is None
        assert model.assigned_worker_fencing_token is None
    finally:
        session.close()


def test_assign_task_blocks_when_attempts_exhausted(task_repo, active_worker):
    create_test_task(task_repo, "task-block-exhaust-1", max_attempts=1)
    t1 = task_repo.assign_task("task-block-exhaust-1", active_worker.worker_id)
    task_repo.record_execution_failure(
        task_id="task-block-exhaust-1",
        expected_lease_version=t1.lease_version,
        worker_id=active_worker.worker_id,
        worker_fencing_token=1,
        error_message="Fatal fail",
    )

    with pytest.raises(InvalidTaskStateError):
        task_repo.assign_task("task-block-exhaust-1", active_worker.worker_id)


def test_retry_budget_can_retry_helper(task_repo):
    task = RemediationTask(
        task_id="task-helper-1",
        finding_id="f1",
        approval_token_id="a1",
        token="",
        fingerprint="fp1",
        attempts=3,
        max_attempts=3,
    )
    assert TaskRetryBudget.can_retry(task) is False
    assert TaskRetryBudget.is_exhausted(task) is True
    assert TaskRetryBudget.remaining_attempts(task) == 0


def test_concurrency_race_single_attempt_increment(task_repo, active_worker):
    create_test_task(task_repo, "task-concur-1", max_attempts=3)
    t1 = task_repo.assign_task("task-concur-1", active_worker.worker_id)
    assert t1.attempts == 1

    # Second assignment on running task raises InvalidTaskStateError
    with pytest.raises(InvalidTaskStateError):
        task_repo.assign_task("task-concur-1", active_worker.worker_id)
