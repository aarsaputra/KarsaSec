"""Adversarial Test Suite for Sprint F6C — Forensic Dead-Letter Queue (9 Tests).

Verifies invariants:
  - INV-F6-DLQ-01: Exactly one terminal task produces at most one forensic DLQ record.
  - INV-F6-DLQ-02: Created transactionally atomic with task FAILED state mutation.
  - INV-F6-DLQ-03: SAFE_DLQ_SCHEMA forensic snapshotting and exception scrubbing.
  - INV-F6-DLQ-04: UNIQUE(task_id) constraint guarantees idempotency under concurrent execution.
  - INV-F6-DLQ-05: Strict byte bounds (sanitized_error_message <= 8192 bytes, payload_json <= 32768 bytes).
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base, DeadLetterEventModel, TaskModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.postgres_worker_repository import PostgresWorkerRepository
from karsasec.reliability.dead_letter import (
    DeadLetterRepository,
    sanitize_exception,
    truncate_to_bytes,
    MAX_ERROR_BYTES,
    MAX_PAYLOAD_BYTES,
)
from karsasec.workers.task import RemediationTask, TaskState


@pytest.fixture
def session_factory(tmp_path):
    db_file = tmp_path / "test_dlq.db"
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
def dlq_repo(session_factory):
    return DeadLetterRepository(session_factory)


@pytest.fixture
def active_worker(worker_repo):
    return worker_repo.register_worker("worker-dlq-1", "secret-token", "localhost")


def create_exhausted_task(task_repo, active_worker, task_id="task-dlq-1") -> RemediationTask:
    task = RemediationTask(
        task_id=task_id,
        finding_id="finding-999",
        approval_token_id="token-888",
        token="",
        fingerprint=f"fp-{task_id}",
        state=TaskState.QUEUED,
        attempts=0,
        max_attempts=1,
    )
    task_repo.create_task(task)
    assigned = task_repo.assign_task(task_id, active_worker.worker_id)
    return assigned


def test_dlq_created_on_task_failed(task_repo, dlq_repo, active_worker):
    assigned = create_exhausted_task(task_repo, active_worker, "task-dlq-created-1")
    task_repo.record_execution_failure(
        task_id="task-dlq-created-1",
        expected_lease_version=assigned.lease_version,
        worker_id=active_worker.worker_id,
        worker_fencing_token=1,
        error_message="Fatal execution error",
    )
    event = dlq_repo.get_event("task-dlq-created-1")
    assert event is not None
    assert event["task_id"] == "task-dlq-created-1"
    assert event["reason"] == "EXHAUSTED"
    assert event["sanitized_error_message"] == "Fatal execution error"


def test_dlq_atomic_with_task_mutation(task_repo, session_factory, active_worker):
    assigned = create_exhausted_task(task_repo, active_worker, "task-dlq-atomic-1")
    failed = task_repo.record_execution_failure(
        task_id="task-dlq-atomic-1",
        expected_lease_version=assigned.lease_version,
        worker_id=active_worker.worker_id,
        worker_fencing_token=1,
        error_message="Atomic fail",
    )
    assert failed.state == TaskState.FAILED

    # Verify both task and DLQ event exist in single commit
    session = session_factory.get_session()
    try:
        task_m = session.scalar(select(TaskModel).where(TaskModel.task_id == "task-dlq-atomic-1"))
        dlq_m = session.scalar(select(DeadLetterEventModel).where(DeadLetterEventModel.task_id == "task-dlq-atomic-1"))
        assert task_m.state == "FAILED"
        assert dlq_m is not None
    finally:
        session.close()


from sqlalchemy.exc import IntegrityError


def test_dlq_idempotency_unique_constraint(session_factory):
    session = session_factory.get_session()
    try:
        e1 = DeadLetterEventModel(
            event_id="evt-1",
            task_id="task-uniq-1",
            reason="EXHAUSTED",
            attempts=1,
            max_attempts=1,
        )
        session.add(e1)
        session.commit()

        # Duplicate task_id insertion raises exception
        e2 = DeadLetterEventModel(
            event_id="evt-2",
            task_id="task-uniq-1",
            reason="EXHAUSTED",
            attempts=1,
            max_attempts=1,
        )
        session.add(e2)
        with pytest.raises(IntegrityError):
            session.commit()
    finally:
        session.close()


def test_dlq_sanitizes_db_credentials():
    raw_error = "Connection failed to postgresql://admin:secret_pass_123@prod-db.internal:5432/karsasec"
    scrubbed = sanitize_exception(raw_error)
    assert "secret_pass_123" not in scrubbed
    assert "postgresql://[REDACTED]@[REDACTED]/[REDACTED]" in scrubbed


def test_dlq_sanitizes_bearer_tokens():
    raw_error = "Authentication header was Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
    scrubbed = sanitize_exception(raw_error)
    assert "eyJhbGci" not in scrubbed
    assert "Bearer [REDACTED]" in scrubbed


def test_dlq_error_message_size_bound():
    huge_error = "E" * 10000
    scrubbed = sanitize_exception(huge_error)
    assert len(scrubbed.encode("utf-8")) <= MAX_ERROR_BYTES
    assert "[TRUNCATED]" in scrubbed


def test_dlq_payload_size_bound():
    huge_text = "A" * 40000
    truncated = truncate_to_bytes(huge_text, MAX_PAYLOAD_BYTES)
    assert len(truncated.encode("utf-8")) <= MAX_PAYLOAD_BYTES
    assert "[TRUNCATED]" in truncated


def test_dlq_repository_get_and_list(task_repo, dlq_repo, active_worker):
    assigned = create_exhausted_task(task_repo, active_worker, "task-list-1")
    task_repo.record_execution_failure(
        task_id="task-list-1",
        expected_lease_version=assigned.lease_version,
        worker_id=active_worker.worker_id,
        worker_fencing_token=1,
        error_message="List test fail",
    )
    events = dlq_repo.list_events(limit=10)
    assert len(events) >= 1
    matched = [e for e in events if e["task_id"] == "task-list-1"]
    assert len(matched) == 1


def test_dlq_repository_get_count(task_repo, dlq_repo, active_worker):
    initial_count = dlq_repo.get_count()
    assigned = create_exhausted_task(task_repo, active_worker, "task-count-1")
    task_repo.record_execution_failure(
        task_id="task-count-1",
        expected_lease_version=assigned.lease_version,
        worker_id=active_worker.worker_id,
        worker_fencing_token=1,
        error_message="Count fail",
    )
    new_count = dlq_repo.get_count()
    assert new_count == initial_count + 1
