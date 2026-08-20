"""Unit & Integration tests for Security Audit Trail & Non-Blocking Resilience (Sprint F6A)."""

from __future__ import annotations

import pytest

from karsasec.persistence.audit_repository import (
    AuditEvent,
    AuditEventType,
    PostgresAuditRepository,
)
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.workers.task import RemediationTask, TaskState, StaleLeaseVersionError


@pytest.fixture
def test_db_factory(tmp_path):
    db_file = tmp_path / "test_f6a_audit.db"
    url = f"sqlite:///{db_file}"
    factory = DatabaseSessionFactory(url=url)
    Base.metadata.create_all(bind=factory.engine)
    yield factory
    factory.close()


class TestNonBlockingAuditRepository:
    def test_audit_append_success(self, test_db_factory):
        audit_repo = PostgresAuditRepository(test_db_factory)
        event = AuditEvent(
            task_id="tsk-audit-1",
            event_type=AuditEventType.TASK_CREATED,
            details={"state": "PENDING"},
            correlation_id="corr-test-1",
        )
        audit_repo.append(event)

        retrieved = audit_repo.get_events_for_task("tsk-audit-1")
        assert len(retrieved) == 1
        assert retrieved[0].task_id == "tsk-audit-1"
        assert retrieved[0].event_type == "TASK_CREATED"
        assert retrieved[0].details.get("correlation_id") == "corr-test-1"

    def test_audit_failure_is_non_blocking(self):
        # Invalid database factory pointing to nonexistent path to trigger session failure
        failing_factory = DatabaseSessionFactory(url="sqlite:////nonexistent/invalid/audit_db.db")
        audit_repo = PostgresAuditRepository(failing_factory)

        event = AuditEvent(
            task_id="tsk-fail-audit",
            event_type=AuditEventType.TASK_STARTED,
        )

        # Append must NOT raise an exception (non-blocking audit safety rule)
        audit_repo.append(event)


class TestTaskRepositoryAuditIntegration:
    def test_task_atomic_transition_emits_audit_events(self, test_db_factory):
        audit_repo = PostgresAuditRepository(test_db_factory)
        task_repo = PostgresTaskRepository(test_db_factory, audit_repo=audit_repo)

        task = RemediationTask(
            task_id="tsk-audit-int-1",
            finding_id="f-1",
            approval_token_id="tok-1",
            token="secret",
            fingerprint="fp-1",
            state=TaskState.PENDING,
        )
        task_repo.create_task(task)

        # Transition 1: PENDING -> QUEUED
        task_repo.atomic_transition("tsk-audit-int-1", 1, [TaskState.PENDING], TaskState.QUEUED)

        # Transition 2: QUEUED -> RUNNING
        task_repo.atomic_transition("tsk-audit-int-1", 2, [TaskState.QUEUED], TaskState.RUNNING)

        events = audit_repo.get_events_for_task("tsk-audit-int-1")
        assert len(events) == 2
        assert events[0].event_type == AuditEventType.TASK_STATE_CHANGED
        assert events[0].details.get("new_state") == "QUEUED"
        assert events[1].details.get("new_state") == "RUNNING"

    def test_stale_lease_cas_rejection_records_audit(self, test_db_factory):
        audit_repo = PostgresAuditRepository(test_db_factory)
        task_repo = PostgresTaskRepository(test_db_factory, audit_repo=audit_repo)

        task = RemediationTask(
            task_id="tsk-audit-rej",
            finding_id="f-1",
            approval_token_id="tok-1",
            token="secret",
            fingerprint="fp-1",
            state=TaskState.PENDING,
        )
        task_repo.create_task(task)

        # v1 -> v2
        task_repo.atomic_transition("tsk-audit-rej", 1, [TaskState.PENDING], TaskState.QUEUED)

        # Stale CAS using v1 (active is v2)
        with pytest.raises(StaleLeaseVersionError):
            task_repo.atomic_transition("tsk-audit-rej", 1, [TaskState.QUEUED], TaskState.RUNNING)

        events = audit_repo.get_events_for_task("tsk-audit-rej")
        assert len(events) == 2
        assert events[1].event_type == AuditEventType.TASK_CAS_REJECTED
        assert events[1].details.get("expected_lease_version") == 1
        assert events[1].details.get("active_lease_version") == 2
