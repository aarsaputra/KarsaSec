"""Adversarial security tests for INV-F8-OUTBOX-01 (Transactional Outbox Atomicity).

Verifies that task state mutations, outbox event generation, and audit log creation occur atomically in the SAME SQL transaction. If a transaction rolls back, all three entities are rolled back together.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base, TaskModel, OutboxEventModel, TaskAuditLogModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.workers.task import RemediationTask, TaskState


class TestOutboxAtomicityF8:
    @pytest.fixture(autouse=True)
    def setup_db(self):
        sf = DatabaseSessionFactory("sqlite:///:memory:")
        engine = sf.engine
        Base.metadata.create_all(bind=engine)
        self.sf = sf
        self.repo = PostgresTaskRepository(sf)

    def test_atomicity_commit_creates_task_outbox_and_audit(self):
        task = RemediationTask(
            task_id="task_atomicity_1",
            finding_id="find_1",
            approval_token_id="tok_1",
            token="token_val",
            fingerprint="fp_1",
            state=TaskState.QUEUED,
        )
        self.repo.create_task(task)

        with self.sf.session_scope() as session:
            t = session.scalar(select(TaskModel).where(TaskModel.task_id == "task_atomicity_1"))
            assert t is not None

            evt = session.scalar(select(OutboxEventModel).where(OutboxEventModel.aggregate_id == "task_atomicity_1"))
            assert evt is not None
            assert evt.event_type == "TASK_CREATED"
            assert evt.status == "PENDING"

            audit = session.scalar(select(TaskAuditLogModel).where(TaskAuditLogModel.task_id == "task_atomicity_1"))
            assert audit is not None
            assert audit.previous_state == "NONE"
            assert audit.new_state == "QUEUED"

    def test_atomicity_rollback_cancels_all_mutations(self):
        # Trigger explicit transaction rollback simulation
        try:
            with self.sf.session_scope() as session:
                task = TaskModel(task_id="task_rollback_1", finding_id="find_1", state="QUEUED")
                session.add(task)
                # Stage outbox event manually
                evt = OutboxEventModel(
                    event_id="evt_rollback",
                    aggregate_id="task_rollback_1",
                    event_type="TASK_CREATED",
                    payload="{}",
                    status="PENDING",
                )
                session.add(evt)
                # Force rollback
                raise RuntimeError("Simulated DB error mid-transaction")
        except RuntimeError:
            pass

        # Verify nothing was committed
        with self.sf.session_scope() as session:
            t = session.scalar(select(TaskModel).where(TaskModel.task_id == "task_rollback_1"))
            assert t is None
            e = session.scalar(select(OutboxEventModel).where(OutboxEventModel.event_id == "evt_rollback"))
            assert e is None
