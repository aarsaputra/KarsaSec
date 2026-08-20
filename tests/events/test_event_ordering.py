"""Adversarial security tests for INV-F8-ORDER-03 (Per-Task Event Ordering).

Verifies that lease_version drives per-task aggregate_sequence, preserving strict event sequence (QUEUED -> RUNNING -> COMPLETED).
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base, OutboxEventModel, WorkerModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.workers.task import RemediationTask, TaskState


class TestEventOrderingF8:
    @pytest.fixture(autouse=True)
    def setup_db(self):
        sf = DatabaseSessionFactory("sqlite:///:memory:")
        engine = sf.engine
        Base.metadata.create_all(bind=engine)
        self.sf = sf
        self.repo = PostgresTaskRepository(sf)

    def test_per_task_event_sequence_monotonic(self):
        # 1. Create task (v1)
        task = RemediationTask(
            task_id="task_order_1",
            finding_id="find_1",
            approval_token_id="tok_1",
            token="token_val",
            fingerprint="fp_1",
            state=TaskState.QUEUED,
        )
        self.repo.create_task(task)

        # 2. Register worker and assign task (v2)
        with self.sf.session_scope() as session:
            w = WorkerModel(
                worker_id="worker_order",
                auth_token_hash="hash_123",
                status="ONLINE",
                fencing_token=1,
            )
            session.add(w)

        self.repo.assign_task("task_order_1", "worker_order")

        # 3. Complete task (v2)
        self.repo.complete_task(
            task_id="task_order_1",
            expected_lease_version=2,
            worker_id="worker_order",
            worker_fencing_token=1,
            receipt_id="rec_1",
            receipt_fingerprint="fp_1",
            security_verification_status="VERIFIED",
        )

        # Fetch all outbox events for task_order_1
        with self.sf.session_scope() as session:
            events = list(
                session.scalars(
                    select(OutboxEventModel)
                    .where(OutboxEventModel.aggregate_id == "task_order_1")
                    .order_by(OutboxEventModel.created_at.asc(), OutboxEventModel.aggregate_sequence.asc())
                ).all()
            )

            assert len(events) == 3
            assert events[0].event_type == "TASK_CREATED"
            assert events[0].aggregate_sequence == 1

            assert events[1].event_type == "TASK_ASSIGNED"
            assert events[1].aggregate_sequence == 2

            assert events[2].event_type == "TASK_COMPLETED"
            assert events[2].aggregate_sequence == 3
