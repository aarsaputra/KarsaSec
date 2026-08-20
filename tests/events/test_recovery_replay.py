"""Adversarial security tests for INV-F8-REPLAY-06 (Recovery Replay Protection).

Verifies that duplicate recovery sweeps or retry executions produce deduplicated outbox events.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base, OutboxEventModel
from karsasec.events.outbox import TransactionalOutbox


class TestRecoveryReplayF8:
    @pytest.fixture(autouse=True)
    def setup_db(self):
        sf = DatabaseSessionFactory("sqlite:///:memory:")
        engine = sf.engine
        Base.metadata.create_all(bind=engine)
        self.sf = sf

    def test_duplicate_recovery_event_deduplication(self):
        dedup_key = "recovery_task_99_v3"

        # First recovery sweep
        with self.sf.session_scope() as session:
            evt1 = TransactionalOutbox.stage_event(
                session=session,
                aggregate_type="TASK",
                aggregate_id="task_99",
                event_type="TASK_RECOVERED",
                payload={"task_id": "task_99", "state": "QUEUED"},
                lease_version=3,
                deduplication_key=dedup_key,
            )
            assert evt1 is not None
            evt1_id = evt1.event_id

        # Second recovery sweep (duplicate execution attempt)
        with self.sf.session_scope() as session:
            evt2 = TransactionalOutbox.stage_event(
                session=session,
                aggregate_type="TASK",
                aggregate_id="task_99",
                event_type="TASK_RECOVERED",
                payload={"task_id": "task_99", "state": "QUEUED"},
                lease_version=3,
                deduplication_key=dedup_key,
            )
            assert evt2 is not None
            assert evt2.event_id == evt1_id  # Returns existing event, avoiding duplicate!

        # Assert total event count for task_99 remains 1
        with self.sf.session_scope() as session:
            events = list(
                session.scalars(select(OutboxEventModel).where(OutboxEventModel.aggregate_id == "task_99")).all()
            )
            assert len(events) == 1
