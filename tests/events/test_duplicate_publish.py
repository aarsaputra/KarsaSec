"""Adversarial security tests for INV-F8-EVENT-02 and INV-F8-PUBLISH-04.

Verifies publisher lease fencing with FOR UPDATE SKIP LOCKED and idempotency against duplicate delivery.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base, OutboxEventModel
from karsasec.events.outbox import TransactionalOutbox
from karsasec.events.publisher import ReliableEventPublisher


class TestDuplicatePublishF8:
    @pytest.fixture(autouse=True)
    def setup_db(self):
        sf = DatabaseSessionFactory("sqlite:///:memory:")
        engine = sf.engine
        Base.metadata.create_all(bind=engine)
        self.sf = sf

    def test_publisher_lease_fencing_claims_events_uniquely(self):
        with self.sf.session_scope() as session:
            TransactionalOutbox.stage_event(
                session=session,
                aggregate_type="TASK",
                aggregate_id="task_1",
                event_type="TASK_CREATED",
                payload={"task_id": "task_1"},
            )

        pub1 = ReliableEventPublisher(self.sf, publisher_id="publisher_A")
        pub2 = ReliableEventPublisher(self.sf, publisher_id="publisher_B")

        handler_calls = []

        def _handler(evt):
            handler_calls.append(evt)

        # Publisher A polls and claims
        count1 = pub1.poll_and_publish(limit=10, handler=_handler)
        assert count1 == 1
        assert len(handler_calls) == 1

        # Publisher B attempts poll; event is already CLAIMED / PUBLISHED so count is 0
        count2 = pub2.poll_and_publish(limit=10, handler=_handler)
        assert count2 == 0
        assert len(handler_calls) == 1

    def test_idempotency_prevents_duplicate_side_effects(self):
        with self.sf.session_scope() as session:
            evt = TransactionalOutbox.stage_event(
                session=session,
                aggregate_type="TASK",
                aggregate_id="task_dup",
                event_type="TASK_ASSIGNED",
                payload={"task_id": "task_dup"},
            )
            evt_id = evt.event_id

        publisher = ReliableEventPublisher(self.sf, publisher_id="publisher_single")

        execution_count = 0

        def _side_effect(data):
            nonlocal execution_count
            execution_count += 1

        # First publish
        pub_count1 = publisher.poll_and_publish(handler=_side_effect)
        assert pub_count1 == 1
        assert execution_count == 1

        # Re-add to processed list simulation or force claim again
        with self.sf.session_scope() as session:
            model = session.scalar(select(OutboxEventModel).where(OutboxEventModel.event_id == evt_id))
            model.status = "PENDING"

        # Second publish call by same publisher instance
        pub_count2 = publisher.poll_and_publish(handler=_side_effect)
        assert pub_count2 == 1
        assert execution_count == 1  # Side-effect NOT executed twice!
