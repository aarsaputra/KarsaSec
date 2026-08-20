"""Sprint F10 Phase 4 — Idempotency Tests (INV-F10-AUDIT-09)."""

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from karsasec.ai.events import AIEventService
from karsasec.persistence.models import AIBudgetModel, Base, OutboxEventModel, TaskModel


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        task = TaskModel(task_id="t-p4-idem", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
        budget = AIBudgetModel(budget_id="b-p4-idem", tenant_id="t1", token_limit=1_000_000)
        session.add_all([task, budget])
        session.commit()
        yield session
    finally:
        session.close()


def test_retry_returns_existing_staged_event(db_session):
    """INV-F10-AUDIT-09: Re-staging the same event returns the existing OutboxEventModel."""
    evt1 = AIEventService.stage_budget_reserved(
        db_session, request_id="req-idem-1", task_id="t-p4-idem", budget_id="b-p4-idem", reserved_tokens=1000
    )
    db_session.flush()

    evt2 = AIEventService.stage_budget_reserved(
        db_session, request_id="req-idem-1", task_id="t-p4-idem", budget_id="b-p4-idem", reserved_tokens=1000
    )

    assert evt1.event_id == evt2.event_id
    assert evt1.deduplication_key == evt2.deduplication_key

    # Count outbox records in DB
    events = db_session.scalars(select(OutboxEventModel).where(OutboxEventModel.aggregate_id == "req-idem-1")).all()
    assert len(events) == 1, "Duplicate staging attempt must not create duplicate outbox records"


def test_different_attempt_ids_produce_distinct_events(db_session):
    """Different attempt_id values (failover) produce distinct deduplication keys."""
    evt1 = AIEventService.stage_provider_selected(
        db_session,
        request_id="req-idem-2",
        task_id="t-p4-idem",
        attempt_id="att-1",
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
        estimated_cost_micro_units=5000,
    )
    db_session.flush()

    evt2 = AIEventService.stage_provider_selected(
        db_session,
        request_id="req-idem-2",
        task_id="t-p4-idem",
        attempt_id="att-2",
        attempt_number=2,
        provider_id="anthropic",
        model_id="claude-3-5",
        estimated_cost_micro_units=4000,
    )
    db_session.flush()

    assert evt1.event_id != evt2.event_id
    assert evt1.deduplication_key != evt2.deduplication_key

    events = db_session.scalars(select(OutboxEventModel).where(OutboxEventModel.aggregate_id == "req-idem-2")).all()
    assert len(events) == 2
