"""Sprint F10 Phase 4 — Event Ordering Tests (INV-F10-AUDIT-06)."""

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
        task = TaskModel(task_id="t-p4-ord", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
        budget = AIBudgetModel(budget_id="b-p4-ord", tenant_id="t1", token_limit=1_000_000)
        session.add_all([task, budget])
        session.commit()
        yield session
    finally:
        session.close()


def test_happy_path_event_ordering(db_session):
    """INV-F10-AUDIT-06: Happy path stages events in exact deterministic sequence."""
    task_id = "t-p4-ord"
    req_id = "req-ord-1"
    b_id = "b-p4-ord"

    AIEventService.stage_budget_reserved(db_session, req_id, task_id, b_id, reserved_tokens=1000, lease_version=1)
    AIEventService.stage_prompt_generated(
        db_session, req_id, task_id, prompt_hash="1" * 64, context_hash="2" * 64, lease_version=2
    )
    AIEventService.stage_provider_selected(
        db_session, req_id, task_id, "att-1", 1, "openai", "gpt-4o", 5000, lease_version=3
    )
    AIEventService.stage_response_received(
        db_session, req_id, task_id, "att-1", 1, "openai", "gpt-4o", 1000, 500, 4500, lease_version=4
    )
    AIEventService.stage_budget_committed(
        db_session, req_id, task_id, b_id, actual_tokens=1500, actual_cost_micro_units=4500, lease_version=5
    )
    db_session.flush()

    events = db_session.scalars(
        select(OutboxEventModel)
        .where(OutboxEventModel.aggregate_id == req_id)
        .order_by(OutboxEventModel.aggregate_sequence.asc())
    ).all()

    types = [e.event_type for e in events]
    assert types == [
        "AI_BUDGET_RESERVED",
        "AI_PROMPT_GENERATED",
        "AI_PROVIDER_SELECTED",
        "AI_RESPONSE_RECEIVED",
        "AI_BUDGET_COMMITTED",
    ]


def test_failover_retry_event_ordering(db_session):
    """Provider failure -> retry with new provider -> completion ordering."""
    task_id = "t-p4-ord"
    req_id = "req-ord-2"
    b_id = "b-p4-ord"

    AIEventService.stage_budget_reserved(db_session, req_id, task_id, b_id, 1000, lease_version=1)
    AIEventService.stage_prompt_generated(db_session, req_id, task_id, "1" * 64, "2" * 64, lease_version=2)
    AIEventService.stage_provider_selected(
        db_session, req_id, task_id, "att-1", 1, "openai", "gpt-4o", 5000, lease_version=3
    )
    AIEventService.stage_provider_failed(
        db_session, req_id, task_id, "att-1", 1, "openai", "gpt-4o", "TIMEOUT", lease_version=4
    )
    AIEventService.stage_provider_selected(
        db_session, req_id, task_id, "att-2", 2, "anthropic", "claude-3-5", 4000, lease_version=5
    )
    AIEventService.stage_response_received(
        db_session, req_id, task_id, "att-2", 2, "anthropic", "claude-3-5", 1000, 400, 3800, lease_version=6
    )
    AIEventService.stage_budget_committed(db_session, req_id, task_id, b_id, 1400, 3800, lease_version=7)
    db_session.flush()

    events = db_session.scalars(
        select(OutboxEventModel)
        .where(OutboxEventModel.aggregate_id == req_id)
        .order_by(OutboxEventModel.aggregate_sequence.asc())
    ).all()

    types = [e.event_type for e in events]
    assert types == [
        "AI_BUDGET_RESERVED",
        "AI_PROMPT_GENERATED",
        "AI_PROVIDER_SELECTED",
        "AI_PROVIDER_FAILED",
        "AI_PROVIDER_SELECTED",
        "AI_RESPONSE_RECEIVED",
        "AI_BUDGET_COMMITTED",
    ]
