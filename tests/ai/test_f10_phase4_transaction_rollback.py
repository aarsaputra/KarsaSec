"""Sprint F10 Phase 4 — Transaction Rollback Tests (INV-F10-AUDIT-02, INV-F10-AUDIT-03)."""

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from karsasec.ai.budget import AIBudgetService
from karsasec.ai.events import AIEventService
from karsasec.ai.request import AIRequestStateService
from karsasec.persistence.models import (
    AIBudgetModel,
    AIRequestModel,
    Base,
    OutboxEventModel,
    TaskAuditLogModel,
    TaskModel,
)


@pytest.fixture
def db_session_factory():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    task = TaskModel(task_id="t-p4-rb", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
    budget = AIBudgetModel(budget_id="b-p4-rb", tenant_id="t1", token_limit=1_000_000)
    session.add_all([task, budget])
    session.commit()
    session.close()
    return session_factory


def test_transaction_rollback_removes_state_budget_and_events(db_session_factory):
    """INV-F10-AUDIT-03: Rollback cancels state transition, budget reservation, outbox event, and audit entry."""
    session = db_session_factory()

    try:
        # Step 1: Create request
        AIRequestStateService.create_request(
            session,
            request_id="req-rb-1",
            task_id="t-p4-rb",
            budget_id="b-p4-rb",
            prompt_hash="1" * 64,
            context_hash="2" * 64,
        )

        # Step 2: Reserve budget
        AIBudgetService.reserve_tokens(session, "b-p4-rb", 5000)
        AIRequestStateService.transition_status(session, "req-rb-1", "CREATED", "RESERVED")

        # Step 3: Stage events
        AIEventService.stage_budget_reserved(
            session, request_id="req-rb-1", task_id="t-p4-rb", budget_id="b-p4-rb", reserved_tokens=5000
        )
        AIEventService.stage_prompt_generated(
            session, request_id="req-rb-1", task_id="t-p4-rb", prompt_hash="1" * 64, context_hash="2" * 64
        )

        # Step 4: Simulate a mid-transaction failure
        raise RuntimeError("Simulated crash mid-transaction")

    except RuntimeError:
        session.rollback()
    finally:
        session.close()

    # Verify everything was rolled back in a new session
    verify_session = db_session_factory()
    try:
        req = verify_session.scalar(select(AIRequestModel).where(AIRequestModel.request_id == "req-rb-1"))
        assert req is None, "AIRequestModel must be rolled back"

        budget = verify_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-p4-rb"))
        assert budget.reserved_tokens == 0, "Budget reservation must be rolled back"

        events = verify_session.scalars(
            select(OutboxEventModel).where(OutboxEventModel.aggregate_id == "req-rb-1")
        ).all()
        assert len(events) == 0, "Outbox events must be rolled back"

        audits = verify_session.scalars(select(TaskAuditLogModel).where(TaskAuditLogModel.task_id == "t-p4-rb")).all()
        assert len(audits) == 0, "Audit log entries must be rolled back"
    finally:
        verify_session.close()


def test_no_internal_session_commit_in_event_service(db_session_factory):
    """INV-F10-AUDIT-02: AIEventService methods do NOT call session.commit()."""
    session = db_session_factory()

    AIEventService.stage_budget_reserved(
        session, request_id="req-rb-2", task_id="t-p4-rb", budget_id="b-p4-rb", reserved_tokens=1000
    )

    # Session should be uncommitted (in transaction / pending state)
    assert len(session.new) > 0, "Staged models must reside in session.new before explicit commit"
    session.rollback()
    session.close()
