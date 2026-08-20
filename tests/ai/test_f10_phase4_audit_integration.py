"""Sprint F10 Phase 4 — Audit Integration Tests (INV-F10-AUDIT-08, INV-F10-AUDIT-12)."""

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from karsasec.ai.events import AIEventService
from karsasec.events.audit_ledger import TaskAuditLedger
from karsasec.persistence.models import Base, TaskAuditLogModel, TaskModel


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        task = TaskModel(task_id="t-p4-audit", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
        session.add(task)
        session.commit()
        yield session
    finally:
        session.close()


def test_ai_events_maintain_hash_chain_integrity(db_session):
    """INV-F10-AUDIT-12: Audit chain integrity passes after multiple AI lifecycle transitions."""
    task_id = "t-p4-audit"

    # Genesis transition
    TaskAuditLedger.record_transition(
        db_session, task_id, previous_state="NONE", new_state="QUEUED", reason="TASK_CREATED"
    )

    # AI events that trigger audit transitions
    AIEventService.stage_budget_reserved(
        db_session, request_id="req-1", task_id=task_id, budget_id="b-1", reserved_tokens=1000
    )
    AIEventService.stage_provider_failed(
        db_session,
        request_id="req-1",
        task_id=task_id,
        attempt_id="att-1",
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
        error_class="TIMEOUT",
    )
    AIEventService.stage_budget_committed(
        db_session,
        request_id="req-1",
        task_id=task_id,
        budget_id="b-1",
        actual_tokens=800,
        actual_cost_micro_units=2400,
    )

    # Verify cryptographic hash chain integrity using existing TaskAuditLedger API
    assert TaskAuditLedger.verify_chain_integrity(db_session, task_id) is True

    # Check history reconstruction
    history = TaskAuditLedger.reconstruct_history(db_session, task_id)
    assert len(history) == 4
    assert "AI_BUDGET_RESERVED" in history[1]["reason"]
    assert "AI_PROVIDER_FAILED" in history[2]["reason"]
    assert "AI_BUDGET_COMMITTED" in history[3]["reason"]


def test_audit_log_entries_have_valid_hash_pointers(db_session):
    """Each AI audit log entry links back to the previous event hash."""
    task_id = "t-p4-audit"

    AIEventService.stage_budget_reserved(
        db_session, request_id="req-2", task_id=task_id, budget_id="b-1", reserved_tokens=500
    )
    AIEventService.stage_budget_released(
        db_session, request_id="req-2", task_id=task_id, budget_id="b-1", released_tokens=500, reason="CANCELLED"
    )

    rows = db_session.scalars(
        select(TaskAuditLogModel)
        .where(TaskAuditLogModel.task_id == task_id)
        .order_by(TaskAuditLogModel.created_at.asc())
    ).all()

    assert len(rows) == 2
    # First row is genesis (no previous hash)
    first_row = [r for r in rows if r.previous_event_hash is None][0]
    second_row = [r for r in rows if r.previous_event_hash == first_row.event_hash][0]
    assert second_row.previous_event_hash == first_row.event_hash
