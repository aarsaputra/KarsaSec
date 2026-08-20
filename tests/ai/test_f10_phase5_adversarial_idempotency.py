"""Sprint F10 Phase 5 — Adversarial Idempotency Test Suite (INV-F10-IDEM-14).

Verifies idempotency guarantees across budget reservations, attempt registrations,
and event staging when operations are retried under simulated duplicate network delivery.
"""

from __future__ import annotations

from pathlib import Path
import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from karsasec.ai.events import AIEventService
from karsasec.ai.exceptions import AIRequestIdempotencyConflictError
from karsasec.ai.request import AIRequestStateService
from karsasec.persistence.models import (
    AIBudgetModel,
    Base,
    OutboxEventModel,
    TaskModel,
)


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    db_file = tmp_path / "idempotency_test.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url, connect_args={"timeout": 30.0})
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL;"))
        conn.commit()

    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    task = TaskModel(task_id="t-idem", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
    budget = AIBudgetModel(budget_id="b-idem", tenant_id="t1", token_limit=10_000)
    session.add_all([task, budget])
    session.commit()
    session.close()
    engine.dispose()
    return db_file


def test_duplicate_event_staging_returns_existing_event(temp_db_path: Path):
    """INV-F10-IDEM-14: Staging identical event with same deduplication key returns existing staged event."""
    db_url = f"sqlite:///{temp_db_path}"
    engine = create_engine(db_url)
    session = sessionmaker(bind=engine)()

    AIRequestStateService.create_request(session, "req-idem-1", "t-idem", "b-idem", "1" * 64, "2" * 64)
    session.commit()

    evt1 = AIEventService.stage_budget_reserved(session, "req-idem-1", "t-idem", "b-idem", 500)
    session.commit()

    evt2 = AIEventService.stage_budget_reserved(session, "req-idem-1", "t-idem", "b-idem", 500)
    session.commit()

    assert evt1.event_id == evt2.event_id

    events = session.scalars(select(OutboxEventModel).where(OutboxEventModel.aggregate_id == "req-idem-1")).all()
    assert len(events) == 1
    session.close()
    engine.dispose()


def test_duplicate_request_creation_idempotent_and_conflict_rejection(temp_db_path: Path):
    """Creating a request with duplicate request_id returns existing record if identical, or raises AIRequestIdempotencyConflictError if metadata conflicts."""
    db_url = f"sqlite:///{temp_db_path}"
    engine = create_engine(db_url)
    session = sessionmaker(bind=engine)()

    # Identical creation: idempotent success
    req1 = AIRequestStateService.create_request(session, "req-dup-1", "t-idem", "b-idem", "1" * 64, "2" * 64)
    session.commit()
    assert req1.status == "CREATED"

    req2 = AIRequestStateService.create_request(session, "req-dup-1", "t-idem", "b-idem", "1" * 64, "2" * 64)
    assert req2.request_id == req1.request_id

    # Conflicting creation: throws AIRequestIdempotencyConflictError
    with pytest.raises(AIRequestIdempotencyConflictError):
        AIRequestStateService.create_request(session, "req-dup-1", "t-idem", "b-idem", "3" * 64, "2" * 64)

    session.rollback()
    session.close()
    engine.dispose()
