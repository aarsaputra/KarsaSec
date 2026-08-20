"""Sprint F10 Phase 2 — Idempotency & Crash Recovery Tests (INV-F10-IDEMPOTENCY-04, INV-F10-IDEMPOTENCY-05, INV-F10-CRASH-13)."""

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from karsasec.ai.exceptions import (
    AIRequestIdempotencyConflictError,
)
from karsasec.ai.request import AIRequestStateService
from karsasec.persistence.models import AIBudgetModel, Base, TaskModel


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        task = TaskModel(task_id="t-idem", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
        budget = AIBudgetModel(budget_id="b-idem", tenant_id="t1", token_limit=100_000)
        session.add_all([task, budget])
        session.commit()
        yield session
    finally:
        session.close()


def test_request_creation_idempotency_same_metadata(db_session: Session):
    """Creating request with same request_id and identical metadata returns existing record."""
    req1 = AIRequestStateService.create_request(
        db_session,
        request_id="req-idem-1",
        task_id="t-idem",
        budget_id="b-idem",
        prompt_hash="1" * 64,
        context_hash="2" * 64,
    )
    db_session.commit()

    req2 = AIRequestStateService.create_request(
        db_session,
        request_id="req-idem-1",
        task_id="t-idem",
        budget_id="b-idem",
        prompt_hash="1" * 64,
        context_hash="2" * 64,
    )
    assert req1.request_id == req2.request_id


def test_request_creation_conflict_on_metadata_mismatch(db_session: Session):
    """13. Request ID conflict: same request_id with different payload metadata raises AIRequestIdempotencyConflictError."""
    AIRequestStateService.create_request(
        db_session,
        request_id="req-conflict-1",
        task_id="t-idem",
        budget_id="b-idem",
        prompt_hash="1" * 64,
        context_hash="2" * 64,
    )
    db_session.commit()

    # Mismatched prompt_hash
    with pytest.raises(AIRequestIdempotencyConflictError):
        AIRequestStateService.create_request(
            db_session,
            request_id="req-conflict-1",
            task_id="t-idem",
            budget_id="b-idem",
            prompt_hash="9" * 64,  # Different!
            context_hash="2" * 64,
        )


def test_double_reservation_idempotent_no_double_charge(db_session: Session):
    """5. Double reservation: same request_id attempts reservation twice -> no double charge on budget."""
    AIRequestStateService.create_request(
        db_session,
        request_id="req-dres-1",
        task_id="t-idem",
        budget_id="b-idem",
        prompt_hash="1" * 64,
        context_hash="2" * 64,
    )
    db_session.commit()

    # First reservation
    AIRequestStateService.reserve_budget(db_session, "req-dres-1", 10_000)
    db_session.commit()

    budget1 = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-idem"))
    assert budget1.reserved_tokens == 10_000

    # Second reservation attempt with same request_id & token amount
    AIRequestStateService.reserve_budget(db_session, "req-dres-1", 10_000)
    db_session.commit()

    # Budget reserved_tokens MUST still be 10,000 (NOT 20,000!)
    budget2 = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-idem"))
    assert budget2.reserved_tokens == 10_000


def test_crash_retry_recovery_simulation(db_session: Session):
    """12. Crash retry simulation: worker crashes after reservation; retry with same request_id succeeds safely."""
    # Step 1: Create request & reserve budget
    req = AIRequestStateService.create_request(
        db_session,
        request_id="req-crash-1",
        task_id="t-idem",
        budget_id="b-idem",
        prompt_hash="a" * 64,
        context_hash="b" * 64,
    )
    AIRequestStateService.reserve_budget(db_session, req.request_id, 15_000)
    db_session.commit()

    # Step 2: Simulate worker crash (close session, discard memory objects)
    db_session.close()

    # Step 3: Worker restarts and retries request creation & reservation
    engine = db_session.get_bind()
    new_session = sessionmaker(bind=engine)()
    try:
        recovered_req = AIRequestStateService.create_request(
            new_session,
            request_id="req-crash-1",
            task_id="t-idem",
            budget_id="b-idem",
            prompt_hash="a" * 64,
            context_hash="b" * 64,
        )
        assert recovered_req.status == "RESERVED"

        # Retry reserve_budget
        res = AIRequestStateService.reserve_budget(new_session, "req-crash-1", 15_000)
        assert res.reserved_tokens == 15_000

        budget = new_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-idem"))
        assert budget.reserved_tokens == 15_000
    finally:
        new_session.close()


def test_commit_execution_idempotency(db_session: Session):
    """Committing completion twice with identical figures is idempotent."""
    req = AIRequestStateService.create_request(
        db_session,
        request_id="req-commit-idem",
        task_id="t-idem",
        budget_id="b-idem",
        prompt_hash="1" * 64,
        context_hash="2" * 64,
    )
    AIRequestStateService.reserve_budget(db_session, req.request_id, 10_000)
    AIRequestStateService.transition_status(db_session, req.request_id, "RESERVED", "ROUTED")
    AIRequestStateService.transition_status(db_session, req.request_id, "ROUTED", "IN_FLIGHT")
    db_session.commit()

    # First commit
    AIRequestStateService.commit_execution(
        db_session,
        request_id="req-commit-idem",
        actual_tokens=8_000,
        actual_cost_micro_units=500_000,
        selected_provider_id="openai",
        selected_model_id="gpt-4o",
    )
    db_session.commit()

    # Second commit with identical figures
    res2 = AIRequestStateService.commit_execution(
        db_session,
        request_id="req-commit-idem",
        actual_tokens=8_000,
        actual_cost_micro_units=500_000,
        selected_provider_id="openai",
        selected_model_id="gpt-4o",
    )
    assert res2.status == "COMPLETED"
    assert res2.committed_tokens == 8_000


def test_release_reservation_idempotency(db_session: Session):
    """Releasing reservation twice returns existing cancelled/failed request without double releasing tokens."""
    req = AIRequestStateService.create_request(
        db_session,
        request_id="req-rel-idem",
        task_id="t-idem",
        budget_id="b-idem",
        prompt_hash="1" * 64,
        context_hash="2" * 64,
    )
    AIRequestStateService.reserve_budget(db_session, req.request_id, 5_000)
    db_session.commit()

    # First release
    AIRequestStateService.release_reservation(db_session, "req-rel-idem", target_status="CANCELLED")
    db_session.commit()

    b1 = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-idem"))
    assert b1.reserved_tokens == 0

    # Second release attempt
    res2 = AIRequestStateService.release_reservation(db_session, "req-rel-idem", target_status="CANCELLED")
    assert res2.status == "CANCELLED"

    b2 = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-idem"))
    assert b2.reserved_tokens == 0
