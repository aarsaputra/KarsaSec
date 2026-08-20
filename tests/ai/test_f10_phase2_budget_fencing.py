"""Sprint F10 Phase 2 — Budget Fencing Tests (INV-F10-BUDGET-01, INV-F10-BUDGET-02, INV-F10-BUDGET-03)."""

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from karsasec.ai.budget import AIBudgetService
from karsasec.ai.exceptions import (
    BudgetAccountingError,
    TokenBudgetExceededError,
)
from karsasec.persistence.models import AIBudgetModel, Base


@pytest.fixture
def db_session():
    """In-memory SQLite session configured with Base metadata for budget tests."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


def test_basic_token_reservation(db_session: Session):
    """1. Basic reservation: reserve 10,000 tokens."""
    budget = AIBudgetModel(budget_id="b-1", tenant_id="t-1", token_limit=50_000)
    db_session.add(budget)
    db_session.commit()

    AIBudgetService.reserve_tokens(db_session, "b-1", 10_000)
    db_session.commit()

    fetched = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-1"))
    assert fetched.reserved_tokens == 10_000
    assert fetched.used_tokens == 0


def test_budget_exhaustion_rejected(db_session: Session):
    """2. Budget exhaustion: attempt reservation beyond limit fails closed."""
    budget = AIBudgetModel(budget_id="b-ex", tenant_id="t-1", token_limit=10_000)
    db_session.add(budget)
    db_session.commit()

    with pytest.raises(TokenBudgetExceededError):
        AIBudgetService.reserve_tokens(db_session, "b-ex", 10_001)

    db_session.rollback()

    fetched = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-ex"))
    assert fetched.reserved_tokens == 0
    assert fetched.used_tokens == 0


def test_exact_budget_boundary(db_session: Session):
    """3. Exact boundary: reserve exact limit succeeds, 1 more fails."""
    budget = AIBudgetModel(budget_id="b-bound", tenant_id="t-1", token_limit=100_000)
    db_session.add(budget)
    db_session.commit()

    AIBudgetService.reserve_tokens(db_session, "b-bound", 100_000)
    db_session.commit()

    fetched = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-bound"))
    assert fetched.reserved_tokens == 100_000

    with pytest.raises(TokenBudgetExceededError):
        AIBudgetService.reserve_tokens(db_session, "b-bound", 1)


def test_commit_tokens_and_cost(db_session: Session):
    """6. Commit: reserve 10,000, commit 8,000 tokens & cost -> reserved decreases, used increases."""
    budget = AIBudgetModel(
        budget_id="b-commit",
        tenant_id="t-1",
        token_limit=100_000,
        cost_limit_micro_units=5_000_000,  # $5.00
    )
    db_session.add(budget)
    db_session.commit()

    AIBudgetService.reserve_tokens(db_session, "b-commit", 10_000)
    db_session.commit()

    AIBudgetService.commit_tokens(
        db_session,
        budget_id="b-commit",
        reserved_tokens=10_000,
        actual_tokens=8_000,
        actual_cost_micro_units=1_200_000,  # $1.20
    )
    db_session.commit()

    fetched = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-commit"))
    assert fetched.reserved_tokens == 0
    assert fetched.used_tokens == 8_000
    assert fetched.used_cost_micro_units == 1_200_000


def test_release_tokens(db_session: Session):
    """7. Release: reserve 10,000, release -> reserved returns to 0."""
    budget = AIBudgetModel(budget_id="b-rel", tenant_id="t-1", token_limit=100_000)
    db_session.add(budget)
    db_session.commit()

    AIBudgetService.reserve_tokens(db_session, "b-rel", 10_000)
    db_session.commit()

    AIBudgetService.release_tokens(db_session, "b-rel", 10_000)
    db_session.commit()

    fetched = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-rel"))
    assert fetched.reserved_tokens == 0


def test_double_release_fails_or_noop(db_session: Session):
    """8. Double release: second release when reserved_tokens < release_amount raises BudgetAccountingError."""
    budget = AIBudgetModel(budget_id="b-drel", tenant_id="t-1", token_limit=100_000)
    db_session.add(budget)
    db_session.commit()

    AIBudgetService.reserve_tokens(db_session, "b-drel", 10_000)
    db_session.commit()

    AIBudgetService.release_tokens(db_session, "b-drel", 10_000)
    db_session.commit()

    with pytest.raises(BudgetAccountingError):
        AIBudgetService.release_tokens(db_session, "b-drel", 10_000)


def test_negative_values_rejected(db_session: Session):
    """14. Negative values rejected before SQL mutation."""
    budget = AIBudgetModel(budget_id="b-neg", tenant_id="t-1", token_limit=100_000)
    db_session.add(budget)
    db_session.commit()

    with pytest.raises(BudgetAccountingError):
        AIBudgetService.reserve_tokens(db_session, "b-neg", -500)

    with pytest.raises(BudgetAccountingError):
        AIBudgetService.release_tokens(db_session, "b-neg", -100)

    with pytest.raises(BudgetAccountingError):
        AIBudgetService.commit_tokens(
            db_session, "b-neg", reserved_tokens=10, actual_tokens=-5, actual_cost_micro_units=0
        )


def test_large_integer_bigint_accounting(db_session: Session):
    """15. Large BigInteger values support enterprise scale."""
    budget = AIBudgetModel(
        budget_id="b-big",
        tenant_id="t-big",
        token_limit=1_000_000_000_000,
        cost_limit_micro_units=100_000_000_000,  # $100,000.00
    )
    db_session.add(budget)
    db_session.commit()

    AIBudgetService.reserve_tokens(db_session, "b-big", 500_000_000_000)
    db_session.commit()

    fetched = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-big"))
    assert fetched.reserved_tokens == 500_000_000_000


def test_transaction_rollback_reverts_reservation(db_session: Session):
    """16. Transaction rollback reverts budget reservation cleanly."""
    budget = AIBudgetModel(budget_id="b-rb", tenant_id="t-1", token_limit=100_000)
    db_session.add(budget)
    db_session.commit()

    AIBudgetService.reserve_tokens(db_session, "b-rb", 25_000)
    # Explicit rollback without commit
    db_session.rollback()

    fetched = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-rb"))
    assert fetched.reserved_tokens == 0
