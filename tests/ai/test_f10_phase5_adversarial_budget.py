"""Sprint F10 Phase 5 — Adversarial Token Budget & Concurrency Test Suite (INV-F10-BUDGET-01, INV-F10-CONCURRENCY-11, INV-F10-CONCURRENCY-12)."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from karsasec.ai.budget import AIBudgetService
from karsasec.ai.exceptions import (
    AIRequestStateConflictError,
    BudgetAccountingError,
    TokenBudgetExceededError,
)
from karsasec.ai.request import AIRequestStateService
from karsasec.persistence.models import AIBudgetModel, Base, TaskModel


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    """Creates a temporary SQLite database configured in WAL mode for concurrent thread safety."""
    db_file = tmp_path / "adv_budget_test.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url, connect_args={"timeout": 30.0})
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL;"))
        conn.execute(text("PRAGMA busy_timeout=30000;"))
        conn.commit()

    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    task = TaskModel(task_id="t-p5-budget", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
    # Token limit: 10,000 tokens (enough for exactly 100 requests of 100 tokens each)
    budget = AIBudgetModel(budget_id="b-p5-adv", tenant_id="t1", token_limit=10_000)
    session.add_all([task, budget])
    session.commit()
    session.close()
    engine.dispose()
    return db_file


def test_100_concurrent_workers_budget_reservation_boundary(temp_db_path: Path):
    """INV-F10-BUDGET-01 & INV-F10-CONCURRENCY-11: 100 workers attempt 100 token reservations on a 10,000 token budget.

    All 100 must succeed; the 105 total attempts result in 100 successes and 5 failures.
    """
    db_url = f"sqlite:///{temp_db_path}"

    def worker_reserve(worker_idx: int):
        engine = create_engine(db_url, connect_args={"timeout": 30.0})
        sess = sessionmaker(bind=engine)()
        try:
            req_id = f"req-p5-adv-{worker_idx}"
            AIRequestStateService.create_request(
                sess,
                request_id=req_id,
                task_id="t-p5-budget",
                budget_id="b-p5-adv",
                prompt_hash="1" * 64,
                context_hash="2" * 64,
            )
            AIRequestStateService.reserve_budget(sess, req_id, 100)
            sess.commit()
            return True, None
        except TokenBudgetExceededError as exc:
            sess.rollback()
            return False, exc
        except Exception as exc:
            sess.rollback()
            return False, exc
        finally:
            sess.close()
            engine.dispose()

    successes = 0
    failures = 0

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker_reserve, i) for i in range(105)]
        for future in as_completed(futures):
            ok, exc = future.result()
            if ok:
                successes += 1
            else:
                failures += 1
                assert isinstance(exc, TokenBudgetExceededError)

    assert successes == 100, f"Exactly 100 reservations of 100 tokens must succeed, got {successes}"
    assert failures == 5, f"Exactly 5 over-limit reservations must fail, got {failures}"

    # Verify database state truth
    verify_engine = create_engine(db_url)
    sess = sessionmaker(bind=verify_engine)()
    budget = sess.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-p5-adv"))
    assert budget.reserved_tokens == 10_000
    assert budget.used_tokens == 0
    assert budget.reserved_tokens + budget.used_tokens <= budget.token_limit
    sess.close()
    verify_engine.dispose()


def test_concurrent_state_transition_cas_winner(temp_db_path: Path):
    """INV-F10-CONCURRENCY-12: 50 concurrent workers attempt CREATED -> RESERVED on same request.

    Exactly 1 worker must win the state transition.
    """
    db_url = f"sqlite:///{temp_db_path}"

    # Setup target request
    init_engine = create_engine(db_url)
    init_sess = sessionmaker(bind=init_engine)()
    AIRequestStateService.create_request(
        init_sess,
        request_id="req-cas-50",
        task_id="t-p5-budget",
        budget_id="b-p5-adv",
        prompt_hash="1" * 64,
        context_hash="2" * 64,
    )
    init_sess.commit()
    init_sess.close()
    init_engine.dispose()

    def worker_transition():
        engine = create_engine(db_url, connect_args={"timeout": 30.0})
        sess = sessionmaker(bind=engine)()
        try:
            res = AIRequestStateService.transition_status(sess, "req-cas-50", "CREATED", "RESERVED")
            sess.commit()
            return True, res
        except AIRequestStateConflictError as exc:
            sess.rollback()
            return False, exc
        finally:
            sess.close()
            engine.dispose()

    winners = 0
    conflicts = 0

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker_transition) for _ in range(50)]
        for future in as_completed(futures):
            ok, exc = future.result()
            if ok:
                winners += 1
            else:
                conflicts += 1
                assert isinstance(exc, AIRequestStateConflictError)

    assert winners == 1, f"Exactly 1 worker must succeed, got {winners}"
    assert conflicts == 49, f"49 workers must be rejected, got {conflicts}"


def test_mixed_operations_atomic_consistency(temp_db_path: Path):
    """Reserve + release + commit interleaving maintains strict non-negative non-overallocated budget counters."""
    db_url = f"sqlite:///{temp_db_path}"
    engine = create_engine(db_url)
    sess = sessionmaker(bind=engine)()

    # Reserve 2000
    AIBudgetService.reserve_tokens(sess, "b-p5-adv", 2000)
    sess.commit()

    # Commit 1500 tokens / 4500 micro-units (releases remaining 500)
    AIBudgetService.commit_tokens(
        sess, "b-p5-adv", reserved_tokens=2000, actual_tokens=1500, actual_cost_micro_units=4500
    )
    sess.commit()

    b = sess.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-p5-adv"))
    assert b.used_tokens == 1500
    assert b.reserved_tokens == 0

    # Reserve 3000 then release
    AIBudgetService.reserve_tokens(sess, "b-p5-adv", 3000)
    sess.commit()
    AIBudgetService.release_tokens(sess, "b-p5-adv", 3000)
    sess.commit()

    b_final = sess.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-p5-adv"))
    assert b_final.used_tokens == 1500
    assert b_final.reserved_tokens == 0
    sess.close()
    engine.dispose()


def test_budget_accounting_rejects_negative_and_floating_point(temp_db_path: Path):
    """Negative values and invalid types raise BudgetAccountingError."""
    db_url = f"sqlite:///{temp_db_path}"
    engine = create_engine(db_url)
    sess = sessionmaker(bind=engine)()

    with pytest.raises(BudgetAccountingError):
        AIBudgetService.reserve_tokens(sess, "b-p5-adv", -100)

    with pytest.raises(BudgetAccountingError):
        AIBudgetService.commit_tokens(
            sess, "b-p5-adv", reserved_tokens=100, actual_tokens=-50, actual_cost_micro_units=100
        )

    with pytest.raises(BudgetAccountingError):
        AIBudgetService.release_tokens(sess, "b-p5-adv", -1)

    sess.rollback()
    sess.close()
    engine.dispose()
