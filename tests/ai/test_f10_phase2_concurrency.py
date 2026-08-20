"""Sprint F10 Phase 2 — Concurrency & Adversarial Race Condition Tests (INV-F10-CONCURRENCY-11, INV-F10-CONCURRENCY-12)."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from karsasec.ai.exceptions import (
    AIRequestStateConflictError,
    TokenBudgetExceededError,
)
from karsasec.ai.request import AIRequestStateService
from karsasec.persistence.models import AIBudgetModel, Base, TaskModel


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    """Creates a temporary SQLite database configured in WAL mode for concurrent thread safety."""
    db_file = tmp_path / "concurrency_test.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url, connect_args={"timeout": 30.0})
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL;"))
        conn.execute(text("PRAGMA busy_timeout=30000;"))
        conn.commit()

    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    task = TaskModel(task_id="t-conc", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
    # Token limit: 100,000 tokens (enough for exactly 100 requests of 1,000 tokens each)
    budget = AIBudgetModel(budget_id="b-conc", tenant_id="t-conc", token_limit=100_000)
    session.add_all([task, budget])
    session.commit()
    session.close()
    engine.dispose()
    return db_file


def test_concurrent_reservation_no_lost_update(temp_db_path: Path):
    """4. Concurrent reservation (INV-F10-CONCURRENCY-11):

    Given token_limit = 100,000 and request_tokens = 1,000.
    Execute 120 concurrent attempts. Exactly 100 must succeed, 20 must raise TokenBudgetExceededError.
    Final invariant: reserved_tokens == 100,000 (used_tokens + reserved_tokens <= token_limit).
    """
    db_url = f"sqlite:///{temp_db_path}"

    def worker_attempt(index: int):
        # Each thread gets its own engine & connection pool
        engine = create_engine(db_url, connect_args={"timeout": 30.0})
        session = sessionmaker(bind=engine)()
        try:
            req_id = f"req-conc-{index}"
            AIRequestStateService.create_request(
                session,
                request_id=req_id,
                task_id="t-conc",
                budget_id="b-conc",
                prompt_hash="1" * 64,
                context_hash="2" * 64,
            )
            AIRequestStateService.reserve_budget(session, req_id, 1_000)
            session.commit()
            return True, None
        except TokenBudgetExceededError as exc:
            session.rollback()
            return False, exc
        except Exception as exc:
            session.rollback()
            return False, exc
        finally:
            session.close()
            engine.dispose()

    successes = 0
    failures = 0

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker_attempt, i) for i in range(120)]
        for future in as_completed(futures):
            ok, exc = future.result()
            if ok:
                successes += 1
            else:
                failures += 1
                assert isinstance(exc, TokenBudgetExceededError)

    assert successes == 100
    assert failures == 20

    verify_engine = create_engine(db_url)
    session = sessionmaker(bind=verify_engine)()
    budget = session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-conc"))
    assert budget.reserved_tokens == 100_000
    assert budget.used_tokens == 0
    assert budget.reserved_tokens + budget.used_tokens <= budget.token_limit
    session.close()
    verify_engine.dispose()


def test_single_winner_concurrent_state_transition(temp_db_path: Path):
    """11. Concurrent state transition (INV-F10-CONCURRENCY-12):

    50 concurrent workers attempt CREATED -> RESERVED on the EXACT same request_id.
    Exactly 1 worker succeeds in making the status transition.
    The remaining 49 workers receive AIRequestStateConflictError or idempotent retry.
    """
    db_url = f"sqlite:///{temp_db_path}"

    # Setup single shared request
    setup_engine = create_engine(db_url)
    session = sessionmaker(bind=setup_engine)()
    AIRequestStateService.create_request(
        session,
        request_id="req-single-winner",
        task_id="t-conc",
        budget_id="b-conc",
        prompt_hash="a" * 64,
        context_hash="b" * 64,
    )
    session.commit()
    session.close()
    setup_engine.dispose()

    def transition_worker():
        engine = create_engine(db_url, connect_args={"timeout": 30.0})
        s = sessionmaker(bind=engine)()
        try:
            # Low-level conditional transition attempt
            AIRequestStateService.transition_status(
                s,
                request_id="req-single-winner",
                expected_status="CREATED",
                new_status="RESERVED",
            )
            s.commit()
            return True, None
        except AIRequestStateConflictError as exc:
            s.rollback()
            return False, exc
        finally:
            s.close()
            engine.dispose()

    winners = 0
    conflicts = 0

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(transition_worker) for _ in range(50)]
        for future in as_completed(futures):
            ok, exc = future.result()
            if ok:
                winners += 1
            else:
                conflicts += 1
                assert isinstance(exc, AIRequestStateConflictError)

    assert winners == 1
    assert conflicts == 49
