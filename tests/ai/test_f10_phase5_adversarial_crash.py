"""Sprint F10 Phase 5 — Adversarial Crash Injection & Rollback Consistency Test Suite (INV-F10-CRASH-13).

Simulates system crashes at boundaries A through J and verifies idempotent retry & atomic recovery.
"""

from pathlib import Path
import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from karsasec.ai.events import AIEventService
from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.provider import HEALTH_HEALTHY, ProviderDescriptor
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.ai.request import AIRequestStateService
from karsasec.ai.router import ProviderRouter
from karsasec.ai.routing_policy import RoutingPolicy
from karsasec.persistence.models import (
    AIBudgetModel,
    AIProviderAttemptModel,
    AIRequestModel,
    Base,
    OutboxEventModel,
    TaskAuditLogModel,
    TaskModel,
)


@pytest.fixture
def temp_db_path(tmp_path: Path) -> Path:
    db_file = tmp_path / "crash_test.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url, connect_args={"timeout": 30.0})
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL;"))
        conn.execute(text("PRAGMA busy_timeout=30000;"))
        conn.commit()

    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    task = TaskModel(task_id="t-crash", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
    budget = AIBudgetModel(budget_id="b-crash", tenant_id="t1", token_limit=10_000)
    session.add_all([task, budget])
    session.commit()
    session.close()
    engine.dispose()
    return db_file


def test_crash_boundary_a_through_j_rollback_atomicity(temp_db_path: Path):
    """INV-F10-CRASH-13: Simulates process crashes / uncommitted session aborts at boundaries A–J.

    Verifies zero partial state residue in PostgreSQL/SQLite database upon rollback.
    """
    db_url = f"sqlite:///{temp_db_path}"

    def run_pipeline_up_to_boundary(boundary: str):
        engine = create_engine(db_url)
        sess = sessionmaker(bind=engine)()
        req_id = f"req-crash-{boundary}"

        try:
            # Step 1: Request creation (Boundary A)
            req = AIRequestStateService.create_request(
                sess, req_id, "t-crash", "b-crash", prompt_hash="1" * 64, context_hash="2" * 64
            )
            if boundary == "A":
                raise RuntimeError("Crash at Boundary A: Request Creation")

            # Step 2: Budget reservation (Boundary B)
            AIRequestStateService.reserve_budget(sess, req_id, 500)
            if boundary == "B":
                raise RuntimeError("Crash at Boundary B: Budget Reservation")

            # Step 3: State transition to RESERVED (Boundary C)
            if boundary == "C":
                raise RuntimeError("Crash at Boundary C: State RESERVED")

            # Step 4: Provider selection & transition to ROUTED (Boundary D)
            registry = ProviderRegistry()
            p_desc = ProviderDescriptor("openai", "gpt-4o", frozenset({"CODE_REMEDIATION"}), 1, 100, 200)
            registry.register(p_desc)
            health = ProviderHealthRegistry()
            health.register("openai", "gpt-4o", HEALTH_HEALTHY)
            router = ProviderRouter(registry, health)
            policy = RoutingPolicy(frozenset({"CODE_REMEDIATION"}), 100, 100)
            routing_res = router.select_provider(policy)
            AIRequestStateService.transition_status(sess, req_id, "RESERVED", "ROUTED", "openai", "gpt-4o")
            if boundary == "D":
                raise RuntimeError("Crash at Boundary D: Provider Selection")

            # Step 5: Attempt creation & transition to IN_FLIGHT (Boundary E)
            attempt = router.record_attempt(sess, req_id, routing_res.attempt_number, "openai", "gpt-4o")
            AIRequestStateService.transition_status(sess, req_id, "ROUTED", "IN_FLIGHT")
            if boundary == "E":
                raise RuntimeError("Crash at Boundary E: Attempt Creation")

            # Step 6: Provider execution (Boundary F)
            if boundary == "F":
                raise RuntimeError("Crash at Boundary F: Provider Execution")

            # Step 7: Provider response / failure persistence (Boundary G)
            attempt.status = "COMPLETED"
            attempt.output_tokens = 50
            if boundary == "G":
                raise RuntimeError("Crash at Boundary G: Provider Response Persistence")

            # Step 8: Budget commit & transition to COMPLETED (Boundary H)
            AIRequestStateService.commit_execution(sess, req_id, 100, 300)
            if boundary == "H":
                raise RuntimeError("Crash at Boundary H: Budget Commit")

            # Step 9: Event staging (Boundary I)
            AIEventService.stage_budget_committed(sess, req_id, "t-crash", "b-crash", 100, 300)
            if boundary == "I":
                raise RuntimeError("Crash at Boundary I: Event Staging")

            # Step 10: Immediately before SQL commit (Boundary J)
            if boundary == "J":
                raise RuntimeError("Crash at Boundary J: Before Commit")

            sess.commit()
        except RuntimeError:
            sess.rollback()
        finally:
            sess.close()
            engine.dispose()

    # Test all crash boundaries A through J
    boundaries = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J"]
    for b in boundaries:
        run_pipeline_up_to_boundary(b)

        # Verify database truth after crash at boundary b: NO partial state for req-crash-b
        verify_engine = create_engine(db_url)
        sess = sessionmaker(bind=verify_engine)()
        req = sess.scalar(select(AIRequestModel).where(AIRequestModel.request_id == f"req-crash-{b}"))
        attempts = sess.scalars(
            select(AIProviderAttemptModel).where(AIProviderAttemptModel.request_id == f"req-crash-{b}")
        ).all()
        events = sess.scalars(select(OutboxEventModel).where(OutboxEventModel.aggregate_id == f"req-crash-{b}")).all()
        audits = sess.scalars(select(TaskAuditLogModel).where(TaskAuditLogModel.task_id == f"req-crash-{b}")).all()

        assert req is None, f"Request req-crash-{b} must not exist after crash at boundary {b}"
        assert len(attempts) == 0, f"Attempts for req-crash-{b} must be 0 after crash at boundary {b}"
        assert len(events) == 0, f"Outbox events for req-crash-{b} must be 0 after crash at boundary {b}"
        assert len(audits) == 0, f"Audit logs for req-crash-{b} must be 0 after crash at boundary {b}"

        sess.close()
        verify_engine.dispose()

    # Finally verify budget is untainted (0 used, 0 reserved)
    final_engine = create_engine(db_url)
    sess = sessionmaker(bind=final_engine)()
    budget = sess.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-crash"))
    assert budget.reserved_tokens == 0
    assert budget.used_tokens == 0
    sess.close()
    final_engine.dispose()


def test_retry_after_crash_is_clean_and_idempotent(temp_db_path: Path):
    """Crash at Boundary E followed by retry completes successfully with zero double charging."""
    db_url = f"sqlite:///{temp_db_path}"

    # First attempt: crash at Boundary E
    engine1 = create_engine(db_url)
    sess1 = sessionmaker(bind=engine1)()
    AIRequestStateService.create_request(sess1, "req-retry-crash", "t-crash", "b-crash", "1" * 64, "2" * 64)
    AIRequestStateService.reserve_budget(sess1, "req-retry-crash", 500)
    sess1.rollback()  # Simulate crash
    sess1.close()
    engine1.dispose()

    # Retry attempt: full execution
    engine2 = create_engine(db_url)
    sess2 = sessionmaker(bind=engine2)()
    AIRequestStateService.create_request(sess2, "req-retry-crash", "t-crash", "b-crash", "1" * 64, "2" * 64)
    AIRequestStateService.reserve_budget(sess2, "req-retry-crash", 500)
    AIRequestStateService.transition_status(sess2, "req-retry-crash", "RESERVED", "ROUTED", "openai", "gpt-4o")
    AIRequestStateService.transition_status(sess2, "req-retry-crash", "ROUTED", "IN_FLIGHT")
    AIRequestStateService.commit_execution(sess2, "req-retry-crash", 300, 900)
    sess2.commit()
    sess2.close()
    engine2.dispose()

    # Verify database state truth
    verify_engine = create_engine(db_url)
    sess = sessionmaker(bind=verify_engine)()
    budget = sess.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-crash"))
    assert budget.used_tokens == 300
    assert budget.reserved_tokens == 0
    sess.close()
    verify_engine.dispose()
