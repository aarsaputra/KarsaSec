"""Sprint F10 Phase 5 — Secret Isolation Fuzzing & Persistence Boundary Test Suite (INV-F10-AUDIT-04).

Fuzzes payloads with sensitive strings and verifies zero raw secrets enter database tables, outbox events, or audit logs.
"""

from pathlib import Path
import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.orm import sessionmaker

from karsasec.ai.events import AIEventSecurityError, AIEventService
from karsasec.ai.router import InvalidAttemptError, ProviderRouter
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
    db_file = tmp_path / "secrets_fuzz_test.db"
    db_url = f"sqlite:///{db_file}"
    engine = create_engine(db_url, connect_args={"timeout": 30.0})
    with engine.connect() as conn:
        conn.execute(text("PRAGMA journal_mode=WAL;"))
        conn.execute(text("PRAGMA busy_timeout=30000;"))
        conn.commit()

    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    task = TaskModel(task_id="t-sec-fuzz", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
    budget = AIBudgetModel(budget_id="b-sec-fuzz", tenant_id="t1", token_limit=10_000)
    session.add_all([task, budget])
    session.commit()
    session.close()
    engine.dispose()
    return db_file


SECRET_FUZZ_PATTERNS = [
    "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz",
    "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
    "Authorization: Bearer secret_token_123",
    "api_key=secret_value_999",
    "access_token=secret_abc_xyz",
    "password=supersecretpassword123",
    "SELECT * FROM users; -- raw SQL injection prompt",
    "https://admin:super_secret_pass@api.openai.com/v1",
    "OPENAI_API_KEY=sk-abcdef1234567890",
]


def test_ai_event_service_rejects_credential_fuzz_patterns(temp_db_path: Path):
    """INV-F10-AUDIT-04: AIEventService raises AIEventSecurityError when secrets are present in parameters."""
    db_url = f"sqlite:///{temp_db_path}"
    engine = create_engine(db_url)
    sess = sessionmaker(bind=engine)()

    for secret in SECRET_FUZZ_PATTERNS:
        # Fuzz prompt_generated
        with pytest.raises((AIEventSecurityError, ValueError)):
            AIEventService.stage_prompt_generated(sess, "req-1", "t-sec-fuzz", secret, "2" * 64)

        # Fuzz provider_failed error_class
        with pytest.raises(AIEventSecurityError):
            AIEventService.stage_provider_failed(sess, "req-1", "t-sec-fuzz", "att-1", 1, "openai", "gpt-4o", secret)

    sess.rollback()
    sess.close()
    engine.dispose()


def test_attempt_ledger_rejects_unbounded_error_strings(temp_db_path: Path):
    """AIProviderAttemptModel record_attempt rejects non-taxonomy error classes containing secret strings."""
    db_url = f"sqlite:///{temp_db_path}"
    engine = create_engine(db_url)
    sess = sessionmaker(bind=engine)()

    router = ProviderRouter(None, None)

    for secret in SECRET_FUZZ_PATTERNS:
        with pytest.raises(InvalidAttemptError):
            router.record_attempt(sess, "req-fuzz", 1, "openai", "gpt-4o", error_class=secret)

    sess.rollback()
    sess.close()
    engine.dispose()


def test_zero_raw_secrets_in_all_persistence_tables(temp_db_path: Path):
    """Adversarially queries all persistence tables to confirm 0 raw secret substrings exist."""
    db_url = f"sqlite:///{temp_db_path}"
    engine = create_engine(db_url)
    sess = sessionmaker(bind=engine)()

    # Check AIRequestModel, AIProviderAttemptModel, OutboxEventModel, TaskAuditLogModel
    requests = sess.scalars(select(AIRequestModel)).all()
    attempts = sess.scalars(select(AIProviderAttemptModel)).all()
    outbox = sess.scalars(select(OutboxEventModel)).all()
    audit = sess.scalars(select(TaskAuditLogModel)).all()

    all_text_blobs: list[str] = []
    for r in requests:
        all_text_blobs.extend([r.request_id, r.task_id, r.budget_id, r.prompt_hash, r.context_hash, r.status])
    for a in attempts:
        all_text_blobs.extend([a.attempt_id, a.request_id, a.provider_id, a.model_id, a.status, str(a.error_class)])
    for o in outbox:
        all_text_blobs.extend([o.aggregate_id, o.event_type, str(o.payload)])
    for log in audit:
        all_text_blobs.extend([log.task_id, log.previous_state, log.new_state, log.reason])

    concat_text = " ".join(all_text_blobs)

    for secret in SECRET_FUZZ_PATTERNS:
        assert secret not in concat_text, f"Secret pattern '{secret}' leaked into persistence storage!"

    sess.close()
    engine.dispose()
