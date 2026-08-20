"""Sprint F10 Phase 4 — Secret Isolation Tests (INV-F10-AUDIT-04, INV-F10-AUDIT-08)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from karsasec.ai.events import AIEventSecurityError, AIEventService
from karsasec.persistence.models import Base, TaskModel


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        task = TaskModel(task_id="t-p4-sec", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
        session.add(task)
        session.commit()
        yield session
    finally:
        session.close()


def test_api_keys_rejected_in_all_event_fields(db_session):
    """INV-F10-AUDIT-04: Credential strings (sk-..., Bearer ...) trigger AIEventSecurityError."""
    bad_secrets = [
        "sk-proj-supersecretkey12345",
        "Bearer eyJhbGciOiJIUzI1Ni...",
        "Authorization: Basic dXNlcjpwYXNz",
        "api_key=topsecret",
    ]

    for secret in bad_secrets:
        with pytest.raises(AIEventSecurityError):
            AIEventService.stage_budget_reserved(
                db_session, request_id=secret, task_id="t-p4-sec", budget_id="b-1", reserved_tokens=100
            )

        with pytest.raises(AIEventSecurityError):
            AIEventService.stage_provider_selected(
                db_session,
                request_id="req-1",
                task_id="t-p4-sec",
                attempt_id="att-1",
                attempt_number=1,
                provider_id=secret,
                model_id="gpt-4o",
                estimated_cost_micro_units=100,
            )


def test_raw_exception_strings_rejected_in_provider_failed(db_session):
    """INV-F10-AUDIT-08: Unbounded exception payloads trigger AIEventSecurityError."""
    unbounded_errors = [
        "Exception: Connection reset by peer at api.openai.com",
        "Traceback (most recent call last):\n  File 'app.py', line 12",
        "HTTP 500: Internal Server Error with key=sk-12345",
    ]

    for err in unbounded_errors:
        with pytest.raises(AIEventSecurityError):
            AIEventService.stage_provider_failed(
                db_session,
                request_id="req-1",
                task_id="t-p4-sec",
                attempt_id="att-1",
                attempt_number=1,
                provider_id="openai",
                model_id="gpt-4o",
                error_class=err,
            )


def test_invalid_hash_lengths_rejected(db_session):
    """Raw prompt/context text (not 64 hex chars) is rejected."""
    with pytest.raises(ValueError):
        AIEventService.stage_prompt_generated(
            db_session,
            request_id="req-1",
            task_id="t-p4-sec",
            prompt_hash="This is raw prompt text, not a sha256 hash!",
            context_hash="a" * 64,
        )
