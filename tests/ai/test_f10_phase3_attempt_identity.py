"""Sprint F10 Phase 3 — Attempt Identity & Ledger Tests (INV-F10-ROUTER-08, INV-F10-ROUTER-10).

Tests:
11. Attempt numbers remain unique
16. Concurrent routing does not produce duplicate attempt numbers
"""

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from karsasec.ai.provider import ATTEMPT_ERROR_TIMEOUT, HEALTH_HEALTHY, ProviderDescriptor
from karsasec.ai.router import InvalidAttemptError, ProviderRouter
from karsasec.ai.health import ProviderHealthRegistry
from karsasec.ai.provider_registry import ProviderRegistry
from karsasec.persistence.models import AIBudgetModel, AIProviderAttemptModel, Base, TaskModel, AIRequestModel


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        task = TaskModel(task_id="t-att", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
        budget = AIBudgetModel(budget_id="b-att", tenant_id="t1", token_limit=1_000_000)
        session.add_all([task, budget])
        session.commit()
        # Create a minimal AIRequestModel
        req = AIRequestModel(
            request_id="req-att-1",
            task_id="t-att",
            budget_id="b-att",
            prompt_hash="1" * 64,
            context_hash="2" * 64,
            status="RESERVED",
        )
        session.add(req)
        session.commit()
        yield session
    finally:
        session.close()


def _make_router() -> ProviderRouter:
    registry = ProviderRegistry()
    health_reg = ProviderHealthRegistry()
    desc = ProviderDescriptor("openai", "gpt-4o", frozenset({"chat"}), 10, 1000, 3000, HEALTH_HEALTHY)
    registry.register(desc)
    health_reg.register("openai", "gpt-4o", HEALTH_HEALTHY)
    return ProviderRouter(registry, health_reg)


def test_attempt_record_created(db_session: Session):
    """record_attempt creates an AIProviderAttemptModel record in the database."""
    router = _make_router()
    attempt = router.record_attempt(
        db_session,
        request_id="req-att-1",
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
        status="IN_FLIGHT",
        input_tokens=1000,
        output_tokens=0,
    )
    db_session.commit()

    fetched = db_session.scalar(
        select(AIProviderAttemptModel).where(AIProviderAttemptModel.attempt_id == attempt.attempt_id)
    )
    assert fetched is not None
    assert fetched.request_id == "req-att-1"
    assert fetched.attempt_number == 1
    assert fetched.provider_id == "openai"
    assert fetched.status == "IN_FLIGHT"


def test_unique_attempt_numbers_enforced(db_session: Session):
    """11. Duplicate attempt_number for the same request_id raises InvalidAttemptError."""
    router = _make_router()

    router.record_attempt(
        db_session,
        "req-att-1",
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
    )
    db_session.commit()

    with pytest.raises(InvalidAttemptError):
        router.record_attempt(
            db_session,
            "req-att-1",
            attempt_number=1,  # Duplicate!
            provider_id="openai",
            model_id="gpt-4o",
        )


def test_attempt_failure_recording(db_session: Session):
    """record_attempt_failure updates attempt status to FAILED with bounded error class."""
    router = _make_router()
    attempt = router.record_attempt(
        db_session,
        "req-att-1",
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
    )
    db_session.commit()

    router.record_attempt_failure(db_session, attempt, error_class=ATTEMPT_ERROR_TIMEOUT)
    db_session.commit()

    fetched = db_session.scalar(
        select(AIProviderAttemptModel).where(AIProviderAttemptModel.attempt_id == attempt.attempt_id)
    )
    assert fetched.status == "FAILED"
    assert fetched.error_class == "TIMEOUT"


def test_invalid_error_class_rejected(db_session: Session):
    """Attempting to record unbounded error class raises InvalidAttemptError."""
    router = _make_router()
    attempt = router.record_attempt(
        db_session,
        "req-att-1",
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
    )
    db_session.commit()

    with pytest.raises(InvalidAttemptError):
        router.record_attempt_failure(db_session, attempt, error_class="raw exception message here!")


def test_attempt_numbers_increment_across_failovers(db_session: Session):
    """10. Attempt numbers must increment monotonically across failover attempts."""
    router = _make_router()

    for i in range(1, 4):
        router.record_attempt(
            db_session,
            "req-att-1",
            attempt_number=i,
            provider_id="openai",
            model_id="gpt-4o",
        )
    db_session.commit()

    attempts = db_session.scalars(
        select(AIProviderAttemptModel)
        .where(AIProviderAttemptModel.request_id == "req-att-1")
        .order_by(AIProviderAttemptModel.attempt_number)
    ).all()
    assert [a.attempt_number for a in attempts] == [1, 2, 3]


def test_error_class_in_attempt_record_must_be_bounded(db_session: Session):
    """15. API credentials and raw exception payloads must not enter the attempt ledger."""
    router = _make_router()
    raw_secret_like_strings = [
        "sk-supersecretapikey",
        "Bearer eyJhbGci...",
        "Exception: Connection refused to api.openai.com",
    ]
    for bad_error in raw_secret_like_strings:
        with pytest.raises(InvalidAttemptError):
            router.record_attempt(
                db_session,
                "req-att-1",
                attempt_number=1,
                provider_id="openai",
                model_id="gpt-4o",
                error_class=bad_error,
            )
