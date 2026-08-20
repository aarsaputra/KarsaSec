"""Sprint F10 Phase 2 — Request State Machine Tests (INV-F10-STATE-06, INV-F10-STATE-07)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from karsasec.ai.exceptions import (
    AIRequestNotFoundError,
    AIRequestStateConflictError,
    InvalidAIRequestStateTransitionError,
)
from karsasec.ai.request import AIRequestStateService
from karsasec.ai.state_machine import (
    STATE_CANCELLED,
    STATE_COMPLETED,
    STATE_CREATED,
    STATE_FAILED,
    STATE_IN_FLIGHT,
    STATE_PROVIDER_FAILED,
    STATE_RESERVED,
    STATE_ROUTED,
    validate_state_transition,
)
from karsasec.persistence.models import AIBudgetModel, Base, TaskModel


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        task = TaskModel(task_id="t-sm", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
        budget = AIBudgetModel(budget_id="b-sm", tenant_id="t1")
        session.add_all([task, budget])
        session.commit()
        yield session
    finally:
        session.close()


def test_invalid_state_transition_rejected():
    """9. Invalid state transition: CREATED -> COMPLETED raises InvalidAIRequestStateTransitionError."""
    with pytest.raises(InvalidAIRequestStateTransitionError):
        validate_state_transition(STATE_CREATED, STATE_COMPLETED)


def test_valid_state_transitions_allowed():
    """10. Test every allowed state transition across the lifecycle."""
    valid_pairs = [
        (STATE_CREATED, STATE_RESERVED),
        (STATE_CREATED, STATE_CANCELLED),
        (STATE_CREATED, STATE_FAILED),
        (STATE_RESERVED, STATE_ROUTED),
        (STATE_RESERVED, STATE_CANCELLED),
        (STATE_RESERVED, STATE_FAILED),
        (STATE_ROUTED, STATE_IN_FLIGHT),
        (STATE_ROUTED, STATE_PROVIDER_FAILED),
        (STATE_ROUTED, STATE_FAILED),
        (STATE_ROUTED, STATE_CANCELLED),
        (STATE_IN_FLIGHT, STATE_COMPLETED),
        (STATE_IN_FLIGHT, STATE_PROVIDER_FAILED),
        (STATE_IN_FLIGHT, STATE_FAILED),
        (STATE_IN_FLIGHT, STATE_CANCELLED),
        (STATE_PROVIDER_FAILED, STATE_ROUTED),
        (STATE_PROVIDER_FAILED, STATE_FAILED),
        (STATE_PROVIDER_FAILED, STATE_CANCELLED),
    ]
    for current, target in valid_pairs:
        validate_state_transition(current, target)


def test_terminal_state_mutations_prohibited():
    """Terminal states (COMPLETED, FAILED, CANCELLED) cannot transition anywhere."""
    terminals = [STATE_COMPLETED, STATE_FAILED, STATE_CANCELLED]
    targets = [STATE_CREATED, STATE_RESERVED, STATE_ROUTED, STATE_IN_FLIGHT, STATE_PROVIDER_FAILED]

    for term in terminals:
        for tgt in targets:
            with pytest.raises(InvalidAIRequestStateTransitionError):
                validate_state_transition(term, tgt)


def test_self_transitions_prohibited():
    """Self transitions (e.g. RESERVED -> RESERVED) are prohibited."""
    states = [STATE_CREATED, STATE_RESERVED, STATE_ROUTED, STATE_IN_FLIGHT]
    for st in states:
        with pytest.raises(InvalidAIRequestStateTransitionError):
            validate_state_transition(st, st)


def test_db_conditional_state_transition(db_session: Session):
    """Conditional SQL update checks expected_status and raises conflict if mismatched."""
    req = AIRequestStateService.create_request(
        db_session,
        request_id="req-cond-1",
        task_id="t-sm",
        budget_id="b-sm",
        prompt_hash="1" * 64,
        context_hash="2" * 64,
    )
    AIRequestStateService.reserve_budget(db_session, req.request_id, 1000)
    db_session.commit()

    # Successful transition: RESERVED -> ROUTED
    AIRequestStateService.transition_status(
        db_session,
        request_id="req-cond-1",
        expected_status=STATE_RESERVED,
        new_status=STATE_ROUTED,
    )
    db_session.commit()

    # Mismatched expected status: active status is now ROUTED, but caller expects RESERVED -> raise AIRequestStateConflictError
    with pytest.raises(AIRequestStateConflictError):
        AIRequestStateService.transition_status(
            db_session,
            request_id="req-cond-1",
            expected_status=STATE_RESERVED,
            new_status=STATE_CANCELLED,
        )

    # Valid transition: ROUTED -> IN_FLIGHT
    AIRequestStateService.transition_status(
        db_session,
        request_id="req-cond-1",
        expected_status=STATE_ROUTED,
        new_status=STATE_IN_FLIGHT,
    )
    db_session.commit()

    # Active status is now IN_FLIGHT. If caller expects ROUTED -> conflict!
    with pytest.raises(AIRequestStateConflictError):
        AIRequestStateService.transition_status(
            db_session,
            request_id="req-cond-1",
            expected_status=STATE_ROUTED,
            new_status=STATE_CANCELLED,
        )


def test_transition_non_existent_request_raises_not_found(db_session: Session):
    """Transitioning non-existent request raises AIRequestNotFoundError."""
    with pytest.raises(AIRequestNotFoundError):
        AIRequestStateService.transition_status(
            db_session,
            request_id="ghost-request",
            expected_status=STATE_CREATED,
            new_status=STATE_RESERVED,
        )
