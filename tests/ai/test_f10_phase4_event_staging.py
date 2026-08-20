"""Sprint F10 Phase 4 — Event Staging Tests (INV-F10-AUDIT-01, INV-F10-AUDIT-05)."""

import json
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from karsasec.ai.events import (
    AIEventService,
    EVT_BUDGET_COMMITTED,
    EVT_BUDGET_EXHAUSTED,
    EVT_BUDGET_RELEASED,
    EVT_BUDGET_RESERVED,
    EVT_PROMPT_GENERATED,
    EVT_PROVIDER_FAILED,
    EVT_PROVIDER_SELECTED,
    EVT_RESPONSE_RECEIVED,
)
from karsasec.persistence.models import (
    AIBudgetModel,
    AIRequestModel,
    Base,
    TaskModel,
)


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        task = TaskModel(task_id="t-p4-stage", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
        budget = AIBudgetModel(budget_id="b-p4-stage", tenant_id="t1", token_limit=1_000_000)
        session.add_all([task, budget])
        session.commit()

        req = AIRequestModel(
            request_id="req-p4-stage",
            task_id="t-p4-stage",
            budget_id="b-p4-stage",
            prompt_hash="1" * 64,
            context_hash="2" * 64,
            status="CREATED",
        )
        session.add(req)
        session.commit()
        yield session
    finally:
        session.close()


def test_stage_budget_reserved(db_session):
    evt = AIEventService.stage_budget_reserved(
        db_session,
        request_id="req-p4-stage",
        task_id="t-p4-stage",
        budget_id="b-p4-stage",
        reserved_tokens=1000,
    )
    assert evt is not None
    assert evt.event_type == EVT_BUDGET_RESERVED
    assert evt.aggregate_id == "req-p4-stage"
    assert evt.aggregate_type == "AI_REQUEST"

    payload = json.loads(evt.payload)
    assert payload == {
        "budget_id": "b-p4-stage",
        "request_id": "req-p4-stage",
        "reserved_tokens": 1000,
        "task_id": "t-p4-stage",
    }


def test_stage_prompt_generated(db_session):
    evt = AIEventService.stage_prompt_generated(
        db_session,
        request_id="req-p4-stage",
        task_id="t-p4-stage",
        prompt_hash="a" * 64,
        context_hash="b" * 64,
    )
    assert evt is not None
    assert evt.event_type == EVT_PROMPT_GENERATED
    payload = json.loads(evt.payload)
    assert payload["prompt_hash"] == "a" * 64
    assert payload["context_hash"] == "b" * 64


def test_stage_provider_selected(db_session):
    evt = AIEventService.stage_provider_selected(
        db_session,
        request_id="req-p4-stage",
        task_id="t-p4-stage",
        attempt_id="att-1",
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
        estimated_cost_micro_units=5000,
    )
    assert evt is not None
    assert evt.event_type == EVT_PROVIDER_SELECTED
    payload = json.loads(evt.payload)
    assert payload["provider_id"] == "openai"
    assert payload["estimated_cost_micro_units"] == 5000


def test_stage_provider_failed(db_session):
    evt = AIEventService.stage_provider_failed(
        db_session,
        request_id="req-p4-stage",
        task_id="t-p4-stage",
        attempt_id="att-1",
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
        error_class="TIMEOUT",
    )
    assert evt is not None
    assert evt.event_type == EVT_PROVIDER_FAILED
    payload = json.loads(evt.payload)
    assert payload["error_class"] == "TIMEOUT"


def test_stage_response_received(db_session):
    evt = AIEventService.stage_response_received(
        db_session,
        request_id="req-p4-stage",
        task_id="t-p4-stage",
        attempt_id="att-1",
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
        input_tokens=1000,
        output_tokens=500,
        actual_cost_micro_units=4500,
    )
    assert evt is not None
    assert evt.event_type == EVT_RESPONSE_RECEIVED
    payload = json.loads(evt.payload)
    assert payload["input_tokens"] == 1000
    assert payload["output_tokens"] == 500


def test_stage_budget_committed(db_session):
    evt = AIEventService.stage_budget_committed(
        db_session,
        request_id="req-p4-stage",
        task_id="t-p4-stage",
        budget_id="b-p4-stage",
        actual_tokens=1500,
        actual_cost_micro_units=4500,
    )
    assert evt is not None
    assert evt.event_type == EVT_BUDGET_COMMITTED
    payload = json.loads(evt.payload)
    assert payload["actual_tokens"] == 1500


def test_stage_budget_released(db_session):
    evt = AIEventService.stage_budget_released(
        db_session,
        request_id="req-p4-stage",
        task_id="t-p4-stage",
        budget_id="b-p4-stage",
        released_tokens=1000,
        reason="CANCELLED",
    )
    assert evt is not None
    assert evt.event_type == EVT_BUDGET_RELEASED
    payload = json.loads(evt.payload)
    assert payload["released_tokens"] == 1000


def test_stage_budget_exhausted(db_session):
    evt = AIEventService.stage_budget_exhausted(
        db_session,
        request_id="req-p4-stage",
        task_id="t-p4-stage",
        budget_id="b-p4-stage",
        requested_tokens=10000,
        current_available=500,
    )
    assert evt is not None
    assert evt.event_type == EVT_BUDGET_EXHAUSTED
    payload = json.loads(evt.payload)
    assert payload["requested_tokens"] == 10000
    assert payload["current_available"] == 500
