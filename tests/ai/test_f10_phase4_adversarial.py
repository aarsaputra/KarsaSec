"""Sprint F10 Phase 4 — Adversarial Test Suite (INV-F10-AUDIT-01 through INV-F10-AUDIT-14)."""

import json
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from karsasec.ai.events import AIEventService
from karsasec.events.audit_ledger import TaskAuditLedger
from karsasec.persistence.models import AIBudgetModel, Base, TaskModel


@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        task = TaskModel(task_id="t-p4-adv", finding_id="f1", approval_token_id="tok1", fingerprint="a" * 64)
        budget = AIBudgetModel(budget_id="b-p4-adv", tenant_id="t1", token_limit=1_000_000)
        session.add_all([task, budget])
        session.commit()
        yield session
    finally:
        session.close()


def test_adv_budget_exhaustion_does_not_coexist_with_committed(db_session):
    """INV-F10-AUDIT-10: Budget exhaustion event and commit event are distinct."""
    req_id = "req-adv-1"

    evt_commit = AIEventService.stage_budget_committed(
        db_session, req_id, "t-p4-adv", "b-p4-adv", actual_tokens=500, actual_cost_micro_units=1500
    )
    evt_exhaust = AIEventService.stage_budget_exhausted(
        db_session, req_id, "t-p4-adv", "b-p4-adv", requested_tokens=10000, current_available=0
    )
    db_session.flush()

    assert evt_commit.event_type != evt_exhaust.event_type
    assert evt_commit.event_id != evt_exhaust.event_id


def test_adv_canonical_json_serialization_is_deterministic(db_session):
    """INV-F10-AUDIT-13: Event payload JSON keys are strictly sorted and separator-compact."""
    evt = AIEventService.stage_provider_selected(
        db_session,
        request_id="req-adv-2",
        task_id="t-p4-adv",
        attempt_id="att-1",
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
        estimated_cost_micro_units=5000,
    )

    # Verify key ordering in raw payload string using json.loads (Python 3.7+ preserves insertion order)
    parsed = json.loads(evt.payload)
    keys_in_raw = list(parsed.keys())
    sorted_keys = sorted(keys_in_raw)
    assert keys_in_raw == sorted_keys, "JSON payload keys must be strictly sorted"
    assert ", " not in evt.payload, "JSON payload separators must be compact (no trailing space)"


def test_adv_budget_accounting_is_never_mutated_by_events(db_session):
    """INV-F10-AUDIT-11: Event staging never modifies AIBudgetModel counters directly."""
    b_before = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-p4-adv"))
    used_before = b_before.used_tokens
    reserved_before = b_before.reserved_tokens

    AIEventService.stage_budget_reserved(db_session, "req-adv-3", "t-p4-adv", "b-p4-adv", 5000)
    AIEventService.stage_budget_committed(db_session, "req-adv-3", "t-p4-adv", "b-p4-adv", 5000, 15000)
    db_session.flush()

    b_after = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "b-p4-adv"))
    assert b_after.used_tokens == used_before
    assert b_after.reserved_tokens == reserved_before


def test_adv_audit_ledger_preserves_hash_chain_under_mixed_operations(db_session):
    """INV-F10-AUDIT-12: Hash chain is valid across multi-event sequence."""
    task_id = "t-p4-adv"

    AIEventService.stage_budget_reserved(db_session, "req-adv-4", task_id, "b-p4-adv", 1000, lease_version=1)
    AIEventService.stage_provider_failed(
        db_session, "req-adv-4", task_id, "att-1", 1, "openai", "gpt-4o", "RATE_LIMIT", lease_version=2
    )
    AIEventService.stage_budget_released(
        db_session, "req-adv-4", task_id, "b-p4-adv", 1000, "CANCELLED", lease_version=3
    )

    assert TaskAuditLedger.verify_chain_integrity(db_session, task_id) is True
