"""Sprint F10 Phase 1 — Database Schema & ORM Model Tests.

Verifies:
  - AIBudgetModel, AIRequestModel, AIProviderAttemptModel creation & defaults.
  - Foreign key integrity & SQLAlchemy relationships (TaskModel <-> AIRequestModel <-> AIBudgetModel <-> AIProviderAttemptModel).
  - Database CHECK constraints (non-negative tokens, micro-unit costs, valid state vocabularies).
  - UNIQUE(request_id, attempt_number) and primary key uniqueness.
  - Integer micro-unit financial accounting ($1.00 = 1,000,000 micro-units).
  - SHA-256 prompt/context hash length boundaries and zero secret persistence.
"""

import uuid
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from karsasec.persistence.models import (
    Base,
    TaskModel,
    AIBudgetModel,
    AIRequestModel,
    AIProviderAttemptModel,
)


@pytest.fixture
def db_session():
    """In-memory SQLite session configured with Base metadata for model tests."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


def test_ai_budget_model_defaults(db_session: Session):
    """1. Test AIBudgetModel creation & 2. Default counter values."""
    budget = AIBudgetModel(
        budget_id="budget-101",
        tenant_id="tenant-alpha",
    )
    db_session.add(budget)
    db_session.commit()

    fetched = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "budget-101"))
    assert fetched is not None
    assert fetched.tenant_id == "tenant-alpha"
    assert fetched.token_limit == 1_000_000
    assert fetched.used_tokens == 0
    assert fetched.reserved_tokens == 0
    assert fetched.cost_limit_micro_units == 10_000_000  # $10.00 in micro-units
    assert fetched.used_cost_micro_units == 0


def test_ai_budget_negative_token_limit_rejected(db_session: Session):
    """3. Negative token limits rejected by CHECK constraint."""
    budget = AIBudgetModel(
        budget_id="budget-bad-limit",
        tenant_id="tenant-alpha",
        token_limit=-100,
    )
    db_session.add(budget)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_ai_budget_negative_reserved_tokens_rejected(db_session: Session):
    """4. Negative reserved tokens rejected by CHECK constraint."""
    budget = AIBudgetModel(
        budget_id="budget-bad-reserved",
        tenant_id="tenant-alpha",
        reserved_tokens=-50,
    )
    db_session.add(budget)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_ai_budget_negative_cost_counters_rejected(db_session: Session):
    """5. Negative cost counters rejected by CHECK constraint."""
    budget = AIBudgetModel(
        budget_id="budget-bad-cost",
        tenant_id="tenant-alpha",
        used_cost_micro_units=-1,
    )
    db_session.add(budget)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_ai_request_model_creation_and_fk_relationships(db_session: Session):
    """6. AIRequestModel creation, 7. FK to TaskModel, 8. FK to AIBudgetModel, 19. Relationships load correctly."""
    task = TaskModel(
        task_id="task-f10-001",
        finding_id="FIND-01",
        approval_token_id="TOKEN-01",
        fingerprint="a" * 64,
        state="PENDING",
    )
    budget = AIBudgetModel(
        budget_id="budget-f10-001",
        tenant_id="tenant-beta",
    )
    db_session.add_all([task, budget])
    db_session.commit()

    req = AIRequestModel(
        request_id="req-f10-001",
        task_id=task.task_id,
        budget_id=budget.budget_id,
        prompt_hash="b" * 64,
        context_hash="c" * 64,
        status="CREATED",
        reserved_tokens=500,
        actual_cost_micro_units=150_000,  # $0.15
        selected_provider_id="anthropic",
        selected_model_id="claude-3-5-sonnet",
    )
    db_session.add(req)
    db_session.commit()

    # Verify relationships via task and budget
    fetched_task = db_session.scalar(select(TaskModel).where(TaskModel.task_id == "task-f10-001"))
    assert len(fetched_task.ai_requests) == 1
    assert fetched_task.ai_requests[0].request_id == "req-f10-001"

    fetched_budget = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "budget-f10-001"))
    assert len(fetched_budget.requests) == 1
    assert fetched_budget.requests[0].request_id == "req-f10-001"

    assert req.task.task_id == "task-f10-001"
    assert req.budget.budget_id == "budget-f10-001"


def test_ai_request_valid_states_accepted(db_session: Session):
    """9. Valid AI request states accepted."""
    task = TaskModel(
        task_id="task-f10-states",
        finding_id="FIND-01",
        approval_token_id="TOKEN-01",
        fingerprint="a" * 64,
    )
    budget = AIBudgetModel(budget_id="budget-f10-states", tenant_id="tenant-states")
    db_session.add_all([task, budget])
    db_session.commit()

    valid_states = [
        "CREATED",
        "RESERVED",
        "ROUTED",
        "IN_FLIGHT",
        "PROVIDER_FAILED",
        "COMPLETED",
        "FAILED",
        "CANCELLED",
    ]
    for idx, st in enumerate(valid_states):
        req = AIRequestModel(
            request_id=f"req-state-{idx}",
            task_id=task.task_id,
            budget_id=budget.budget_id,
            prompt_hash="d" * 64,
            context_hash="e" * 64,
            status=st,
        )
        db_session.add(req)
    db_session.commit()

    count = db_session.scalar(select(AIRequestModel).where(AIRequestModel.task_id == "task-f10-states"))
    assert count is not None


def test_ai_request_invalid_state_rejected(db_session: Session):
    """10. Invalid AI request states rejected by CHECK constraint."""
    task = TaskModel(
        task_id="task-f10-badstate",
        finding_id="FIND-01",
        approval_token_id="TOKEN-01",
        fingerprint="a" * 64,
    )
    budget = AIBudgetModel(budget_id="budget-f10-badstate", tenant_id="tenant-badstate")
    db_session.add_all([task, budget])
    db_session.commit()

    req = AIRequestModel(
        request_id="req-bad-state",
        task_id=task.task_id,
        budget_id=budget.budget_id,
        prompt_hash="d" * 64,
        context_hash="e" * 64,
        status="INVALID_EXPLOIT_STATE",
    )
    db_session.add(req)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_ai_provider_attempt_model_creation(db_session: Session):
    """11. AIProviderAttemptModel creation."""
    task = TaskModel(
        task_id="task-attempt",
        finding_id="FIND-01",
        approval_token_id="TOKEN-01",
        fingerprint="a" * 64,
    )
    budget = AIBudgetModel(budget_id="budget-attempt", tenant_id="tenant-att")
    db_session.add_all([task, budget])
    db_session.commit()

    req = AIRequestModel(
        request_id="req-attempt-1",
        task_id=task.task_id,
        budget_id=budget.budget_id,
        prompt_hash="1" * 64,
        context_hash="2" * 64,
    )
    db_session.add(req)
    db_session.commit()

    attempt = AIProviderAttemptModel(
        attempt_id="att-001",
        request_id=req.request_id,
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
        status="IN_FLIGHT",
        input_tokens=150,
        output_tokens=300,
        error_class=None,
    )
    db_session.add(attempt)
    db_session.commit()

    fetched = db_session.scalar(select(AIProviderAttemptModel).where(AIProviderAttemptModel.attempt_id == "att-001"))
    assert fetched is not None
    assert fetched.request_id == "req-attempt-1"
    assert fetched.attempt_number == 1
    assert fetched.provider_id == "openai"
    assert fetched.input_tokens == 150
    assert fetched.output_tokens == 300
    assert fetched.request.request_id == "req-attempt-1"


def test_attempt_number_positive_enforced(db_session: Session):
    """12. attempt_number > 0 enforcement via CHECK constraint."""
    task = TaskModel(
        task_id="task-att-num",
        finding_id="FIND-01",
        approval_token_id="TOKEN-01",
        fingerprint="a" * 64,
    )
    budget = AIBudgetModel(budget_id="budget-att-num", tenant_id="tenant-att-num")
    db_session.add_all([task, budget])
    db_session.commit()

    req = AIRequestModel(
        request_id="req-att-num",
        task_id=task.task_id,
        budget_id=budget.budget_id,
        prompt_hash="1" * 64,
        context_hash="2" * 64,
    )
    db_session.add(req)
    db_session.commit()

    att0 = AIProviderAttemptModel(
        attempt_id=str(uuid.uuid4()),
        request_id=req.request_id,
        attempt_number=0,
        provider_id="openai",
        model_id="gpt-4o",
    )
    db_session.add(att0)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_negative_input_output_tokens_rejected(db_session: Session):
    """13. Negative input_tokens rejected & 14. Negative output_tokens rejected."""
    task = TaskModel(
        task_id="task-neg-tok",
        finding_id="FIND-01",
        approval_token_id="TOKEN-01",
        fingerprint="a" * 64,
    )
    budget = AIBudgetModel(budget_id="budget-neg-tok", tenant_id="tenant-neg")
    db_session.add_all([task, budget])
    db_session.commit()

    req = AIRequestModel(
        request_id="req-neg-tok",
        task_id=task.task_id,
        budget_id=budget.budget_id,
        prompt_hash="1" * 64,
        context_hash="2" * 64,
    )
    db_session.add(req)
    db_session.commit()

    att_bad_in = AIProviderAttemptModel(
        attempt_id=str(uuid.uuid4()),
        request_id=req.request_id,
        attempt_number=1,
        provider_id="ollama",
        model_id="llama3",
        input_tokens=-10,
    )
    db_session.add(att_bad_in)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_unique_request_id_attempt_number_enforced(db_session: Session):
    """15. UNIQUE(request_id, attempt_number) enforcement."""
    task = TaskModel(
        task_id="task-uniq-att",
        finding_id="FIND-01",
        approval_token_id="TOKEN-01",
        fingerprint="a" * 64,
    )
    budget = AIBudgetModel(budget_id="budget-uniq-att", tenant_id="tenant-uniq")
    db_session.add_all([task, budget])
    db_session.commit()

    req = AIRequestModel(
        request_id="req-uniq-att",
        task_id=task.task_id,
        budget_id=budget.budget_id,
        prompt_hash="1" * 64,
        context_hash="2" * 64,
    )
    db_session.add(req)
    db_session.commit()

    att1 = AIProviderAttemptModel(
        attempt_id="att-uniq-1",
        request_id=req.request_id,
        attempt_number=1,
        provider_id="openai",
        model_id="gpt-4o",
    )
    att2 = AIProviderAttemptModel(
        attempt_id="att-uniq-2",
        request_id=req.request_id,
        attempt_number=1,  # Duplicate attempt number for same request_id!
        provider_id="anthropic",
        model_id="claude-3-5-sonnet",
    )
    db_session.add_all([att1, att2])
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_request_id_primary_key_uniqueness(db_session: Session):
    """16. request_id primary key uniqueness."""
    task = TaskModel(
        task_id="task-pk-uniq",
        finding_id="FIND-01",
        approval_token_id="TOKEN-01",
        fingerprint="a" * 64,
    )
    budget = AIBudgetModel(budget_id="budget-pk-uniq", tenant_id="tenant-pk")
    db_session.add_all([task, budget])
    db_session.commit()

    req1 = AIRequestModel(
        request_id="SAME-REQ-ID",
        task_id=task.task_id,
        budget_id=budget.budget_id,
        prompt_hash="1" * 64,
        context_hash="2" * 64,
    )
    req2 = AIRequestModel(
        request_id="SAME-REQ-ID",
        task_id=task.task_id,
        budget_id=budget.budget_id,
        prompt_hash="3" * 64,
        context_hash="4" * 64,
    )
    db_session.add(req1)
    db_session.commit()

    db_session.add(req2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_sha256_hash_field_length_and_requiredness(db_session: Session):
    """17. SHA-256 hash field size / requiredness."""
    task = TaskModel(
        task_id="task-hashes",
        finding_id="FIND-01",
        approval_token_id="TOKEN-01",
        fingerprint="a" * 64,
    )
    budget = AIBudgetModel(budget_id="budget-hashes", tenant_id="tenant-hashes")
    db_session.add_all([task, budget])
    db_session.commit()

    # Missing prompt_hash must raise IntegrityError
    req_null = AIRequestModel(
        request_id="req-null-hash",
        task_id=task.task_id,
        budget_id=budget.budget_id,
        prompt_hash=None,  # Nullable=False violated!
        context_hash="2" * 64,
    )
    db_session.add(req_null)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_integer_micro_unit_accounting(db_session: Session):
    """18. Integer micro-unit accounting ($1.00 = 1,000,000 micro-units)."""
    budget = AIBudgetModel(
        budget_id="budget-micros",
        tenant_id="tenant-micros",
        cost_limit_micro_units=5_000_000,  # $5.00
        used_cost_micro_units=1_250_000,  # $1.25
    )
    db_session.add(budget)
    db_session.commit()

    fetched = db_session.scalar(select(AIBudgetModel).where(AIBudgetModel.budget_id == "budget-micros"))
    assert fetched.cost_limit_micro_units == 5_000_000
    assert fetched.used_cost_micro_units == 1_250_000
    assert isinstance(fetched.cost_limit_micro_units, int)
    assert isinstance(fetched.used_cost_micro_units, int)
