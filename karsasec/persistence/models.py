"""SQLAlchemy 2.x ORM Models for KarsaSec Sprint F5 PostgreSQL Authoritative Engine.

Tables:
  - tasks           : Persistent task state, lease version, assignment, and metadata.
  - workers         : Worker nodes, authentication hashes, and heartbeat sequence tracking.
  - recovery_leases : Durable cluster recovery leases and fencing tokens.
  - outbox_events   : Transactional outbox ledger for queue/database consistency.
  - receipts        : Immutable verification receipts.
  - audit_events    : Append-only audit ledger.

Privacy Invariants (R7-R9):
  - No source code, unified_diff, patch, credential, token, or api_key columns.
  - Only metadata, hashes, fingerprints, and status values are stored.
"""

from __future__ import annotations

import uuid
from datetime import datetime, UTC

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    Sequence,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


from sqlalchemy.types import TypeDecorator, CHAR
from sqlalchemy.dialects.postgresql import UUID as PG_UUID


class GUID(TypeDecorator):
    """Platform-independent GUID type for PostgreSQL and SQLite compatibility."""

    impl = CHAR
    cache_ok = True

    def load_dialect_impl(self, dialect):
        if dialect.name == "postgresql":
            return dialect.type_descriptor(PG_UUID(as_uuid=True))
        else:
            return dialect.type_descriptor(CHAR(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        return str(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return value
        if isinstance(value, uuid.UUID):
            return value
        return uuid.UUID(str(value))


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Shared declarative base for all KarsaSec persistence models."""

    pass


# PostgreSQL sequence for durable monotonic recovery fencing tokens across restarts
recovery_fencing_token_seq = Sequence("recovery_fencing_token_seq", metadata=Base.metadata)


class TaskModel(Base):
    """Persistent representation of a RemediationTask in PostgreSQL.

    Privacy: No source code, diffs, credentials, or tokens stored.
    The `token` field from the domain model is NOT persisted.
    """

    __tablename__ = "tasks"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
    )
    task_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(256), nullable=False)
    approval_token_id: Mapped[str] = mapped_column(String(256), nullable=False)
    # fingerprint: canonical SHA-256 over payload (not a secret)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    lease_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=300)
    # F5 Distributed Authority Fields:
    lease_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    assigned_worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    assigned_worker_fencing_token: Mapped[int | None] = mapped_column(Integer, nullable=True)
    recovery_fencing_token: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    # lease_started_at: wall-clock UTC for persistence
    lease_started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    receipt_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    receipt_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    # L7: exclusively set from RTPValidator output — never by router or worker directly
    security_verification_status: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    audit_events: Mapped[list[AuditEventModel]] = relationship(
        "AuditEventModel", back_populates="task", cascade="all, delete-orphan"
    )
    ai_requests: Mapped[list[AIRequestModel]] = relationship(
        "AIRequestModel", back_populates="task", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("ix_tasks_state_fingerprint", "state", "fingerprint"),
        Index("ix_tasks_state_lease", "state", "lease_started_at"),
        Index("ix_tasks_assigned_worker", "assigned_worker_id"),
    )


class WorkerModel(Base):
    """Authoritative representation of registered worker nodes.

    INV-F5-06: worker_id has UNIQUE / PRIMARY KEY constraint to prevent duplicate overwrite.
    INV-F5-07: heartbeat_sequence tracks monotonic heartbeat counter for replay rejection.
    INV-F6-DRAIN-01: status in WorkerModel (ONLINE, DRAINING, DRAINED, FENCED, OFFLINE) is authoritative.
    INV-F6-SHUTDOWN-05: fencing_token is incremented on fence/timeout to invalidate worker mutation authority.
    """

    __tablename__ = "workers"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
    )
    worker_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    auth_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    hostname: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ONLINE")
    fencing_token: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    heartbeat_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    __table_args__ = (Index("ix_workers_status_heartbeat", "status", "last_heartbeat"),)


class DeadLetterEventModel(Base):
    """Forensic Dead-Letter Queue event ledger.

    INV-F6-DLQ-01: Exactly one terminal task produces at most one forensic DLQ record.
    INV-F6-DLQ-02: Created transactionally atomic with task FAILED state mutation.
    INV-F6-DLQ-04: UNIQUE(task_id) enforces idempotency under concurrent execution.
    INV-F6-DLQ-05: Strict byte bounds (sanitized_error_message <= 8KB, payload_json <= 32KB).
    """

    __tablename__ = "dead_letter_events"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
    )
    event_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    task_id: Mapped[str] = mapped_column(String(128), nullable=False, unique=True, index=True)
    correlation_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    reason: Mapped[str] = mapped_column(String(256), nullable=False, default="EXHAUSTED")
    attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False)
    payload_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_type: Mapped[str | None] = mapped_column(String(256), nullable=True)
    sanitized_error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        UniqueConstraint("task_id", name="uq_dead_letter_task_id"),
        Index("ix_dead_letter_events_reason", "reason", "created_at"),
    )


class RecoveryLeaseModel(Base):
    """Authoritative durable cluster recovery lease.

    INV-F5-04: Durable recovery lease record stored in PostgreSQL.
    INV-F5-03: fencing_token is strictly monotonic across node restarts.
    """

    __tablename__ = "recovery_leases"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
    )
    lease_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    owner_id: Mapped[str] = mapped_column(String(128), nullable=False)
    fencing_token: Mapped[int] = mapped_column(Integer, nullable=False)
    acquired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="ACTIVE")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    __table_args__ = (
        Index("ix_recovery_leases_status", "status", "expires_at"),
        UniqueConstraint("fencing_token", name="uq_recovery_leases_token"),
    )


class OutboxEventModel(Base):
    """Transactional Outbox ledger for queue/database consistency.

    INV-F5-09: Created atomically within task state mutation transaction.
    INV-F5-10: Idempotent publishing by event_id prevents duplicate logical execution.
    INV-F8-PUBLISH-04: Publisher lease fencing with FOR UPDATE SKIP LOCKED.
    """

    __tablename__ = "outbox_events"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
    )
    event_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    aggregate_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    aggregate_type: Mapped[str] = mapped_column(String(64), nullable=False, default="TASK")
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    deduplication_key: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True, index=True)
    aggregate_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING", index=True)
    claimed_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    publisher_lease_token: Mapped[str | None] = mapped_column(String(128), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (Index("ix_outbox_events_status_created", "status", "created_at"),)


class TaskAuditLogModel(Base):
    """Tamper-Evident Task Audit Ledger for Sprint F8 (INV-F8-AUDIT-05).

    Stores an append-only, cryptographic hash-chained audit log of all task state transitions.
    """

    __tablename__ = "task_audit_log"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
    )
    task_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    previous_state: Mapped[str] = mapped_column(String(32), nullable=False)
    new_state: Mapped[str] = mapped_column(String(32), nullable=False)
    worker_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    fencing_token: Mapped[int | None] = mapped_column(Integer, nullable=True)
    lease_version: Mapped[int] = mapped_column(Integer, nullable=False)
    reason: Mapped[str] = mapped_column(String(256), nullable=False, default="")
    previous_event_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    event_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (Index("ix_task_audit_log_task_created", "task_id", "created_at"),)


class ReceiptModel(Base):
    """Immutable Verification Receipt stored in PostgreSQL.

    Privacy: No source code, diffs, credentials, raw patch content.
    Contains only fingerprints, status metadata, and receipt identifiers.
    """

    __tablename__ = "receipts"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
    )
    receipt_id: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    transaction_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    finding_id: Mapped[str] = mapped_column(String(256), nullable=False)
    rule_id: Mapped[str] = mapped_column(String(256), nullable=False)
    receipt_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1.0")
    # L7: exclusively derived by RTPValidator — never set by worker or API layer
    integrity_status: Mapped[str] = mapped_column(String(32), nullable=False)
    security_verification_status: Mapped[str] = mapped_column(String(64), nullable=False)
    verification_run_id: Mapped[str | None] = mapped_column(String(256), nullable=True)
    matching_findings_count: Mapped[int] = mapped_column(Integer, nullable=False, default=-1)
    proposal_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    provenance_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    ledger_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    receipt_fingerprint: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (UniqueConstraint("receipt_fingerprint", name="uq_receipts_fingerprint"),)


class AuditEventModel(Base):
    """Append-only audit event ledger.

    Immutability constraints:
      - No UPDATE or DELETE operations are allowed on this table (enforced in repository).
      - Each event is a permanent, cryptographically identifiable record.

    Privacy: No source code, diffs, credentials in `details` field.
    """

    __tablename__ = "audit_events"

    id: Mapped[str] = mapped_column(
        String(36),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
    )
    task_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("tasks.task_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    # details: structured JSON metadata — no source code, diffs, or credentials
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    task: Mapped[TaskModel] = relationship("TaskModel", back_populates="audit_events")

    __table_args__ = (Index("ix_audit_events_task_created", "task_id", "created_at"),)


class RecoveryCheckpointModel(Base):
    """Recovery Checkpoint and Snapshot Ledger for Sprint F9.

    Stores versioned snapshot payload, PITR boundary markers, recovery lease fencing tokens,
    and Merkle-lite composite root hashes (SHA256(snapshot_hash + audit_head_hash + outbox_head_hash)).
    """

    __tablename__ = "recovery_checkpoints"

    checkpoint_id: Mapped[str] = mapped_column(String(128), primary_key=True, nullable=False)
    snapshot_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=1, index=True)
    snapshot_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    root_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    snapshot_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    audit_head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    outbox_head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    recovery_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    recovery_lease_token: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_audit_id: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_lease_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_outbox_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    audit_chain_head: Mapped[str] = mapped_column(String(64), nullable=False, default="GENESIS")
    snapshot_json: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (Index("ix_recovery_checkpoints_gen_created", "snapshot_generation", "created_at"),)


class AIBudgetModel(Base):
    """Authoritative Tenant Token & Cost Budget Ledger for Sprint F10 (INV-F10-BUDGET-01).

    Enforces non-negative token & financial counters via database CHECK constraints.
    Financial values are strictly stored in integer micro-units ($1.00 = 1,000,000 micro-units).
    """

    __tablename__ = "ai_budgets"

    budget_id: Mapped[str] = mapped_column(String(128), primary_key=True, nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    token_limit: Mapped[int] = mapped_column(BigInteger, nullable=False, default=1_000_000)
    used_tokens: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    reserved_tokens: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    cost_limit_micro_units: Mapped[int] = mapped_column(BigInteger, nullable=False, default=10_000_000)
    used_cost_micro_units: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    requests: Mapped[list[AIRequestModel]] = relationship(
        "AIRequestModel", back_populates="budget", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint("token_limit >= 0", name="ck_ai_budgets_token_limit_positive"),
        CheckConstraint("used_tokens >= 0", name="ck_ai_budgets_used_tokens_positive"),
        CheckConstraint("reserved_tokens >= 0", name="ck_ai_budgets_reserved_tokens_positive"),
        CheckConstraint("cost_limit_micro_units >= 0", name="ck_ai_budgets_cost_limit_positive"),
        CheckConstraint("used_cost_micro_units >= 0", name="ck_ai_budgets_used_cost_positive"),
    )


class AIRequestModel(Base):
    """Durable AI Request & Idempotency Boundary Ledger for Sprint F10 (INV-F10-CONCURRENCY-02).

    Primary key `request_id` acts as the durable identity boundary for crash-safe execution.
    `prompt_hash` and `context_hash` store SHA-256 digests (never raw prompts, credentials, or secrets).
    """

    __tablename__ = "ai_requests"

    request_id: Mapped[str] = mapped_column(String(128), primary_key=True, nullable=False)
    task_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("tasks.task_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    budget_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("ai_budgets.budget_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    prompt_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    context_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="CREATED", index=True)
    reserved_tokens: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    committed_tokens: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    actual_cost_micro_units: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    selected_provider_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    selected_model_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    winner_provider: Mapped[str | None] = mapped_column(String(64), nullable=True)
    winner_claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    task: Mapped[TaskModel] = relationship("TaskModel", back_populates="ai_requests")
    budget: Mapped[AIBudgetModel] = relationship("AIBudgetModel", back_populates="requests")
    attempts: Mapped[list[AIProviderAttemptModel]] = relationship(
        "AIProviderAttemptModel", back_populates="request", cascade="all, delete-orphan"
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('CREATED', 'RESERVED', 'ROUTED', 'IN_FLIGHT', 'PROVIDER_FAILED', 'COMPLETED', 'FAILED', 'CANCELLED')",
            name="ck_ai_requests_status_valid",
        ),
        CheckConstraint("reserved_tokens >= 0", name="ck_ai_requests_reserved_tokens_positive"),
        CheckConstraint("committed_tokens >= 0", name="ck_ai_requests_committed_tokens_positive"),
        CheckConstraint("actual_cost_micro_units >= 0", name="ck_ai_requests_actual_cost_positive"),
    )


class AIProviderAttemptModel(Base):
    """Detailed Provider Call Attempt Ledger for Sprint F10 (INV-F10-FAILOVER-04).

    Guarantees UNIQUE(request_id, attempt_number) to prevent duplicate provider attempt execution.
    `error_class` stores bounded classification strings (never raw exception payloads or API credentials).
    """

    __tablename__ = "ai_provider_attempts"

    attempt_id: Mapped[str] = mapped_column(String(128), primary_key=True, nullable=False)
    request_id: Mapped[str] = mapped_column(
        String(128),
        ForeignKey("ai_requests.request_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    model_id: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="IN_FLIGHT", index=True)
    input_tokens: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    output_tokens: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    error_class: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    request: Mapped[AIRequestModel] = relationship("AIRequestModel", back_populates="attempts")

    __table_args__ = (
        UniqueConstraint("request_id", "attempt_number", name="uq_ai_provider_attempts_req_num"),
        CheckConstraint("attempt_number > 0", name="ck_ai_attempts_number_positive"),
        CheckConstraint("input_tokens >= 0", name="ck_ai_attempts_input_tokens_positive"),
        CheckConstraint("output_tokens >= 0", name="ck_ai_attempts_output_tokens_positive"),
        CheckConstraint(
            "status IN ('IN_FLIGHT', 'COMPLETED', 'FAILED', 'CANCELLED')",
            name="ck_ai_attempts_status_valid",
        ),
    )


class AICircuitStateModel(Base):
    """Authoritative Persistent Circuit Breaker State Ledger for Sprint F11.6 & F11.7 (INV-F11-CIRCUIT-06/07, INV-F11-CONSENSUS-18).

    Guarantees UNIQUE(provider_id, model_id) and persists circuit state, failure windows, cooldown reasons,
    and state_version for optimistic concurrency locking across distributed workers.
    """

    __tablename__ = "ai_circuit_states"

    id: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
    )
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    model_id: Mapped[str] = mapped_column(String(64), nullable=False)
    state: Mapped[str] = mapped_column(String(32), nullable=False, default="CLOSED")
    state_version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    success_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failures_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    opened_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    cooldown_until: Mapped[float | None] = mapped_column(Float, nullable=True)
    cooldown_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    probe_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    __table_args__ = (
        UniqueConstraint("provider_id", "model_id", name="uq_ai_circuit_provider_model"),
        CheckConstraint("state IN ('CLOSED', 'OPEN', 'HALF_OPEN')", name="ck_ai_circuit_state_valid"),
    )


class AIProviderRateLimitModel(Base):
    """Database-authoritative Rate Limiter Token Bucket Ledger for Sprint F11.6 (INV-F11-RATELIMIT-08/09/13).

    Guarantees UNIQUE(provider_id, model_id) and separates request bucket (RPM) from token bucket (TPM).
    Uses DB locking / atomic updates to guarantee cluster-wide token acquisition atomicity.
    """

    __tablename__ = "ai_provider_rate_limits"

    id: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        nullable=False,
    )
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    model_id: Mapped[str] = mapped_column(String(64), nullable=False)

    # Request Bucket (RPM)
    requests_remaining: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    max_requests: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    rpm_refill_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    last_request_refill_at: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Token Bucket (TPM)
    tokens_remaining: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    max_tokens: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    tpm_refill_rate: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    last_token_refill_at: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)

    # Cooldown Tracking
    cooldown_until: Mapped[float | None] = mapped_column(Float, nullable=True)
    cooldown_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    __table_args__ = (
        UniqueConstraint("provider_id", "model_id", name="uq_ai_rate_limit_provider_model"),
        CheckConstraint("requests_remaining >= 0", name="ck_ai_rate_limit_requests_pos"),
        CheckConstraint("tokens_remaining >= 0", name="ck_ai_rate_limit_tokens_pos"),
    )
