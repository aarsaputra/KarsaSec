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
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Sequence,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import UUID
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

    __table_args__ = (
        Index("ix_tasks_state_fingerprint", "state", "fingerprint"),
        Index("ix_tasks_state_lease", "state", "lease_started_at"),
        Index("ix_tasks_assigned_worker", "assigned_worker_id"),
    )


class WorkerModel(Base):
    """Authoritative representation of registered worker nodes.

    INV-F5-06: worker_id has UNIQUE / PRIMARY KEY constraint to prevent duplicate overwrite.
    INV-F5-07: heartbeat_sequence tracks monotonic heartbeat counter for replay rejection.
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
    heartbeat_sequence: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_heartbeat: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=_utcnow,
        onupdate=_utcnow,
    )

    __table_args__ = (
        Index("ix_workers_status_heartbeat", "status", "last_heartbeat"),
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
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="PENDING", index=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("ix_outbox_events_status_created", "status", "created_at"),
    )


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

    __table_args__ = (
        UniqueConstraint("receipt_fingerprint", name="uq_receipts_fingerprint"),
    )


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

    __table_args__ = (
        Index("ix_audit_events_task_created", "task_id", "created_at"),
    )

