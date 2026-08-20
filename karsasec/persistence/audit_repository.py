"""PostgresAuditRepository — Non-Blocking Append-Only Audit Event Ledger for Sprint F6A.

Enforces immutability: no UPDATE or DELETE is allowed on audit_events.
Each event is a permanent, append-only record.

Non-Blocking Security Invariant:
  Audit writing operations are executed inside safe try/except wrappers.
  If an audit persistence fails (e.g. DB temporary issue), the exception is captured
  and logged via default_logger without aborting or rolling back primary CAS state transitions.

Privacy:
  - 'details' field stores only metadata (state, attempt count, timestamps).
  - No source code, diffs, credentials, or tokens in event records.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from contextlib import contextmanager
from enum import StrEnum
from collections.abc import Generator

from sqlalchemy import select
from sqlalchemy.orm import Session

from karsasec.persistence.db import DatabaseSessionFactory, get_session_factory
from karsasec.persistence.models import AuditEventModel
from karsasec.observability.correlation import get_correlation_id
from karsasec.observability.logger import default_logger


class AuditEventType(StrEnum):
    TASK_CREATED = "TASK_CREATED"
    TASK_QUEUED = "TASK_QUEUED"
    TASK_STARTED = "TASK_STARTED"
    TASK_RETRIED = "TASK_RETRIED"
    TASK_COMPLETED = "TASK_COMPLETED"
    TASK_FAILED = "TASK_FAILED"
    TASK_CANCELLED = "TASK_CANCELLED"
    TASK_RECOVERED = "TASK_RECOVERED"
    TASK_STATE_CHANGED = "TASK_STATE_CHANGED"
    TASK_CAS_REJECTED = "TASK_CAS_REJECTED"
    TASK_RESURRECTION_BLOCKED = "TASK_RESURRECTION_BLOCKED"
    LEASE_ACQUIRED = "LEASE_ACQUIRED"
    LEASE_RENEWED = "LEASE_RENEWED"
    LEASE_EXPIRED = "LEASE_EXPIRED"
    LEASE_FENCED = "LEASE_FENCED"
    WORKER_REGISTERED = "WORKER_REGISTERED"
    WORKER_REJECTED = "WORKER_REJECTED"
    WORKER_HEARTBEAT_REJECTED = "WORKER_HEARTBEAT_REJECTED"
    OUTBOX_CREATED = "OUTBOX_CREATED"
    OUTBOX_PUBLISHED = "OUTBOX_PUBLISHED"
    OUTBOX_RETRY = "OUTBOX_RETRY"


class AuditEvent:
    """Lightweight domain object representing a single audit log entry."""

    __slots__ = ("task_id", "event_type", "details", "correlation_id", "actor", "old_state", "new_state")

    def __init__(
        self,
        task_id: str,
        event_type: AuditEventType | str,
        details: dict | None = None,
        correlation_id: str | None = None,
        actor: str | None = None,
        old_state: str | None = None,
        new_state: str | None = None,
    ) -> None:
        self.task_id = task_id
        self.event_type = str(event_type)
        self.details = details or {}
        self.correlation_id = correlation_id or get_correlation_id()
        self.actor = actor
        self.old_state = old_state
        self.new_state = new_state


def _model_to_event(model: AuditEventModel) -> AuditEvent:
    details = {}
    if model.details:
        try:
            details = json.loads(model.details)
        except (json.JSONDecodeError, TypeError):
            details = {"raw": model.details}
    return AuditEvent(
        task_id=model.task_id,
        event_type=model.event_type,
        details=details,
    )


class AuditRepository(ABC):
    """Append-only audit log abstraction."""

    @abstractmethod
    def append(self, event: AuditEvent) -> None:
        """Persist a new audit event. NEVER updates existing records."""

    @abstractmethod
    def get_events_for_task(self, task_id: str) -> list[AuditEvent]:
        """Return all events for a task ordered by creation time (ascending)."""


class InMemoryAuditRepository(AuditRepository):
    """In-memory append-only ledger for unit tests."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        self._events.append(event)

    def get_events_for_task(self, task_id: str) -> list[AuditEvent]:
        return [e for e in self._events if e.task_id == task_id]

    def all_events(self) -> list[AuditEvent]:
        return list(self._events)


class PostgresAuditRepository(AuditRepository):
    """Production PostgreSQL append-only audit ledger.

    Non-blocking safe execution guarantees audit errors never disrupt primary operations.
    """

    def __init__(self, factory: DatabaseSessionFactory | None = None) -> None:
        self._factory = factory or get_session_factory()

    @contextmanager
    def _session(self) -> Generator[Session, None, None]:
        with self._factory.session_scope() as session:
            yield session

    def append(self, event: AuditEvent) -> None:
        """Append a single immutable audit event in a non-blocking safe try/except block."""
        try:
            safe_details = {
                k: v
                for k, v in event.details.items()
                if k not in {"source_code", "unified_diff", "diff", "patch", "token", "credential", "api_key"}
            }
            if event.correlation_id:
                safe_details["correlation_id"] = event.correlation_id
            if event.actor:
                safe_details["actor"] = event.actor
            if event.old_state:
                safe_details["old_state"] = event.old_state
            if event.new_state:
                safe_details["new_state"] = event.new_state

            with self._session() as session:
                model = AuditEventModel(
                    task_id=event.task_id,
                    event_type=event.event_type,
                    details=json.dumps(safe_details) if safe_details else None,
                )
                session.add(model)
        except Exception as err:
            # Non-blocking audit safety rule: audit failures must NOT raise or break authoritative caller
            default_logger.warning(
                "AUDIT_APPEND_FAILED",
                f"Failed to record audit event '{event.event_type}' for task '{event.task_id}': {err}",
                component="audit_repository",
                task_id=event.task_id,
            )

    def get_events_for_task(self, task_id: str) -> list[AuditEvent]:
        """Retrieve all audit events for a task, ordered by time ascending."""
        try:
            with self._session() as session:
                rows = session.scalars(
                    select(AuditEventModel)
                    .where(AuditEventModel.task_id == task_id)
                    .order_by(AuditEventModel.created_at.asc())
                ).all()
                return [_model_to_event(r) for r in rows]
        except Exception as err:
            default_logger.warning(
                "AUDIT_QUERY_FAILED",
                f"Failed to query audit events for task '{task_id}': {err}",
                component="audit_repository",
                task_id=task_id,
            )
            return []
