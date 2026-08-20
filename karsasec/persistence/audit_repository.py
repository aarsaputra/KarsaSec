"""PostgresAuditRepository — Append-Only Audit Event Ledger for Sprint F3.

Enforces immutability: no UPDATE or DELETE is allowed on audit_events.
Each event is a permanent, append-only record.

Audit Event Types:
  TASK_CREATED, TASK_QUEUED, TASK_STARTED, TASK_RETRIED,
  TASK_COMPLETED, TASK_FAILED, TASK_CANCELLED, TASK_RECOVERED

Privacy:
  - 'details' field stores only metadata (state, attempt count, timestamps).
  - No source code, diffs, credentials, or tokens in event records.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from contextlib import contextmanager
from enum import StrEnum
from typing import Generator, List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from karsasec.persistence.db import DatabaseSessionFactory, get_session_factory
from karsasec.persistence.models import AuditEventModel


class AuditEventType(StrEnum):
    TASK_CREATED = "TASK_CREATED"
    TASK_QUEUED = "TASK_QUEUED"
    TASK_STARTED = "TASK_STARTED"
    TASK_RETRIED = "TASK_RETRIED"
    TASK_COMPLETED = "TASK_COMPLETED"
    TASK_FAILED = "TASK_FAILED"
    TASK_CANCELLED = "TASK_CANCELLED"
    TASK_RECOVERED = "TASK_RECOVERED"


class AuditEvent:
    """Lightweight domain object representing a single audit log entry."""

    __slots__ = ("task_id", "event_type", "details")

    def __init__(
        self,
        task_id: str,
        event_type: AuditEventType | str,
        details: dict | None = None,
    ) -> None:
        self.task_id = task_id
        self.event_type = str(event_type)
        # details: metadata only — no source code, diffs, or credentials
        self.details = details or {}


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


# ---------------------------------------------------------------------------
# Abstract contract
# ---------------------------------------------------------------------------

class AuditRepository(ABC):
    """Append-only audit log abstraction."""

    @abstractmethod
    def append(self, event: AuditEvent) -> None:
        """Persist a new audit event. NEVER updates existing records."""

    @abstractmethod
    def get_events_for_task(self, task_id: str) -> List[AuditEvent]:
        """Return all events for a task ordered by creation time (ascending)."""


# ---------------------------------------------------------------------------
# InMemory fallback (tests / CI without Postgres)
# ---------------------------------------------------------------------------

class InMemoryAuditRepository(AuditRepository):
    """In-memory append-only ledger for unit tests."""

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def append(self, event: AuditEvent) -> None:
        # Append-only: no mutation allowed
        self._events.append(event)

    def get_events_for_task(self, task_id: str) -> List[AuditEvent]:
        return [e for e in self._events if e.task_id == task_id]

    def all_events(self) -> List[AuditEvent]:
        return list(self._events)


# ---------------------------------------------------------------------------
# Postgres implementation
# ---------------------------------------------------------------------------

class PostgresAuditRepository(AuditRepository):
    """Production PostgreSQL append-only audit ledger.

    CRITICAL: No UPDATE or DELETE statements are issued by this class.
    The DB-level constraint on audit_events ensures immutability.
    """

    def __init__(self, factory: DatabaseSessionFactory | None = None) -> None:
        self._factory = factory or get_session_factory()

    @contextmanager
    def _session(self) -> Generator[Session, None, None]:
        yield from self._factory.session_scope()

    def append(self, event: AuditEvent) -> None:
        """Append a single immutable audit event."""
        # Privacy guard: strip any forbidden keys from details before persisting
        safe_details = {
            k: v for k, v in event.details.items()
            if k not in {"source_code", "unified_diff", "diff", "patch", "token", "credential", "api_key"}
        }
        with self._session() as session:
            model = AuditEventModel(
                task_id=event.task_id,
                event_type=event.event_type,
                details=json.dumps(safe_details) if safe_details else None,
            )
            session.add(model)
            # Explicitly NO session.merge(), NO UPDATE

    def get_events_for_task(self, task_id: str) -> List[AuditEvent]:
        """Retrieve all audit events for a task, ordered by time ascending."""
        with self._session() as session:
            rows = session.scalars(
                select(AuditEventModel)
                .where(AuditEventModel.task_id == task_id)
                .order_by(AuditEventModel.created_at.asc())
            ).all()
            return [_model_to_event(r) for r in rows]
