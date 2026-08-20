"""Transactional Outbox Repository and Publisher Engine for Sprint F5.

Guarantees atomic task state mutation and outbox creation within a single database transaction (INV-F5-09),
and provides idempotent task queue publishing with FOR UPDATE SKIP LOCKED concurrency (INV-F5-10).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, UTC
from typing import Optional, List, Dict, Any

from sqlalchemy import select, update, text
from sqlalchemy.orm import Session

from karsasec.persistence.db import DatabaseSessionFactory, get_session_factory
from karsasec.persistence.models import OutboxEventModel
from karsasec.workers.queue import TaskQueue


class OutboxRepository:
    """Repository handling transactional insertion and processing of outbox events."""

    def __init__(self, session_factory: DatabaseSessionFactory | None = None) -> None:
        self._session_factory = session_factory or get_session_factory()

    def create_event_in_session(
        self,
        session: Session,
        aggregate_id: str,
        event_type: str,
        payload: Dict[str, Any],
        event_id: Optional[str] = None,
    ) -> OutboxEventModel:
        """Create an outbox event WITHIN an existing database transaction (INV-F5-09)."""
        evt_id = event_id or f"evt-{uuid.uuid4().hex[:12]}"
        existing = session.scalar(
            select(OutboxEventModel).where(OutboxEventModel.event_id == evt_id)
        )
        if existing:
            raise ValueError(f"Outbox event with ID '{evt_id}' already exists.")

        model = OutboxEventModel(
            event_id=evt_id,
            aggregate_id=aggregate_id,
            event_type=event_type,
            payload=json.dumps(payload),
            status="PENDING",
            attempt_count=0,
            created_at=datetime.now(UTC),
        )
        session.add(model)
        return model

    def fetch_pending_events(self, session: Session, limit: int = 10) -> List[OutboxEventModel]:
        """Fetch pending outbox events using FOR UPDATE SKIP LOCKED for concurrent worker safety."""
        try:
            # PostgreSQL row-level skip-locked selection
            query = (
                select(OutboxEventModel)
                .where(OutboxEventModel.status == "PENDING")
                .order_by(OutboxEventModel.created_at)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
            return list(session.scalars(query).all())
        except Exception:
            # Fallback for SQLite in isolated test suites
            query = (
                select(OutboxEventModel)
                .where(OutboxEventModel.status == "PENDING")
                .order_by(OutboxEventModel.created_at)
                .limit(limit)
            )
            return list(session.scalars(query).all())

    def mark_published(self, session: Session, event_id: str) -> None:
        """Mark outbox event as PUBLISHED."""
        event = session.scalar(
            select(OutboxEventModel).where(OutboxEventModel.event_id == event_id)
        )
        if event:
            event.status = "PUBLISHED"
            event.published_at = datetime.now(UTC)

    def record_failure(self, session: Session, event_id: str, error_msg: str) -> None:
        """Increment attempt count and mark FAILED if max retries exceeded."""
        event = session.scalar(
            select(OutboxEventModel).where(OutboxEventModel.event_id == event_id)
        )
        if event:
            event.attempt_count += 1
            if event.attempt_count >= 5:
                event.status = "FAILED"


class OutboxPublisher:
    """Outbox Publisher Engine polling pending events and enqueuing tasks into TaskQueue."""

    def __init__(
        self,
        queue: TaskQueue,
        session_factory: DatabaseSessionFactory | None = None,
        outbox_repo: OutboxRepository | None = None,
    ) -> None:
        self._queue = queue
        self._session_factory = session_factory or get_session_factory()
        self._outbox_repo = outbox_repo or OutboxRepository(self._session_factory)

    def process_pending_events(self, limit: int = 10) -> int:
        """Poll PENDING outbox events, publish to queue, and update event status atomically (INV-F5-10)."""
        published_count = 0
        with self._session_factory.session_scope() as session:
            pending_events = self._outbox_repo.fetch_pending_events(session, limit=limit)
            for event in pending_events:
                payload = json.loads(event.payload)
                task_id = payload.get("task_id", event.aggregate_id)
                try:
                    self._queue.enqueue(task_id)
                    stmt = (
                        update(OutboxEventModel)
                        .where(
                            OutboxEventModel.event_id == event.event_id,
                            OutboxEventModel.status == "PENDING",
                        )
                        .values(
                            status="PUBLISHED",
                            published_at=datetime.now(UTC),
                        )
                    )
                    res = session.execute(stmt)
                    if getattr(res, "rowcount", 0) == 1:
                        published_count += 1
                except Exception as err:
                    self._outbox_repo.record_failure(session, event.event_id, str(err))

        return published_count


