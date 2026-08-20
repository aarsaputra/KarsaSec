"""Transactional Outbox Repository & Lifecycle Management for Sprint F8.

Guarantees:
  - INV-F8-OUTBOX-01: Staging outbox events occurs inside open SQL transaction.
  - INV-F8-PUBLISH-04: FOR UPDATE SKIP LOCKED lease fencing prevents concurrent publisher collision.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, UTC
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from karsasec.persistence.models import OutboxEventModel


def _utcnow() -> datetime:
    return datetime.now(UTC)


class TransactionalOutbox:
    """Repository handling transactional staging and publisher lease fencing for OutboxEventModel."""

    @staticmethod
    def stage_event(
        session: Session,
        aggregate_type: str,
        aggregate_id: str,
        event_type: str,
        payload: dict[str, Any] | str,
        lease_version: int = 1,
        deduplication_key: str | None = None,
    ) -> OutboxEventModel | None:
        """Stage an outbox event WITHIN an existing database transaction (INV-F8-OUTBOX-01)."""
        if isinstance(payload, dict):
            payload_str = json.dumps(payload, sort_keys=True)
        else:
            payload_str = str(payload)

        if deduplication_key:
            existing = session.scalar(
                select(OutboxEventModel).where(OutboxEventModel.deduplication_key == deduplication_key)
            )
            if existing:
                return existing

        evt_id = f"evt_{uuid.uuid4().hex[:16]}"
        content_for_hash = f"{aggregate_type}:{aggregate_id}:{event_type}:{payload_str}:{lease_version}"
        event_hash = hashlib.sha256(content_for_hash.encode("utf-8")).hexdigest()

        event = OutboxEventModel(
            event_id=evt_id,
            aggregate_id=aggregate_id,
            aggregate_type=aggregate_type,
            event_type=event_type,
            payload=payload_str,
            event_hash=event_hash,
            deduplication_key=deduplication_key,
            aggregate_sequence=lease_version,
            status="PENDING",
            created_at=_utcnow(),
        )
        session.add(event)
        return event

    @staticmethod
    def claim_pending_events(
        session: Session,
        publisher_id: str,
        publisher_lease_token: str,
        limit: int = 10,
    ) -> list[OutboxEventModel]:
        """Claim PENDING outbox events using FOR UPDATE SKIP LOCKED (INV-F8-PUBLISH-04)."""
        stmt = (
            select(OutboxEventModel)
            .where(OutboxEventModel.status == "PENDING")
            .order_by(OutboxEventModel.created_at.asc())
            .with_for_update(skip_locked=True)
            .limit(limit)
        )
        events = list(session.scalars(stmt).all())

        claimed = []
        now = _utcnow()
        for evt in events:
            evt.status = "CLAIMED"
            evt.claimed_by = publisher_id
            evt.publisher_lease_token = publisher_lease_token
            evt.claimed_at = now
            claimed.append(evt)

        if claimed:
            session.flush()
        return claimed

    @staticmethod
    def mark_published(
        session: Session,
        event_id: str,
        publisher_id: str,
        publisher_lease_token: str,
    ) -> bool:
        """Mark event as PUBLISHED verifying publisher lease ownership (INV-F8-PUBLISH-04)."""
        stmt = (
            update(OutboxEventModel)
            .where(
                OutboxEventModel.event_id == event_id,
                OutboxEventModel.status == "CLAIMED",
                OutboxEventModel.claimed_by == publisher_id,
                OutboxEventModel.publisher_lease_token == publisher_lease_token,
            )
            .values(
                status="PUBLISHED",
                published_at=_utcnow(),
            )
        )
        result = session.execute(stmt)
        return getattr(result, "rowcount", 0) == 1

    @staticmethod
    def mark_failed(
        session: Session,
        event_id: str,
        publisher_id: str,
        error_message: str,
        max_attempts: int = 5,
    ) -> None:
        """Record outbox processing failure and release claim or mark FAILED."""
        event = session.scalar(select(OutboxEventModel).where(OutboxEventModel.event_id == event_id))
        if not event:
            return

        event.attempt_count += 1
        if event.attempt_count >= max_attempts:
            event.status = "FAILED"
        else:
            event.status = "PENDING"  # Release claim for retry

        event.claimed_by = None
        event.claimed_at = None
        event.publisher_lease_token = None
        session.flush()
