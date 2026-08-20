"""Reliable Event Publisher Engine for Sprint F8.

Guarantees:
  - INV-F8-EVENT-02: At-least-once delivery with deduplication tracking.
  - INV-F8-ORDER-03: Per-task sequence ordering via aggregate_sequence (lease_version).
  - INV-F8-PUBLISH-04: Only active publisher lease holder processes claimed events.
"""

from __future__ import annotations

import uuid
from typing import Any
from collections.abc import Callable

from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.events.outbox import TransactionalOutbox
from karsasec.observability.logger import default_logger
from karsasec.observability.metrics import get_metrics_registry


class ReliableEventPublisher:
    """Outbox publisher engine polling claimed events and dispatching to subscribers."""

    def __init__(
        self,
        session_factory: DatabaseSessionFactory,
        publisher_id: str | None = None,
        outbox_repo: TransactionalOutbox | None = None,
    ) -> None:
        self._session_factory = session_factory
        self.publisher_id = publisher_id or f"publisher_{uuid.uuid4().hex[:8]}"
        self.lease_token = f"tok_{uuid.uuid4().hex[:12]}"
        self._outbox = outbox_repo or TransactionalOutbox()
        self._processed_event_ids: set[str] = set()

    def poll_and_publish(
        self,
        limit: int = 10,
        handler: Callable[[dict[str, Any]], None] | None = None,
    ) -> int:
        """Poll PENDING outbox events using lease fencing and dispatch to handler (INV-F8-PUBLISH-04)."""
        published_count = 0

        with self._session_factory.session_scope() as session:
            claimed_events = self._outbox.claim_pending_events(
                session=session,
                publisher_id=self.publisher_id,
                publisher_lease_token=self.lease_token,
                limit=limit,
            )

            for evt in claimed_events:
                # Idempotency check (INV-F8-EVENT-02)
                if evt.event_id in self._processed_event_ids:
                    # Mark published without re-executing handler side-effects
                    self._outbox.mark_published(session, evt.event_id, self.publisher_id, self.lease_token)
                    published_count += 1
                    continue

                try:
                    payload_data = {
                        "event_id": evt.event_id,
                        "aggregate_id": evt.aggregate_id,
                        "aggregate_type": evt.aggregate_type,
                        "event_type": evt.event_type,
                        "payload": evt.payload,
                        "event_hash": evt.event_hash,
                        "aggregate_sequence": evt.aggregate_sequence,
                    }

                    if handler:
                        handler(payload_data)

                    self._processed_event_ids.add(evt.event_id)
                    self._outbox.mark_published(session, evt.event_id, self.publisher_id, self.lease_token)
                    published_count += 1

                    try:
                        get_metrics_registry().outbox_published(result="success")
                    except Exception:
                        pass

                except Exception as err:
                    default_logger.warning(
                        "Outbox publish failed",
                        event_id=evt.event_id,
                        error=str(err),
                    )
                    self._outbox.mark_failed(session, evt.event_id, self.publisher_id, str(err))
                    try:
                        get_metrics_registry().outbox_failed(result="failure")
                    except Exception:
                        pass

        return published_count
