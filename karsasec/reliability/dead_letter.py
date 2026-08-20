"""Forensic Dead-Letter Queue (DLQ) Repository & Sanitizer for Sprint F6C.

Invariants:
  - INV-F6-DLQ-01: Exactly one terminal task produces at most one forensic DLQ record.
  - INV-F6-DLQ-02: DLQ record insertion and task FAILED state mutation occur in the same PostgreSQL transaction.
  - INV-F6-DLQ-03: DLQ payloads use SAFE_DLQ_SCHEMA forensic snapshotting only. All exception strings scrubbed.
  - INV-F6-DLQ-04: UNIQUE(task_id) constraint guarantees idempotency under concurrent execution.
  - INV-F6-DLQ-05: Strict byte bounds (sanitized_error_message <= 8192 bytes, payload_json <= 32768 bytes).
"""

from __future__ import annotations

import json
import re
from typing import Any

from sqlalchemy import select, func

from karsasec.persistence.db import DatabaseSessionFactory, get_session_factory
from karsasec.persistence.models import DeadLetterEventModel, TaskModel

MAX_ERROR_BYTES = 8192
MAX_PAYLOAD_BYTES = 32768

# Sensitive pattern regexes for exception scrubbing
DB_URL_REGEX = re.compile(r"postgresql://[^:]+:[^@]+@[^/]+/\w+", re.IGNORECASE)
BEARER_TOKEN_REGEX = re.compile(r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE)
API_KEY_REGEX = re.compile(r"(?:key|secret|token|password|auth)=['\"]?[A-Za-z0-9\-_=]{8,}['\"]?", re.IGNORECASE)


def sanitize_exception(error_msg: str | None) -> str:
    """Scrub database URLs, Bearer tokens, and secrets from exception messages.

    Truncates result to MAX_ERROR_BYTES (8192 bytes) safely.
    """
    if not error_msg:
        return "Unknown error"

    scrubbed = DB_URL_REGEX.sub("postgresql://[REDACTED]@[REDACTED]/[REDACTED]", error_msg)
    scrubbed = BEARER_TOKEN_REGEX.sub("Bearer [REDACTED]", scrubbed)
    scrubbed = API_KEY_REGEX.sub("[REDACTED_SECRET]", scrubbed)

    return truncate_to_bytes(scrubbed, MAX_ERROR_BYTES)


def truncate_to_bytes(text: str, max_bytes: int) -> str:
    """Truncates text safely at UTF-8 byte boundary if it exceeds max_bytes."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text
    marker = " [TRUNCATED]"
    marker_bytes = len(marker.encode("utf-8"))
    allowed_bytes = max_bytes - marker_bytes
    valid_slice = encoded[:allowed_bytes].decode("utf-8", errors="ignore")
    return valid_slice + marker


def build_forensic_snapshot(task_model: TaskModel) -> str:
    """Build safe forensic JSON snapshot adhering to SAFE_DLQ_SCHEMA.

    Excludes source code, patches, diffs, and credentials.
    Truncates result to MAX_PAYLOAD_BYTES (32768 bytes).
    """
    snapshot: dict[str, Any] = {
        "task_id": task_model.task_id,
        "finding_id": task_model.finding_id,
        "approval_token_id": task_model.approval_token_id,
        "fingerprint": task_model.fingerprint,
        "state": task_model.state,
        "attempts": task_model.attempts,
        "max_attempts": task_model.max_attempts,
        "lease_version": task_model.lease_version,
    }
    if task_model.payload:
        try:
            raw_payload = json.loads(task_model.payload)
            if isinstance(raw_payload, dict):
                safe_keys = {"rule_id", "severity", "target_path", "fingerprint", "task_type"}
                snapshot["payload_metadata"] = {k: v for k, v in raw_payload.items() if k in safe_keys}
        except Exception:
            pass

    serialized = json.dumps(snapshot, sort_keys=True)
    return truncate_to_bytes(serialized, MAX_PAYLOAD_BYTES)


class DeadLetterRepository:
    """Repository for querying forensic Dead Letter events."""

    def __init__(self, session_factory: DatabaseSessionFactory | None = None) -> None:
        self._session_factory = session_factory or get_session_factory()

    def get_event(self, task_id: str) -> dict[str, Any] | None:
        """Fetch DLQ event by task_id."""
        session = self._session_factory.get_session()
        try:
            model = session.scalar(select(DeadLetterEventModel).where(DeadLetterEventModel.task_id == task_id))
            if not model:
                return None
            return {
                "event_id": model.event_id,
                "task_id": model.task_id,
                "correlation_id": model.correlation_id,
                "reason": model.reason,
                "attempts": model.attempts,
                "max_attempts": model.max_attempts,
                "payload_json": model.payload_json,
                "error_type": model.error_type,
                "sanitized_error_message": model.sanitized_error_message,
                "worker_id": model.worker_id,
                "created_at": model.created_at.isoformat() if model.created_at else None,
            }
        finally:
            session.close()

    def list_events(self, limit: int = 100) -> list[dict[str, Any]]:
        """List DLQ events ordered by created_at descending."""
        session = self._session_factory.get_session()
        try:
            stmt = select(DeadLetterEventModel).order_by(DeadLetterEventModel.created_at.desc()).limit(limit)
            models = session.scalars(stmt).all()
            return [
                {
                    "event_id": m.event_id,
                    "task_id": m.task_id,
                    "correlation_id": m.correlation_id,
                    "reason": m.reason,
                    "attempts": m.attempts,
                    "max_attempts": m.max_attempts,
                    "payload_json": m.payload_json,
                    "error_type": m.error_type,
                    "sanitized_error_message": m.sanitized_error_message,
                    "worker_id": m.worker_id,
                    "created_at": m.created_at.isoformat() if m.created_at else None,
                }
                for m in models
            ]
        finally:
            session.close()

    def get_count(self) -> int:
        """Get total count of DLQ events."""
        session = self._session_factory.get_session()
        try:
            return session.scalar(select(func.count()).select_from(DeadLetterEventModel)) or 0
        finally:
            session.close()
