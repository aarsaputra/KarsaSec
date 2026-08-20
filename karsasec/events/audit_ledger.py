"""Tamper-Evident Task Audit Ledger for Sprint F8 (INV-F8-AUDIT-05).

Guarantees:
  - Append-only audit logging inside primary CAS task state transactions.
  - Blockchain-lite cryptographic hash chaining per task (previous_event_hash -> event_hash).
  - Tamper detection via verify_chain_integrity().
"""

from __future__ import annotations

import hashlib
from datetime import datetime, UTC
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from karsasec.persistence.models import TaskAuditLogModel


def _utcnow() -> datetime:
    return datetime.now(UTC)


class AuditChainTamperedError(Exception):
    """Raised when audit ledger hash chain verification fails due to illegal row modification."""


class TaskAuditLedger:
    """Tamper-evident audit ledger manager."""

    @staticmethod
    def _compute_hash(
        task_id: str,
        previous_event_hash: str | None,
        previous_state: str,
        new_state: str,
        worker_id: str | None,
        fencing_token: int | None,
        lease_version: int,
        reason: str,
    ) -> str:
        prev_h = previous_event_hash or "GENESIS"
        w_id = worker_id or ""
        f_tok = fencing_token if fencing_token is not None else 0
        raw = f"{task_id}:{prev_h}:{previous_state}:{new_state}:{w_id}:{f_tok}:{lease_version}:{reason}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @classmethod
    def record_transition(
        cls,
        session: Session,
        task_id: str,
        previous_state: str,
        new_state: str,
        worker_id: str | None = None,
        fencing_token: int | None = None,
        lease_version: int = 1,
        reason: str = "",
    ) -> TaskAuditLogModel:
        """Record an immutable state transition row inside active SQL transaction."""
        # Find latest row for this task_id to get previous_event_hash
        latest = session.scalar(
            select(TaskAuditLogModel)
            .where(TaskAuditLogModel.task_id == task_id)
            .order_by(TaskAuditLogModel.created_at.desc(), TaskAuditLogModel.id.desc())
            .limit(1)
        )
        prev_hash = latest.event_hash if latest else None

        evt_hash = cls._compute_hash(
            task_id=task_id,
            previous_event_hash=prev_hash,
            previous_state=previous_state,
            new_state=new_state,
            worker_id=worker_id,
            fencing_token=fencing_token,
            lease_version=lease_version,
            reason=reason,
        )

        entry = TaskAuditLogModel(
            task_id=task_id,
            previous_state=previous_state,
            new_state=new_state,
            worker_id=worker_id,
            fencing_token=fencing_token,
            lease_version=lease_version,
            reason=reason,
            previous_event_hash=prev_hash,
            event_hash=evt_hash,
            created_at=_utcnow(),
        )
        session.add(entry)
        session.flush()
        return entry

    @classmethod
    def verify_chain_integrity(cls, session: Session, task_id: str) -> bool:
        """Verify that the cryptographic hash chain for task_id has not been modified or tampered with."""
        rows = list(
            session.scalars(
                select(TaskAuditLogModel)
                .where(TaskAuditLogModel.task_id == task_id)
                .order_by(TaskAuditLogModel.created_at.asc(), TaskAuditLogModel.id.asc())
            ).all()
        )

        prev_hash: str | None = None
        for i, row in enumerate(rows):
            if row.previous_event_hash != prev_hash:
                raise AuditChainTamperedError(
                    f"Chain broken at row index {i} for task '{task_id}': expected prev_hash '{prev_hash}', got '{row.previous_event_hash}'"
                )

            expected_hash = cls._compute_hash(
                task_id=row.task_id,
                previous_event_hash=row.previous_event_hash,
                previous_state=row.previous_state,
                new_state=row.new_state,
                worker_id=row.worker_id,
                fencing_token=row.fencing_token,
                lease_version=row.lease_version,
                reason=row.reason,
            )

            if row.event_hash != expected_hash:
                raise AuditChainTamperedError(
                    f"Hash mismatch at row index {i} for task '{task_id}': computed '{expected_hash}', stored '{row.event_hash}'"
                )

            prev_hash = row.event_hash

        return True

    @classmethod
    def reconstruct_history(cls, session: Session, task_id: str) -> list[dict[str, Any]]:
        """Reconstruct chronological state history for forensic auditing."""
        rows = list(
            session.scalars(
                select(TaskAuditLogModel)
                .where(TaskAuditLogModel.task_id == task_id)
                .order_by(TaskAuditLogModel.created_at.asc(), TaskAuditLogModel.id.asc())
            ).all()
        )
        history = []
        for r in rows:
            history.append(
                {
                    "task_id": r.task_id,
                    "previous_state": r.previous_state,
                    "new_state": r.new_state,
                    "worker_id": r.worker_id,
                    "fencing_token": r.fencing_token,
                    "lease_version": r.lease_version,
                    "reason": r.reason,
                    "event_hash": r.event_hash,
                    "created_at": r.created_at.isoformat() if r.created_at else None,
                }
            )
        return history
