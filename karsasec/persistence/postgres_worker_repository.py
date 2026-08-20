"""PostgreSQL-backed Authoritative Worker Repository for Sprint F5.

Provides unique worker registration enforcement (INV-F5-06) and atomic heartbeat
sequence CAS updates (INV-F5-07).
"""

from __future__ import annotations

import hashlib
from datetime import datetime, UTC, timedelta
from typing import Optional, List, Dict, Any

from sqlalchemy import update, select
from sqlalchemy.orm import Session

from karsasec.persistence.db import DatabaseSessionFactory, get_session_factory
from karsasec.persistence.models import WorkerModel
from karsasec.workers.worker_registry import WorkerNode, WorkerStatus


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class PostgresWorkerRepository:
    """Authoritative PostgreSQL Worker Registry & Repository."""

    def __init__(self, session_factory: DatabaseSessionFactory | None = None) -> None:
        self._session_factory = session_factory or get_session_factory()

    def register_worker(
        self, worker_id: str, auth_token: str = "secret-worker-token", hostname: str = "localhost"
    ) -> WorkerNode:
        """Register worker with UNIQUE constraint enforcement and credential validation (INV-F5-06)."""
        token_hash = _hash_token(auth_token)

        try:
            with self._session_factory.session_scope() as session:
                existing = session.scalar(
                    select(WorkerModel)
                    .where(WorkerModel.worker_id == worker_id)
                    .with_for_update()
                )
                if existing:
                    if existing.auth_token_hash != token_hash:
                        raise ValueError(
                            f"Worker '{worker_id}' already registered with conflicting credentials."
                        )
                    # Idempotent re-registration under matching credentials
                    existing.hostname = hostname
                    existing.status = WorkerStatus.ONLINE.value
                    existing.last_heartbeat = datetime.now(UTC)
                    session.flush()
                    node = WorkerNode(
                        worker_id=existing.worker_id,
                        hostname=existing.hostname,
                        auth_token=auth_token,
                    )
                    node.status = WorkerStatus(existing.status)
                    return node

                model = WorkerModel(
                    worker_id=worker_id,
                    auth_token_hash=token_hash,
                    hostname=hostname,
                    status=WorkerStatus.ONLINE.value,
                    heartbeat_sequence=0,
                    last_heartbeat=datetime.now(UTC),
                )
                session.add(model)
                session.flush()
                node = WorkerNode(
                    worker_id=worker_id,
                    hostname=hostname,
                    auth_token=auth_token,
                )
                node.status = WorkerStatus.ONLINE
                return node
        except Exception as err:
            err_msg = str(err).lower()
            if "unique" in err_msg or "duplicate key" in err_msg or "integrityerror" in err_msg:
                with self._session_factory.session_scope() as retry_session:
                    existing = retry_session.scalar(
                        select(WorkerModel).where(WorkerModel.worker_id == worker_id)
                    )
                    if existing and existing.auth_token_hash != token_hash:
                        raise ValueError(
                            f"Worker '{worker_id}' already registered with conflicting credentials."
                        )
                    elif existing:
                        node = WorkerNode(
                            worker_id=existing.worker_id,
                            hostname=existing.hostname,
                            auth_token=auth_token,
                        )
                        node.status = WorkerStatus(existing.status)
                        return node
            raise

    def authenticate_worker(self, worker_id: str, auth_token: str) -> bool:
        """Validate worker authentication token hash against database record."""
        session = self._session_factory.get_session()
        try:
            model = session.scalar(select(WorkerModel).where(WorkerModel.worker_id == worker_id))
            if not model:
                return False
            return model.auth_token_hash == _hash_token(auth_token)
        finally:
            session.close()

    def heartbeat(
        self, worker_id: str, sequence: int, auth_token: str | None = None
    ) -> None:
        """Execute atomic conditional UPDATE for heartbeat sequence ordering and authentication (INV-F5-07)."""
        raw_token = auth_token or "secret-worker-token"
        token_hash = _hash_token(raw_token)

        with self._session_factory.session_scope() as session:
            stmt = (
                update(WorkerModel)
                .where(
                    WorkerModel.worker_id == worker_id,
                    WorkerModel.heartbeat_sequence < sequence,
                    WorkerModel.auth_token_hash == token_hash,
                )
                .values(
                    heartbeat_sequence=sequence,
                    last_heartbeat=datetime.now(UTC),
                    status=WorkerStatus.ONLINE.value,
                )
            )
            result = session.execute(stmt)
            if getattr(result, "rowcount", 0) == 1:
                return

            # Zero rows updated — analyze cause
            model = session.scalar(select(WorkerModel).where(WorkerModel.worker_id == worker_id))
            if not model:
                raise ValueError(f"Worker '{worker_id}' is not registered.")

            if model.auth_token_hash != token_hash:
                raise ValueError(
                    f"Unauthenticated/invalid auth token provided for worker '{worker_id}'."
                )

            if model.heartbeat_sequence >= sequence:
                raise ValueError(
                    f"Stale/replayed heartbeat sequence {sequence} rejected for '{worker_id}' (current is {model.heartbeat_sequence})."
                )

            raise ValueError(f"Heartbeat update failed for worker '{worker_id}'.")

    def get_worker(self, worker_id: str) -> Optional[WorkerNode]:
        """Fetch worker record from database."""
        session = self._session_factory.get_session()
        try:
            model = session.scalar(select(WorkerModel).where(WorkerModel.worker_id == worker_id))
            if not model:
                return None
            node = WorkerNode(
                worker_id=model.worker_id,
                hostname=model.hostname or "localhost",
            )
            node.status = WorkerStatus(model.status)
            return node
        finally:
            session.close()

    def mark_offline(self, worker_id: str) -> None:
        """Mark worker status as OFFLINE."""
        with self._session_factory.session_scope() as session:
            model = session.scalar(select(WorkerModel).where(WorkerModel.worker_id == worker_id))
            if model:
                model.status = WorkerStatus.OFFLINE.value

    def list_active(self, max_heartbeat_age_seconds: int = 30) -> List[WorkerNode]:
        """List active ONLINE or DEGRADED workers with fresh heartbeats."""
        cutoff = datetime.now(UTC) - timedelta(seconds=max_heartbeat_age_seconds)
        session = self._session_factory.get_session()
        try:
            query = (
                select(WorkerModel)
                .where(
                    WorkerModel.status.in_([WorkerStatus.ONLINE.value, WorkerStatus.DEGRADED.value]),
                    WorkerModel.last_heartbeat >= cutoff,
                )
                .order_by(WorkerModel.worker_id)
            )
            models = session.scalars(query).all()
            result = []
            for m in models:
                n = WorkerNode(
                    worker_id=m.worker_id,
                    hostname=m.hostname or "localhost",
                )
                n.status = WorkerStatus(m.status)
                result.append(n)
            return result
        finally:
            session.close()
