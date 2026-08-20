"""PostgreSQL Authoritative Distributed Recovery Lock for Sprint F5.

Implements persistent monotonic fencing tokens via PostgreSQL sequences (INV-F5-03)
and durable recovery lease persistence (INV-F5-04, INV-F5-05).
"""

from __future__ import annotations

from datetime import datetime, UTC, timedelta

from sqlalchemy import select, update, text, func
from sqlalchemy.orm import Session

from karsasec.persistence.db import DatabaseSessionFactory, get_session_factory
from karsasec.persistence.models import RecoveryLeaseModel
from karsasec.workers.cluster_recovery import RecoveryLease


class PostgresRecoveryLock:
    """Authoritative PostgreSQL-backed Distributed Recovery Lock."""

    def __init__(self, session_factory: DatabaseSessionFactory | None = None) -> None:
        self._session_factory = session_factory or get_session_factory()

    def _get_next_fencing_token(self, session: Session) -> int:
        """Fetch next monotonic fencing token from PostgreSQL sequence (INV-F5-03)."""
        try:
            # PostgreSQL native sequence evaluation
            result = session.execute(text("SELECT nextval('recovery_fencing_token_seq')"))
            val = result.scalar()
            if val is not None:
                return int(val)
        except Exception:
            # Fallback for SQLite / test environments without native sequence support
            pass

        max_token = session.scalar(select(func.max(RecoveryLeaseModel.fencing_token)))
        return (max_token or 0) + 1

    def acquire(self, node_id: str, ttl_seconds: int = 30) -> RecoveryLease:
        """Acquire authoritative recovery lease with durable monotonic fencing token (INV-F5-03, INV-F5-04)."""
        with self._session_factory.session_scope() as session:
            # Deactivate all active leases prior to acquiring new lease
            now = datetime.now(UTC)
            session.execute(
                update(RecoveryLeaseModel).where(RecoveryLeaseModel.status == "ACTIVE").values(status="EXPIRED")
            )

            token = self._get_next_fencing_token(session)
            lease_id = f"lease-{node_id}-{token}"
            expires_at = now + timedelta(seconds=ttl_seconds)

            lease_model = RecoveryLeaseModel(
                lease_id=lease_id,
                owner_id=node_id,
                fencing_token=token,
                acquired_at=now,
                expires_at=expires_at,
                status="ACTIVE",
            )
            session.add(lease_model)
            session.flush()

            return RecoveryLease(
                lease_id=lease_id,
                owner_id=node_id,
                fencing_token=token,
                acquired_at=now.timestamp(),
                ttl_seconds=float(ttl_seconds),
            )

    def renew(self, node_id: str, lease_id: str, fencing_token: int, ttl_seconds: int = 30) -> bool:
        """Renew lease if token remains current and un-fenced (INV-F5-05)."""
        with self._session_factory.session_scope() as session:
            now = datetime.now(UTC)
            max_token = session.scalar(select(func.max(RecoveryLeaseModel.fencing_token)))
            if max_token is not None and max_token > fencing_token:
                return False  # Leader has been fenced by a newer token

            model = session.scalar(
                select(RecoveryLeaseModel).where(
                    RecoveryLeaseModel.lease_id == lease_id,
                    RecoveryLeaseModel.owner_id == node_id,
                    RecoveryLeaseModel.fencing_token == fencing_token,
                    RecoveryLeaseModel.status == "ACTIVE",
                )
            )
            if not model:
                return False

            exp = model.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            if exp < now:
                return False

            model.expires_at = now + timedelta(seconds=ttl_seconds)
            return True

    def release(self, node_id: str, lease_id: str, fencing_token: int) -> bool:
        """Release recovery lease."""
        with self._session_factory.session_scope() as session:
            model = session.scalar(
                select(RecoveryLeaseModel).where(
                    RecoveryLeaseModel.lease_id == lease_id,
                    RecoveryLeaseModel.owner_id == node_id,
                    RecoveryLeaseModel.fencing_token == fencing_token,
                    RecoveryLeaseModel.status == "ACTIVE",
                )
            )
            if not model:
                return False

            model.status = "RELEASED"
            model.released_at = datetime.now(UTC)
            return True

    def is_valid(self, node_id: str, lease_id: str, fencing_token: int) -> bool:
        """Verify leader lock validity & ensure token has not been preempted (INV-F5-05)."""
        session = self._session_factory.get_session()
        try:
            now = datetime.now(UTC)
            max_token = session.scalar(select(func.max(RecoveryLeaseModel.fencing_token)))
            if max_token is not None and max_token > fencing_token:
                return False  # Fenced by newer recovery leader

            model = session.scalar(
                select(RecoveryLeaseModel).where(
                    RecoveryLeaseModel.lease_id == lease_id,
                    RecoveryLeaseModel.owner_id == node_id,
                    RecoveryLeaseModel.fencing_token == fencing_token,
                    RecoveryLeaseModel.status == "ACTIVE",
                )
            )
            if not model:
                return False

            exp = model.expires_at
            if exp.tzinfo is None:
                exp = exp.replace(tzinfo=UTC)
            return exp >= now
        finally:
            session.close()
