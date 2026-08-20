"""WorkerRegistry — Distributed Worker Node Lifecycle & Security Registry (Sprint F4).

Manages worker registration, secret token validation, heartbeat timestamps, and active status.

Invariants:
  - L7: Worker registry does not generate or compute security verdicts.
  - Impersonation Protection: Heartbeats are validated against worker registration credentials.
    Forged heartbeats trigger audit event `FORGED_WORKER_HEARTBEAT`.
  - Determinism: Active worker listing is strictly ordered by worker_id.
"""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Dict, List, Optional, Any
from enum import StrEnum

from karsasec.persistence.audit_repository import AuditEvent, AuditEventType, AuditRepository


class WorkerStatus(StrEnum):
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"


class WorkerNode:
    """Domain model representing a registered worker in the KarsaSec cluster."""

    __slots__ = (
        "worker_id",
        "hostname",
        "version",
        "started_at",
        "last_heartbeat",
        "status",
        "auth_token_hash",
        "heartbeat_sequence",
    )

    def __init__(
        self,
        worker_id: str,
        hostname: str,
        version: str = "1.0.0",
        auth_token: str | None = None,
        started_at: float | None = None,
    ) -> None:
        self.worker_id = worker_id
        self.hostname = hostname
        self.version = version
        now = time.time()
        self.started_at = started_at or now
        self.last_heartbeat = now
        self.status = WorkerStatus.ONLINE
        self.heartbeat_sequence: int = 0
        # Hash token for security validation (never store raw token in node object)
        raw = auth_token or f"worker_secret_{worker_id}"
        self.auth_token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def update_heartbeat(self, sequence: int | None = None) -> None:
        # Point 3: Always record server-received timestamp, ignoring any client-supplied timestamps
        self.last_heartbeat = time.time()
        if sequence is not None:
            self.heartbeat_sequence = sequence
        if self.status != WorkerStatus.ONLINE:
            self.status = WorkerStatus.ONLINE

    def to_dict(self) -> Dict[str, Any]:
        """Privacy-safe dictionary representation (token hash omitted)."""
        return {
            "worker_id": self.worker_id,
            "hostname": self.hostname,
            "version": self.version,
            "started_at": self.started_at,
            "last_heartbeat": self.last_heartbeat,
            "heartbeat_sequence": self.heartbeat_sequence,
            "status": str(self.status),
        }


class WorkerRegistry:
    """Process-local thread-safe registry managing worker node lifecycles.

    Note: `threading.Lock()` provides process-local thread-safety.
    In multi-node cluster production (Sprint F5), database transactions and `UNIQUE(worker_id)`
    constraints act as the distributed authority.
    """

    def __init__(self, audit_repository: AuditRepository | None = None) -> None:
        self._workers: Dict[str, WorkerNode] = {}
        self._audit = audit_repository
        self._lock = threading.Lock()

    def register(
        self,
        worker_id: str,
        hostname: str,
        version: str = "1.0.0",
        auth_token: str | None = None,
    ) -> WorkerNode:
        """Register a new worker node under lock. Raises ValueError if worker_id exists with different token."""
        with self._lock:
            if worker_id in self._workers:
                existing = self._workers[worker_id]
                raw = auth_token or f"worker_secret_{worker_id}"
                token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
                if existing.auth_token_hash != token_hash:
                    raise ValueError(f"Duplicate worker registration conflict for '{worker_id}'.")
                existing.update_heartbeat()
                return existing

            node = WorkerNode(
                worker_id=worker_id,
                hostname=hostname,
                version=version,
                auth_token=auth_token,
            )
            self._workers[worker_id] = node
            return node

    def heartbeat(
        self,
        worker_id: str,
        auth_token: str | None = None,
        sequence: int | None = None,
    ) -> bool:
        """Process heartbeat from a worker under lock.

        Validates worker identity and monotonic sequence number.
        Rejects unauthorized or replayed heartbeats and logs `FORGED_WORKER_HEARTBEAT`.
        """
        with self._lock:
            if worker_id not in self._workers:
                if self._audit:
                    self._audit.append(AuditEvent(
                        task_id=f"sys_{worker_id}",
                        event_type="FORGED_WORKER_HEARTBEAT",
                        details={"worker_id": worker_id, "reason": "unregistered_worker"},
                    ))
                return False

            worker = self._workers[worker_id]
            raw = auth_token or f"worker_secret_{worker_id}"
            provided_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()

            if provided_hash != worker.auth_token_hash:
                if self._audit:
                    self._audit.append(AuditEvent(
                        task_id=f"sys_{worker_id}",
                        event_type="FORGED_WORKER_HEARTBEAT",
                        details={"worker_id": worker_id, "reason": "invalid_auth_token"},
                    ))
                return False

            # Point 4: Replay Attack Defense (Monotonic sequence check under lock)
            if sequence is not None and sequence <= worker.heartbeat_sequence:
                if self._audit:
                    self._audit.append(AuditEvent(
                        task_id=f"sys_{worker_id}",
                        event_type="FORGED_WORKER_HEARTBEAT",
                        details={
                            "worker_id": worker_id,
                            "reason": "replayed_heartbeat_sequence",
                            "provided_sequence": sequence,
                            "last_sequence": worker.heartbeat_sequence,
                        },
                    ))
                return False

            worker.update_heartbeat(sequence=sequence)
            return True

    def mark_offline(self, worker_id: str) -> None:
        """Mark a worker as OFFLINE."""
        with self._lock:
            if worker_id in self._workers:
                self._workers[worker_id].status = WorkerStatus.OFFLINE

    def get_worker(self, worker_id: str) -> Optional[WorkerNode]:
        with self._lock:
            return self._workers.get(worker_id)

    def list_active(self) -> List[WorkerNode]:
        """Return all ONLINE or DEGRADED workers, deterministically ordered by worker_id."""
        with self._lock:
            active = [
                w for w in self._workers.values()
                if w.status in (WorkerStatus.ONLINE, WorkerStatus.DEGRADED)
            ]
            return sorted(active, key=lambda w: w.worker_id)

    def list_all(self) -> List[WorkerNode]:
        """Return all registered workers, deterministically ordered by worker_id."""
        with self._lock:
            return sorted(self._workers.values(), key=lambda w: w.worker_id)
