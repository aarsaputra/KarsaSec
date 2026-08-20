"""Remediation Application Service for KarsaSec REST API.

Orchestrates async background task processing via Redis / In-Memory queues.
Enforces L7 (Zero Security Authority) and R1-R6 (Determinism).

Sprint F3: Uses PostgresTaskRepository as the production persistence layer.
Falls back to InMemoryTaskRepository when DATABASE_URL is unavailable (CI / unit tests).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
import json
import logging
from typing import Any

try:
    import redis  # type: ignore # pyright: ignore[reportMissingImports]
except ImportError:
    redis = None  # type: ignore

from karsasec.ai.remediation.rtp.receipt import VerificationReceipt
from karsasec.persistence.audit_repository import (
    AuditEvent,
    AuditEventType,
    InMemoryAuditRepository,
    PostgresAuditRepository,
)
from karsasec.persistence.receipt_repository import (
    InMemoryReceiptRepository,
    PostgresReceiptRepository,
)
from karsasec.persistence.task_repository import PostgresTaskRepository
from karsasec.server.dto.remediation import RemediationResponseDTO
from karsasec.workers.queue import InMemoryTaskQueue
from karsasec.workers.redis_queue import RedisTaskQueue
from karsasec.workers.repository import InMemoryTaskRepository
from karsasec.workers.task import RemediationTask, TaskState

_log = logging.getLogger(__name__)


class RemediationService:
    """Application service orchestrating async background remediation.

    Redis acts purely as a transport queue. State truth resides in the repository.

    Sprint F3:
      - PostgresTaskRepository is the default persistence layer.
      - InMemoryTaskRepository is used as fallback when Postgres is unavailable.
      - PostgresReceiptRepository stores immutable receipts.
      - PostgresAuditRepository records an append-only audit trail.
    """

    def __init__(self) -> None:
        # ---------------------------------------------------------------
        # Persistence layer: prefer Postgres, fall back to InMemory
        # ---------------------------------------------------------------
        try:
            from karsasec.persistence.db import get_session_factory
            factory = get_session_factory()
            # Smoke-test the connection
            engine = factory.engine
            with engine.connect():
                pass
            self.repository = PostgresTaskRepository(factory)
            self.receipt_repository = PostgresReceiptRepository(factory)
            self.audit_repository = PostgresAuditRepository(factory)
            _log.info("F3: Using PostgreSQL persistence layer.")
        except Exception as exc:
            _log.warning("F3: Postgres unavailable (%s); falling back to InMemory.", exc)
            self.repository = InMemoryTaskRepository()
            self.receipt_repository = InMemoryReceiptRepository()
            self.audit_repository = InMemoryAuditRepository()

        # ---------------------------------------------------------------
        # Queue transport: prefer Redis, fall back to InMemory
        # ---------------------------------------------------------------
        try:
            if redis is None:
                raise ImportError("redis package is not installed")
            self.redis_client = redis.Redis(
                host="127.0.0.1", port=6379, db=0, socket_timeout=1.0
            )
            self.redis_client.ping()
            self.queue = RedisTaskQueue(self.redis_client)
        except Exception:
            self.queue = InMemoryTaskQueue()

    def trigger_remediation(
        self,
        finding_id: str,
        approval_token_id: str,
        token: str,
    ) -> RemediationResponseDTO:
        """Trigger an async remediation task.

        Returns task metadata immediately with status QUEUED (HTTP 202).
        Enforces idempotency and replay prevention.
        """
        # Canonical JSON payload fingerprinting (deterministic, SHA-256)
        payload = {
            "finding_id": finding_id,
            "approval_token_id": approval_token_id,
            "token": token,
        }
        canonical = json.dumps(payload, sort_keys=True)
        fingerprint = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        task_id = f"tsk_{fingerprint}"

        # Idempotency check — return existing task if fingerprint matches active task
        existing = self.repository.get_active_task_by_fingerprint(fingerprint)
        if existing:
            return _task_to_dto(existing)

        # Also check by task_id in case the task was previously completed
        existing_by_id = self.repository.get_task(task_id)
        if existing_by_id:
            return _task_to_dto(existing_by_id)

        # Create new RemediationTask
        task = RemediationTask(
            task_id=task_id,
            finding_id=finding_id,
            approval_token_id=approval_token_id,
            token=token,
            fingerprint=fingerprint,
            state=TaskState.PENDING,
        )
        self.repository.create_task(task)

        # Audit: TASK_CREATED
        self.audit_repository.append(AuditEvent(
            task_id=task_id,
            event_type=AuditEventType.TASK_CREATED,
            details={"finding_id": finding_id, "approval_token_id": approval_token_id},
        ))

        # Transition PENDING → QUEUED and submit to queue
        queued_task = self.repository.update_task(task_id, state=TaskState.QUEUED)
        self.queue.enqueue(task_id)

        # Audit: TASK_QUEUED
        self.audit_repository.append(AuditEvent(
            task_id=task_id,
            event_type=AuditEventType.TASK_QUEUED,
            details={},
        ))

        return _task_to_dto(queued_task)

    def get_remediation(self, transaction_id: str) -> RemediationResponseDTO | None:
        """Retrieve task execution status by ID."""
        task = self.repository.get_task(transaction_id)
        if not task:
            return None
        return _task_to_dto(task)

    def get_receipt(self, transaction_id: str) -> VerificationReceipt | None:
        """Retrieve the VerificationReceipt for a completed task."""
        task = self.repository.get_task(transaction_id)
        if not task:
            return None
        return task.receipt


def _task_to_dto(task: RemediationTask) -> RemediationResponseDTO:
    """Map task domain model to privacy-safe API DTO."""
    return RemediationResponseDTO(
        transaction_id=task.task_id,
        finding_id=task.finding_id,
        state=str(task.state),
        integrity_status="VALID" if task.state == TaskState.COMPLETED else "PENDING",
        security_verification_status=task.security_verification_status or "SECURITY_NOT_VERIFIED",
        verification_run_id=task.receipt_id,
        receipt_fingerprint=task.receipt_fingerprint,
        provenance_fingerprint=task.receipt_fingerprint,
        ledger_fingerprint=task.receipt_fingerprint,
    )


def _build_stub_finding(finding_id: str):
    """Build a minimal stub Finding for lifecycle engine invocation in F1/F2 mode."""
    from karsasec.core.finding.model import Finding
    from karsasec.core.finding.evidence import Evidence
    from karsasec.rules.enums import Confidence, Severity

    return Finding(
        finding_id=finding_id,
        rule_id="API_STUB",
        fingerprint=finding_id[:32].ljust(32, "0"),
        title="API-triggered remediation",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        cwe_id="CWE-0",
        owasp="",
        file_path=Path(__file__),
        evidence=Evidence(snippet="", line=1, column=0),
        description="Remediation triggered via REST API",
        remediation="",
    )
