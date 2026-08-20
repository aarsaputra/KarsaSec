"""Adversarial security tests for INV-F8-AUDIT-05 (Tamper-Evident Audit Chain Integrity).

Verifies cryptographic hash chain verification and tamper detection in TaskAuditLedger.
"""

from __future__ import annotations

import pytest
from sqlalchemy import select

from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base, TaskAuditLogModel
from karsasec.events.audit_ledger import TaskAuditLedger, AuditChainTamperedError


class TestAuditIntegrityF8:
    @pytest.fixture(autouse=True)
    def setup_db(self):
        sf = DatabaseSessionFactory("sqlite:///:memory:")
        engine = sf.engine
        Base.metadata.create_all(bind=engine)
        self.sf = sf

    def test_hash_chain_valid_lifecycle_passes(self):
        task_id = "task_audit_valid"

        with self.sf.session_scope() as session:
            TaskAuditLedger.record_transition(
                session, task_id, previous_state="NONE", new_state="QUEUED", lease_version=1, reason="CREATED"
            )
            TaskAuditLedger.record_transition(
                session,
                task_id,
                previous_state="QUEUED",
                new_state="RUNNING",
                worker_id="w1",
                fencing_token=10,
                lease_version=2,
                reason="ASSIGNED",
            )
            TaskAuditLedger.record_transition(
                session,
                task_id,
                previous_state="RUNNING",
                new_state="COMPLETED",
                worker_id="w1",
                fencing_token=10,
                lease_version=2,
                reason="COMPLETED",
            )

        with self.sf.session_scope() as session:
            assert TaskAuditLedger.verify_chain_integrity(session, task_id) is True
            history = TaskAuditLedger.reconstruct_history(session, task_id)
            assert len(history) == 3
            assert history[0]["new_state"] == "QUEUED"
            assert history[1]["new_state"] == "RUNNING"
            assert history[2]["new_state"] == "COMPLETED"

    def test_tamper_detection_catches_modified_audit_row(self):
        task_id = "task_audit_tampered"

        with self.sf.session_scope() as session:
            TaskAuditLedger.record_transition(
                session, task_id, previous_state="NONE", new_state="QUEUED", lease_version=1, reason="CREATED"
            )
            TaskAuditLedger.record_transition(
                session,
                task_id,
                previous_state="QUEUED",
                new_state="RUNNING",
                worker_id="w1",
                fencing_token=10,
                lease_version=2,
                reason="ASSIGNED",
            )

        # Illegal modification of row 1 (simulating unauthorized DB write or attacker alteration)
        with self.sf.session_scope() as session:
            row = session.scalar(
                select(TaskAuditLogModel).where(
                    TaskAuditLogModel.task_id == task_id, TaskAuditLogModel.new_state == "QUEUED"
                )
            )
            assert row is not None
            row.previous_state = "ALTERED_STATE"  # Tamper with row

        # Verification must raise AuditChainTamperedError!
        with self.sf.session_scope() as session:
            with pytest.raises(AuditChainTamperedError):
                TaskAuditLedger.verify_chain_integrity(session, task_id)
