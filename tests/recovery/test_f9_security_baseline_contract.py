"""KarsaSec Sprint F9 — Security Baseline Regression Contract Test Suite.

Verifies that the pre-mutation security boundary, fail-closed order, and invariant contracts
remain continuously enforced without regression.
"""

import pytest
from typing import cast
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from karsasec.persistence.models import Base, TaskModel, TaskAuditLogModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.recovery import AuditCorruptionError, SnapshotIntegrityError
from karsasec.recovery.snapshot import SnapshotManager
from karsasec.recovery.checkpoint import RecoveryCheckpoint


class TestF9SecurityBaselineContract:
    """Architectural contract tests enforcing Sprint F9 invariants."""

    def setup_method(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(bind=self.engine)

        class MockSessionFactory:
            def __init__(sf, sm):
                sf._sm = sm

            def get_session(sf):
                return sf._sm()

            def session_scope(sf):
                from contextlib import contextmanager

                @contextmanager
                def _scope():
                    session = sf._sm()
                    try:
                        yield session
                        session.commit()
                    except Exception:
                        session.rollback()
                        raise
                    finally:
                        session.close()

                return _scope()

        self.sf = MockSessionFactory(self.SessionLocal)
        self.repo = PostgresTaskRepository(cast(DatabaseSessionFactory, self.sf))

    def teardown_method(self):
        Base.metadata.drop_all(self.engine)

    def test_pre_mutation_boundary_prevents_task_deletion_on_audit_corruption(self):
        """Contract Verification: Corrupted audit chain blocks task deletion/restoration before mutation."""
        task = RemediationTask("task_contract_1", "find_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        self.repo.create_task(task)

        with self.sf.session_scope() as session:
            RecoveryCheckpoint.save_checkpoint(
                session, "chk_contract_1", generation=1, recovery_id="rec_1", recovery_lease_token="tok_1"
            )

            # Corrupt audit log entry
            audit_row = session.scalar(select(TaskAuditLogModel).where(TaskAuditLogModel.task_id == "task_contract_1"))
            assert audit_row is not None
            audit_row.event_hash = "corrupted_hash_value_000000000000000000000000000000000000000000000"
            session.flush()

            # Attempt restoration — MUST raise AuditCorruptionError
            with pytest.raises(AuditCorruptionError):
                RecoveryCheckpoint.restore_checkpoint(
                    session, "chk_contract_1", recovery_id="rec_1", recovery_lease_token="tok_1"
                )

        # Verify task was NOT deleted or corrupted
        with self.sf.session_scope() as session:
            task_db = session.scalar(select(TaskModel).where(TaskModel.task_id == "task_contract_1"))
            assert task_db is not None
            assert task_db.task_id == "task_contract_1"

    def test_snapshot_verification_occurs_before_db_load(self):
        """Contract Verification: Invalid Merkle-lite root hash aborts before TaskModel reset."""
        task = RemediationTask("task_contract_2", "find_2", "tok_2", "val_2", "fp_2", state=TaskState.QUEUED)
        self.repo.create_task(task)

        with self.sf.session_scope() as session:
            snapshot = SnapshotManager.create_snapshot(session, generation=1)
            snapshot["root_hash"] = "bad_root_hash_00000000000000000000000000000000000000000000000"

            with pytest.raises(SnapshotIntegrityError):
                SnapshotManager.load_snapshot(session, snapshot)

        # Confirm original task in DB remains untouched
        with self.sf.session_scope() as session:
            task_db = session.scalar(select(TaskModel).where(TaskModel.task_id == "task_contract_2"))
            assert task_db is not None
