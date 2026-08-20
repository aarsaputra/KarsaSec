"""Test end-to-end disaster recovery simulation and state reconstruction (INV-F9-RECOVERY-02, INV-F9-AUDIT-03)."""

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from karsasec.persistence.models import Base, TaskModel, OutboxEventModel, WorkerModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.recovery.checkpoint import RecoveryCheckpoint


class TestDisasterRecoveryEndToEndF9:
    """Verifies end-to-end disaster recovery restoration following database crash or backup restore."""

    @pytest.fixture(autouse=True)
    def setup_db(self):
        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        session_factory = sessionmaker(bind=engine)

        class MockSF(DatabaseSessionFactory):
            def __init__(self, sf):
                self._sf = sf

            def session_scope(self):
                from contextlib import contextmanager

                @contextmanager
                def _scope():
                    session = self._sf()
                    try:
                        yield session
                        session.commit()
                    except Exception:
                        session.rollback()
                        raise
                    finally:
                        session.close()

                return _scope()

        self.sf = MockSF(session_factory)
        self.repo = PostgresTaskRepository(self.sf)

    def test_full_disaster_recovery_restores_task_state_and_outbox(self):
        # 1. Create and assign tasks
        t1 = RemediationTask("t_dr_1", "f_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        t2 = RemediationTask("t_dr_2", "f_2", "tok_2", "val_2", "fp_2", state=TaskState.QUEUED)
        self.repo.create_task(t1)
        self.repo.create_task(t2)

        with self.sf.session_scope() as session:
            w = WorkerModel(worker_id="w_dr", auth_token_hash="hash_dr", status="ONLINE", fencing_token=1)
            session.add(w)

        self.repo.assign_task("t_dr_1", "w_dr")

        # 2. Save Checkpoint at T0
        with self.sf.session_scope() as session:
            RecoveryCheckpoint.save_checkpoint(
                session, "chk_dr_t0", generation=1, recovery_id="owner_dr", recovery_lease_token="tok_dr"
            )

        # 3. Perform work after T0 checkpoint
        self.repo.complete_task(
            task_id="t_dr_1",
            expected_lease_version=2,
            worker_id="w_dr",
            worker_fencing_token=1,
            receipt_id="rec_dr_1",
            receipt_fingerprint="fp_dr_1",
            security_verification_status="VERIFIED",
        )

        # 4. Simulate Disaster: Wipe TaskModel table & Outbox table
        with self.sf.session_scope() as session:
            for task_row in session.scalars(select(TaskModel)).all():
                session.delete(task_row)
            for outbox_row in session.scalars(select(OutboxEventModel)).all():
                session.delete(outbox_row)
            session.flush()

        # 5. Execute Disaster Recovery Restoration
        with self.sf.session_scope() as session:
            summary = RecoveryCheckpoint.restore_checkpoint(
                session, "chk_dr_t0", recovery_id="owner_dr", recovery_lease_token="tok_dr"
            )
            assert summary["replayed_events_count"] == 1
            assert summary["rebuilt_outbox_count"] > 0

            # 6. Verify restored states
            task1 = session.scalar(select(TaskModel).where(TaskModel.task_id == "t_dr_1"))
            assert task1 is not None
            assert task1.state == TaskState.COMPLETED.value
            assert task1.lease_version == 3

            task2 = session.scalar(select(TaskModel).where(TaskModel.task_id == "t_dr_2"))
            assert task2 is not None
            assert task2.state == TaskState.QUEUED.value
            assert task2.lease_version == 1
