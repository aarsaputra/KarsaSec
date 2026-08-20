"""Test deterministic restore execution and hash equality (INV-F9-RECOVERY-13, INV-F9-REPLAY-04)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from karsasec.persistence.models import Base, WorkerModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.recovery.snapshot import SnapshotManager
from karsasec.recovery.checkpoint import RecoveryCheckpoint


class TestRecoveryDeterminismF9:
    """Verifies that executing restore checkpoints 1x, 10x, or 100x yields identical state hashes."""

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

    def test_repeated_restore_produces_identical_state_hash(self):
        # Setup multi-step task lifecycle
        task = RemediationTask("task_det", "find_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        self.repo.create_task(task)

        with self.sf.session_scope() as session:
            w = WorkerModel(worker_id="w_det", auth_token_hash="hash_det", status="ONLINE", fencing_token=1)
            session.add(w)

        self.repo.assign_task("task_det", "w_det")
        self.repo.complete_task(
            task_id="task_det",
            expected_lease_version=2,
            worker_id="w_det",
            worker_fencing_token=1,
            receipt_id="rec_det",
            receipt_fingerprint="fp_det",
            security_verification_status="VERIFIED",
        )

        with self.sf.session_scope() as session:
            RecoveryCheckpoint.save_checkpoint(
                session, "chk_det_1", generation=1, recovery_id="owner_1", recovery_lease_token="tok_1"
            )
            base_snapshot = SnapshotManager.create_snapshot(session, generation=1)

        # Execute 100 restore operations and assert bit-for-bit state hash equality
        for _ in range(100):
            with self.sf.session_scope() as session:
                RecoveryCheckpoint.restore_checkpoint(
                    session, "chk_det_1", recovery_id="owner_1", recovery_lease_token="tok_1"
                )
                current_snapshot = SnapshotManager.create_snapshot(session, generation=1)
                assert current_snapshot["snapshot_hash"] == base_snapshot["snapshot_hash"]
                assert current_snapshot["root_hash"] == base_snapshot["root_hash"]
