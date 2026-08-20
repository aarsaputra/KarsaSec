"""Test Point-In-Time Recovery (PITR) boundary marker correctness (INV-F9-RECOVERY-10)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from karsasec.persistence.models import Base, WorkerModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.recovery.snapshot import SnapshotManager
from karsasec.recovery.replay import AuditReplayEngine


class TestSnapshotBoundaryReplayF9:
    """Verifies that audit replay respects snapshot boundary markers and does not double-replay prior events."""

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

    def test_replay_respects_boundary_marker(self):
        # 1. Create task & assign (lease_version = 2)
        task = RemediationTask("task_pitr", "find_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        self.repo.create_task(task)

        with self.sf.session_scope() as session:
            w = WorkerModel(worker_id="w_pitr", auth_token_hash="hash_pitr", status="ONLINE", fencing_token=1)
            session.add(w)

        self.repo.assign_task("task_pitr", "w_pitr")

        # Capture snapshot at boundary lease_version = 2
        with self.sf.session_scope() as session:
            snapshot = SnapshotManager.create_snapshot(session, generation=1)
            assert snapshot["max_lease_version"] == 2

        # 2. Perform another state transition (complete task -> lease_version = 3)
        self.repo.complete_task(
            task_id="task_pitr",
            expected_lease_version=2,
            worker_id="w_pitr",
            worker_fencing_token=1,
            receipt_id="rec_pitr",
            receipt_fingerprint="fp_pitr",
            security_verification_status="VERIFIED",
        )

        # 3. Restore snapshot (task state set back to lease_version = 2) and replay events after snapshot boundary
        with self.sf.session_scope() as session:
            SnapshotManager.load_snapshot(session, snapshot)
            replayed_count = AuditReplayEngine.replay_events(session, snapshot)

            # Exactly 1 event replayed (the completion transition after boundary)
            assert replayed_count == 1
