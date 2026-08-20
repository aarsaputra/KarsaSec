"""Test snapshot generation fencing and stale generation rejection (INV-F9-RECOVERY-11)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from karsasec.persistence.models import Base
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.recovery import SnapshotFencingError
from karsasec.recovery.snapshot import SnapshotManager
from karsasec.recovery.checkpoint import RecoveryCheckpoint


class TestSnapshotGenerationFencingF9:
    """Verifies that snapshot restore attempts with stale generation numbers are rejected."""

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

    def test_stale_generation_snapshot_rejected(self):
        task = RemediationTask("task_gen", "find_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        self.repo.create_task(task)

        with self.sf.session_scope() as session:
            # Create checkpoint with Generation 14
            RecoveryCheckpoint.save_checkpoint(session, "chk_14", generation=14)

            # Attempt to restore snapshot from Generation 13
            snapshot_gen_13 = SnapshotManager.create_snapshot(session, generation=13)

            with pytest.raises(SnapshotFencingError, match="Stale snapshot generation 13 rejected"):
                SnapshotManager.load_snapshot(session, snapshot_gen_13)
