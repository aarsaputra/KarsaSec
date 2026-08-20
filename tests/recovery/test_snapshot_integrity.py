"""Test snapshot integrity and 100x deterministic generation (INV-F9-SNAP-01, INV-F9-HASH-05)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from karsasec.persistence.models import Base
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.recovery.snapshot import SnapshotManager


class TestSnapshotIntegrityF9:
    """Verifies deterministic snapshot creation and Merkle-lite root hash calculations."""

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

    def test_snapshot_generation_100x_deterministic(self):
        task1 = RemediationTask("task_1", "find_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        task2 = RemediationTask("task_2", "find_2", "tok_2", "val_2", "fp_2", state=TaskState.QUEUED)
        self.repo.create_task(task1)
        self.repo.create_task(task2)

        with self.sf.session_scope() as session:
            first_snapshot = SnapshotManager.create_snapshot(session, generation=1)

            for _ in range(100):
                subsequent = SnapshotManager.create_snapshot(session, generation=1)
                assert subsequent["root_hash"] == first_snapshot["root_hash"]
                assert subsequent["snapshot_hash"] == first_snapshot["snapshot_hash"]
                assert SnapshotManager.verify_snapshot(subsequent) is True
