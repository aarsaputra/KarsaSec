"""Test snapshot payload and Merkle-lite root hash corruption detection (INV-F9-HASH-05)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from karsasec.persistence.models import Base
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.recovery import SnapshotIntegrityError
from karsasec.recovery.snapshot import SnapshotManager


class TestSnapshotCorruptionF9:
    """Verifies that 1-byte alteration in snapshot payload or root hash raises SnapshotIntegrityError."""

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

    def test_corrupted_task_payload_raises_snapshot_integrity_error(self):
        task = RemediationTask("task_corrupt", "find_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        self.repo.create_task(task)

        with self.sf.session_scope() as session:
            snapshot = SnapshotManager.create_snapshot(session, generation=1)

            # Corrupt 1 task field value
            snapshot["tasks"][0]["state"] = "CORRUPTED"

            with pytest.raises(SnapshotIntegrityError, match="payload hash mismatch"):
                SnapshotManager.verify_snapshot(snapshot)

    def test_corrupted_root_hash_raises_snapshot_integrity_error(self):
        task = RemediationTask("task_corrupt_root", "find_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        self.repo.create_task(task)

        with self.sf.session_scope() as session:
            snapshot = SnapshotManager.create_snapshot(session, generation=1)

            # Corrupt 1 char in root_hash
            snapshot["root_hash"] = "0" * 64

            with pytest.raises(SnapshotIntegrityError, match="root hash verification failed"):
                SnapshotManager.verify_snapshot(snapshot)
