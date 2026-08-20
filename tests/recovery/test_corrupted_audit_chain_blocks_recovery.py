"""Test mandatory pre-replay audit chain integrity validation (INV-F9-RECOVERY-12)."""

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from karsasec.persistence.models import Base, TaskAuditLogModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.recovery import AuditCorruptionError
from karsasec.recovery.snapshot import SnapshotManager
from karsasec.recovery.replay import AuditReplayEngine


class TestAuditChainValidationF9:
    """Verifies that audit log chain corruption blocks recovery replay execution immediately."""

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

    def test_corrupted_audit_chain_blocks_replay(self):
        task = RemediationTask("task_audit_corrupt", "find_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        self.repo.create_task(task)

        with self.sf.session_scope() as session:
            snapshot = SnapshotManager.create_snapshot(session, generation=1)

            # Tamper directly with the audit log entry's event_hash
            audit_entry = session.scalar(
                select(TaskAuditLogModel).where(TaskAuditLogModel.task_id == "task_audit_corrupt")
            )
            assert audit_entry is not None
            audit_entry.event_hash = "bad_hash_val_000000000000000000000000000000000000000000000000"
            session.flush()

            with pytest.raises(AuditCorruptionError, match="integrity verification failed"):
                AuditReplayEngine.replay_events(session, snapshot)
