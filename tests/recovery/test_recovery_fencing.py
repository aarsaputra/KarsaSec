"""Test recovery lease fencing and split-recovery rejection (INV-F9-FENCE-07)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from karsasec.persistence.models import Base
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.recovery import RecoveryFencingError
from karsasec.recovery.checkpoint import RecoveryCheckpoint


class TestRecoveryFencingF9:
    """Verifies atomic recovery lease fencing preventing concurrent node restore races."""

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

    def test_concurrent_split_recovery_node_rejected(self):
        task = RemediationTask("task_fence", "find_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        self.repo.create_task(task)

        with self.sf.session_scope() as session:
            # Node A creates checkpoint with lease token 'token_node_a'
            RecoveryCheckpoint.save_checkpoint(
                session, "chk_fence_1", generation=1, recovery_id="node_a", recovery_lease_token="token_node_a"
            )

        # Node B attempts to restore checkpoint using 'token_node_b'
        with self.sf.session_scope() as session:
            with pytest.raises(RecoveryFencingError, match="checkpoint owned by lease token"):
                RecoveryCheckpoint.restore_checkpoint(
                    session, "chk_fence_1", recovery_id="node_b", recovery_lease_token="token_node_b"
                )
