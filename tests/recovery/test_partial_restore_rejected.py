"""Test fail-closed partial restore protection (INV-F9-RECOVERY-09)."""

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from karsasec.persistence.models import Base
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.recovery import PartialRecoveryError
from karsasec.recovery.replay import AuditReplayEngine


class TestPartialRestoreF9:
    """Verifies that missing audit tables or persistence tables during recovery raise PartialRecoveryError."""

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

    def test_missing_audit_log_table_fails_closed(self):
        task = RemediationTask("task_part", "find_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        self.repo.create_task(task)

        with self.sf.session_scope() as session:
            # Drop task_audit_log table to simulate partial DB restore failure
            session.execute(text("DROP TABLE task_audit_log"))
            session.flush()

            with pytest.raises(PartialRecoveryError, match="missing or incomplete"):
                AuditReplayEngine.verify_restore_integrity(session)
