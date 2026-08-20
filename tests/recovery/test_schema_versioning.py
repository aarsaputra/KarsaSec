"""Test schema version safety and compatibility enforcement (INV-F9-VERSION-06)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from karsasec.persistence.models import Base
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.recovery import SchemaMismatchError
from karsasec.recovery.snapshot import SnapshotManager


class TestSchemaVersioningF9:
    """Verifies that snapshots from incompatible schema versions are rejected during restore."""

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

    def test_incompatible_schema_version_rejected(self):
        task = RemediationTask("task_schema", "find_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        self.repo.create_task(task)

        with self.sf.session_scope() as session:
            snapshot = SnapshotManager.create_snapshot(session, generation=1)
            snapshot["schema_version"] = 99  # Incompatible version

            with pytest.raises(SchemaMismatchError, match="incompatible"):
                SnapshotManager.load_snapshot(session, snapshot)
