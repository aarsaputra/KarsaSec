"""Test outbox rebuilding from authoritative audit ledger (INV-F9-RECOVERY-02)."""

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from karsasec.persistence.models import Base, OutboxEventModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.recovery.replay import AuditReplayEngine


class TestOutboxRebuildF9:
    """Verifies that lost outbox events can be completely rebuilt from the audit log stream."""

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

    def test_outbox_wipe_and_rebuild_success(self):
        task1 = RemediationTask("t_reb_1", "f_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        task2 = RemediationTask("t_reb_2", "f_2", "tok_2", "val_2", "fp_2", state=TaskState.QUEUED)
        self.repo.create_task(task1)
        self.repo.create_task(task2)

        with self.sf.session_scope() as session:
            # Wipe outbox completely
            for evt in session.scalars(select(OutboxEventModel)).all():
                session.delete(evt)
            session.flush()

            # Verify 0 outbox events
            assert len(session.scalars(select(OutboxEventModel)).all()) == 0

            # Rebuild outbox
            rebuilt_count = AuditReplayEngine.rebuild_outbox_from_audit(session)
            assert rebuilt_count == 2

            events = list(session.scalars(select(OutboxEventModel)).all())
            assert len(events) == 2
            assert {e.aggregate_id for e in events} == {"t_reb_1", "t_reb_2"}
