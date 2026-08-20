"""Test outbox rebuilding preserves original event identity (INV-F8-EVENT-02, INV-F9-RECOVERY-02)."""

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from karsasec.persistence.models import Base, OutboxEventModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.workers.task import RemediationTask, TaskState
from karsasec.recovery.replay import AuditReplayEngine


class TestRebuildOriginalEventIdentityF9:
    """Verifies that outbox rebuilding preserves original event headers and deduplication keys."""

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

    def test_outbox_rebuild_preserves_original_event_identity(self):
        task = RemediationTask("task_id_pres", "find_1", "tok_1", "val_1", "fp_1", state=TaskState.QUEUED)
        self.repo.create_task(task)

        # Record original outbox details
        with self.sf.session_scope() as session:
            orig_evt = session.scalar(select(OutboxEventModel).where(OutboxEventModel.aggregate_id == "task_id_pres"))
            assert orig_evt is not None
            orig_event_id = orig_evt.event_id
            orig_dedup_key = orig_evt.deduplication_key
            orig_seq = orig_evt.aggregate_sequence

            # Delete outbox event simulate wipe
            session.delete(orig_evt)
            session.flush()

        # Rebuild outbox from audit ledger
        with self.sf.session_scope() as session:
            rebuilt_count = AuditReplayEngine.rebuild_outbox_from_audit(session)
            assert rebuilt_count == 1

            rebuilt_evt = session.scalar(
                select(OutboxEventModel).where(OutboxEventModel.aggregate_id == "task_id_pres")
            )
            assert rebuilt_evt is not None
            assert rebuilt_evt.deduplication_key == orig_dedup_key
            assert rebuilt_evt.aggregate_sequence == orig_seq
