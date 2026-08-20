"""Sprint F7 — Worker Authority Enforcement Adversarial Test Suite.

Verifies WorkerAuthority(W) and TaskAuthority(T, W) enforcement:
  MutationAllowed(T, W) = WorkerAuthority(W) AND TaskAuthority(T, W)
"""

import pytest
from sqlalchemy import create_engine

from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base, WorkerModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.workers.task import (
    RemediationTask,
    TaskState,
    WorkerFencedError,
    StaleLeaseVersionError,
    InvalidTaskStateError,
    InvalidWorkerStateError,
)


@pytest.fixture
def session_factory(tmp_path):
    """Fixture providing isolated SQLite WAL database simulating PostgreSQL atomic semantics."""
    db_path = tmp_path / "test_f7_worker_auth.db"
    engine = create_engine(f"sqlite:///{db_path}", connect_args={"timeout": 15})
    Base.metadata.create_all(engine)
    with engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL")

    factory = DatabaseSessionFactory(url=f"sqlite:///{db_path}")
    return factory


@pytest.fixture
def repo(session_factory):
    return PostgresTaskRepository(session_factory=session_factory)


def _create_test_worker(session_factory, worker_id: str, status: str = "ONLINE", fencing_token: int = 1):
    with session_factory.session_scope() as session:
        w = WorkerModel(
            worker_id=worker_id,
            auth_token_hash="hash_123",
            hostname="host-1",
            status=status,
            fencing_token=fencing_token,
        )
        session.add(w)


class TestWorkerAuthorityF7:
    def test_valid_online_worker_completes_running_task(self, session_factory, repo):
        """ONLINE worker with valid token completes assigned RUNNING task."""
        _create_test_worker(session_factory, "worker_1", status="ONLINE", fencing_token=1)

        task = RemediationTask("task_1", "f_1", "tok_1", "", "fp_1", state=TaskState.QUEUED)
        repo.create_task(task)

        # Assign task
        assigned = repo.assign_task("task_1", "worker_1")
        assert assigned.state == TaskState.RUNNING
        assert assigned.attempts == 1
        assert assigned.lease_version == 2

        # Complete task
        completed = repo.complete_task(
            task_id="task_1",
            expected_lease_version=2,
            worker_id="worker_1",
            worker_fencing_token=1,
            receipt_id="rec_100",
            receipt_fingerprint="fp_rec_100",
            security_verification_status="VERIFIED",
        )
        assert completed.state == TaskState.COMPLETED
        assert completed.attempts == 1  # attempts NOT incremented on completion
        assert completed.lease_version == 3

    def test_draining_worker_can_complete_active_task(self, session_factory, repo):
        """DRAINING worker can complete active RUNNING task assigned before drain initiated."""
        _create_test_worker(session_factory, "worker_drain", status="ONLINE", fencing_token=5)

        task = RemediationTask("task_drain", "f_1", "tok_1", "", "fp_1", state=TaskState.QUEUED)
        repo.create_task(task)

        assigned = repo.assign_task("task_drain", "worker_drain")
        assert assigned.state == TaskState.RUNNING

        # Transition worker status to DRAINING
        with session_factory.session_scope() as session:
            w = session.scalar(WorkerModel.__table__.select().where(WorkerModel.worker_id == "worker_drain"))
            session.execute(
                WorkerModel.__table__.update().where(WorkerModel.worker_id == "worker_drain").values(status="DRAINING")
            )

        # DRAINING worker completes active task
        completed = repo.complete_task(
            task_id="task_drain",
            expected_lease_version=assigned.lease_version,
            worker_id="worker_drain",
            worker_fencing_token=5,
        )
        assert completed.state == TaskState.COMPLETED

    def test_draining_worker_cannot_receive_new_assignment(self, session_factory, repo):
        """DRAINING worker is rejected for NEW assignment."""
        _create_test_worker(session_factory, "worker_drain_new", status="DRAINING", fencing_token=1)

        task = RemediationTask("task_new", "f_1", "tok_1", "", "fp_1", state=TaskState.QUEUED)
        repo.create_task(task)

        with pytest.raises(InvalidWorkerStateError, match="ONLINE"):
            repo.assign_task("task_new", "worker_drain_new")

    def test_fenced_worker_cannot_complete_task(self, session_factory, repo):
        """FENCED worker cannot complete task."""
        _create_test_worker(session_factory, "worker_fenced", status="ONLINE", fencing_token=1)

        task = RemediationTask("task_f", "f_1", "tok_1", "", "fp_1", state=TaskState.QUEUED)
        repo.create_task(task)
        assigned = repo.assign_task("task_f", "worker_fenced")

        # Worker is fenced (status = FENCED, fencing_token bumped)
        with session_factory.session_scope() as session:
            session.execute(
                WorkerModel.__table__.update()
                .where(WorkerModel.worker_id == "worker_fenced")
                .values(status="FENCED", fencing_token=2)
            )

        with pytest.raises(WorkerFencedError):
            repo.complete_task(
                task_id="task_f",
                expected_lease_version=assigned.lease_version,
                worker_id="worker_fenced",
                worker_fencing_token=1,  # Stale token
            )

    def test_fenced_worker_cannot_report_failure(self, session_factory, repo):
        """FENCED worker cannot report execution failure."""
        _create_test_worker(session_factory, "worker_fenced_fail", status="ONLINE", fencing_token=1)

        task = RemediationTask("task_ff", "f_1", "tok_1", "", "fp_1", state=TaskState.QUEUED)
        repo.create_task(task)
        assigned = repo.assign_task("task_ff", "worker_fenced_fail")

        # Fence worker
        with session_factory.session_scope() as session:
            session.execute(
                WorkerModel.__table__.update()
                .where(WorkerModel.worker_id == "worker_fenced_fail")
                .values(status="FENCED", fencing_token=2)
            )

        with pytest.raises(WorkerFencedError):
            repo.record_execution_failure(
                task_id="task_ff",
                expected_lease_version=assigned.lease_version,
                worker_id="worker_fenced_fail",
                worker_fencing_token=1,
                error_message="Failure report after fencing",
            )

    def test_wrong_worker_id_cannot_mutate_task(self, session_factory, repo):
        """Worker W2 cannot complete task assigned to W1."""
        _create_test_worker(session_factory, "w1", status="ONLINE", fencing_token=1)
        _create_test_worker(session_factory, "w2", status="ONLINE", fencing_token=1)

        task = RemediationTask("task_owner", "f_1", "tok_1", "", "fp_1", state=TaskState.QUEUED)
        repo.create_task(task)
        assigned = repo.assign_task("task_owner", "w1")

        with pytest.raises(WorkerFencedError):
            repo.complete_task(
                task_id="task_owner",
                expected_lease_version=assigned.lease_version,
                worker_id="w2",
                worker_fencing_token=1,
            )

    def test_stale_lease_version_rejected(self, session_factory, repo):
        """Mutation with stale lease_version is rejected with StaleLeaseVersionError."""
        _create_test_worker(session_factory, "w_stale", status="ONLINE", fencing_token=1)

        task = RemediationTask("task_stale_lease", "f_1", "tok_1", "", "fp_1", state=TaskState.QUEUED)
        repo.create_task(task)
        repo.assign_task("task_stale_lease", "w_stale")

        with pytest.raises(StaleLeaseVersionError):
            repo.complete_task(
                task_id="task_stale_lease",
                expected_lease_version=999,  # Invalid lease_version
                worker_id="w_stale",
                worker_fencing_token=1,
            )

    def test_terminal_task_resurrection_blocked(self, session_factory, repo):
        """COMPLETED task cannot be mutated or resurrected to RUNNING or QUEUED."""
        _create_test_worker(session_factory, "w_term", status="ONLINE", fencing_token=1)

        task = RemediationTask("task_term", "f_1", "tok_1", "", "fp_1", state=TaskState.QUEUED)
        repo.create_task(task)
        assigned = repo.assign_task("task_term", "w_term")

        repo.complete_task(
            task_id="task_term",
            expected_lease_version=assigned.lease_version,
            worker_id="w_term",
            worker_fencing_token=1,
        )

        with pytest.raises(InvalidTaskStateError, match="Terminal state"):
            repo.atomic_transition(
                task_id="task_term",
                expected_lease_version=assigned.lease_version + 1,
                expected_states=[TaskState.COMPLETED],
                new_state=TaskState.RUNNING,
            )
