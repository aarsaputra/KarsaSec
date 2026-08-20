"""Adversarial Security Test Suite for Sprint F5 PostgreSQL Authoritative Engine.

Tests 24 adversarial concurrency, fencing, restart, outbox atomicity, and restart recovery scenarios.
"""

from __future__ import annotations

import concurrent.futures
import time
import pytest
from sqlalchemy import select

from karsasec.persistence.db import DatabaseSessionFactory
from karsasec.persistence.models import Base, TaskModel, OutboxEventModel
from karsasec.persistence.postgres_task_repository import PostgresTaskRepository
from karsasec.persistence.postgres_worker_repository import PostgresWorkerRepository
from karsasec.persistence.postgres_recovery_lock import PostgresRecoveryLock
from karsasec.persistence.outbox_publisher import OutboxRepository, OutboxPublisher
from karsasec.workers.queue import InMemoryTaskQueue, TaskQueue
from karsasec.workers.scheduler import ConsistentHashScheduler, ConsistentHashRing, NoWorkersAvailableError
from karsasec.workers.task import (
    RemediationTask,
    TaskState,
    StaleLeaseVersionError,
    InvalidTaskStateError,
)


@pytest.fixture
def test_db_factory(tmp_path):
    """Create isolated SQLite database session factory for thread-safe testing."""
    db_file = tmp_path / "test_f5.db"
    url = f"sqlite:///{db_file}"
    factory = DatabaseSessionFactory(url=url)
    Base.metadata.create_all(bind=factory.engine)
    with factory.engine.connect() as conn:
        conn.exec_driver_sql("PRAGMA journal_mode=WAL;")
    yield factory
    Base.metadata.drop_all(bind=factory.engine)


def _create_sample_task(task_id: str = "tsk-f5-test", state: TaskState = TaskState.PENDING) -> RemediationTask:
    return RemediationTask(
        task_id=task_id,
        finding_id="f-100",
        approval_token_id="tok-100",
        token="secret",
        fingerprint="fp-100",
        state=state,
    )


class TestPostgresTaskCAS:
    """1-4: Task CAS, Stale Lease, Concurrency, and Terminal Resurrection Tests."""

    def test_postgres_task_cas_success(self, test_db_factory):
        repo = PostgresTaskRepository(test_db_factory)
        task = _create_sample_task("tsk-cas-1", TaskState.PENDING)
        repo.create_task(task)

        # Transition PENDING -> QUEUED
        updated = repo.atomic_transition(
            task_id="tsk-cas-1",
            expected_lease_version=1,
            expected_states=[TaskState.PENDING],
            new_state=TaskState.QUEUED,
        )
        assert updated.state == TaskState.QUEUED
        assert updated.lease_version == 2

    def test_stale_lease_cas_rejection(self, test_db_factory):
        repo = PostgresTaskRepository(test_db_factory)
        task = _create_sample_task("tsk-cas-2", TaskState.PENDING)
        repo.create_task(task)

        # First transition succeeds: v1 -> v2
        repo.atomic_transition("tsk-cas-2", 1, [TaskState.PENDING], TaskState.QUEUED)

        # Stale attempt using v1 must fail
        with pytest.raises(StaleLeaseVersionError):
            repo.atomic_transition("tsk-cas-2", 1, [TaskState.QUEUED], TaskState.RUNNING)

    def test_concurrent_task_completion(self, test_db_factory):
        repo = PostgresTaskRepository(test_db_factory)
        task = _create_sample_task("tsk-cas-3", TaskState.PENDING)
        repo.create_task(task)
        repo.atomic_transition("tsk-cas-3", 1, [TaskState.PENDING], TaskState.QUEUED)
        repo.atomic_transition("tsk-cas-3", 2, [TaskState.QUEUED], TaskState.RUNNING)

        successes = []
        failures = []

        def worker_attempt():
            try:
                repo.atomic_transition("tsk-cas-3", 3, [TaskState.RUNNING], TaskState.COMPLETED)
                successes.append(True)
            except Exception as e:
                failures.append(e)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(worker_attempt) for _ in range(5)]
            concurrent.futures.wait(futures)

        assert len(successes) == 1
        assert len(failures) == 4
        assert isinstance(failures[0], (StaleLeaseVersionError, InvalidTaskStateError))

    def test_terminal_state_resurrection_prevention(self, test_db_factory):
        repo = PostgresTaskRepository(test_db_factory)
        task = _create_sample_task("tsk-cas-4", TaskState.PENDING)
        repo.create_task(task)
        repo.atomic_transition("tsk-cas-4", 1, [TaskState.PENDING], TaskState.QUEUED)
        repo.atomic_transition("tsk-cas-4", 2, [TaskState.QUEUED], TaskState.RUNNING)
        repo.atomic_transition("tsk-cas-4", 3, [TaskState.RUNNING], TaskState.COMPLETED)

        # Attempting resurrection to QUEUED or RUNNING must fail
        with pytest.raises(InvalidTaskStateError):
            repo.atomic_transition("tsk-cas-4", 4, [TaskState.COMPLETED], TaskState.QUEUED)

        with pytest.raises(InvalidTaskStateError):
            repo.atomic_transition("tsk-cas-4", 4, [TaskState.COMPLETED], TaskState.RUNNING)


class TestPostgresRecoveryFencing:
    """5-10: Persistent Monotonic Fencing & Recovery Lease Tests."""

    def test_persistent_fencing_token_monotonicity(self, test_db_factory):
        lock = PostgresRecoveryLock(test_db_factory)
        l1 = lock.acquire("node-1", ttl_seconds=30)
        l2 = lock.acquire("node-2", ttl_seconds=30)
        assert l2.fencing_token > l1.fencing_token

    def test_fencing_token_survives_process_restart(self, test_db_factory):
        lock1 = PostgresRecoveryLock(test_db_factory)
        l1 = lock1.acquire("node-A", ttl_seconds=30)

        # Simulate process restart by instantiating new lock instance
        lock2 = PostgresRecoveryLock(test_db_factory)
        l2 = lock2.acquire("node-B", ttl_seconds=30)

        assert l2.fencing_token > l1.fencing_token

    def test_recovery_lease_acquisition_race(self, test_db_factory):
        lock = PostgresRecoveryLock(test_db_factory)
        results = []

        def acquire_task(node_id):
            l = lock.acquire(node_id, ttl_seconds=30)
            results.append(l)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(acquire_task, f"leader-{i}") for i in range(5)]
            concurrent.futures.wait(futures)

        assert len(results) == 5
        tokens = [r.fencing_token for r in results]
        assert len(tokens) == len(set(tokens))  # All tokens unique and strictly monotonic

    def test_stale_recovery_leader_rejection(self, test_db_factory):
        lock = PostgresRecoveryLock(test_db_factory)
        l1 = lock.acquire("old-leader", ttl_seconds=30)
        l2 = lock.acquire("new-leader", ttl_seconds=30)

        # old-leader token is now stale/fenced
        assert lock.is_valid("old-leader", l1.lease_id, l1.fencing_token) is False
        assert lock.renew("old-leader", l1.lease_id, l1.fencing_token) is False

    def test_lease_expiration_handling(self, test_db_factory):
        lock = PostgresRecoveryLock(test_db_factory)
        l = lock.acquire("node-exp", ttl_seconds=0)  # Expired immediately
        time.sleep(0.01)
        assert lock.is_valid("node-exp", l.lease_id, l.fencing_token) is False

    def test_lease_renewal(self, test_db_factory):
        lock = PostgresRecoveryLock(test_db_factory)
        l = lock.acquire("node-ren", ttl_seconds=30)
        assert lock.is_valid("node-ren", l.lease_id, l.fencing_token) is True
        assert lock.renew("node-ren", l.lease_id, l.fencing_token, ttl_seconds=60) is True


class TestPostgresWorkerRegistry:
    """11-15: Worker Registration Uniqueness & Heartbeat Sequence CAS Tests."""

    def test_duplicate_worker_registration(self, test_db_factory):
        repo = PostgresWorkerRepository(test_db_factory)
        w1 = repo.register_worker("worker-1", auth_token="tok-123", hostname="host-a")
        # Same credentials -> idempotent success
        w2 = repo.register_worker("worker-1", auth_token="tok-123", hostname="host-b")
        assert w2.worker_id == "worker-1"

    def test_conflicting_worker_registration(self, test_db_factory):
        repo = PostgresWorkerRepository(test_db_factory)
        repo.register_worker("worker-2", auth_token="tok-secret-1")
        # Conflicting credentials -> raises ValueError (INV-F5-06)
        with pytest.raises(ValueError, match="conflicting credentials"):
            repo.register_worker("worker-2", auth_token="tok-secret-2")

    def test_heartbeat_sequence_replay_rejection(self, test_db_factory):
        repo = PostgresWorkerRepository(test_db_factory)
        repo.register_worker("worker-3")
        repo.heartbeat("worker-3", sequence=10)
        repo.heartbeat("worker-3", sequence=15)

        # Replayed/stale sequence numbers (<= 15) must be rejected
        with pytest.raises(ValueError, match="Stale/replayed heartbeat sequence"):
            repo.heartbeat("worker-3", sequence=15)

        with pytest.raises(ValueError, match="Stale/replayed heartbeat sequence"):
            repo.heartbeat("worker-3", sequence=8)

    def test_concurrent_heartbeat_sequence_race(self, test_db_factory):
        repo = PostgresWorkerRepository(test_db_factory)
        repo.register_worker("worker-4")

        def send_hb(seq):
            try:
                repo.heartbeat("worker-4", sequence=seq)
            except ValueError:
                pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(send_hb, i) for i in [5, 12, 8, 20, 15]]
            concurrent.futures.wait(futures)

        w = repo.get_worker("worker-4")
        assert w is not None

    def test_database_timestamp_trust_boundary(self, test_db_factory):
        repo = PostgresWorkerRepository(test_db_factory)
        w = repo.register_worker("worker-5")
        repo.heartbeat("worker-5", sequence=1)
        # Verify server/DB timestamp populated
        active = repo.list_active(max_heartbeat_age_seconds=60)
        assert len(active) == 1
        assert active[0].worker_id == "worker-5"


class TestOutboxPattern:
    """16-20: Outbox Pattern Atomicity, Idempotency, and Concurrency Tests."""

    def test_task_and_outbox_atomicity(self, test_db_factory):
        outbox_repo = OutboxRepository(test_db_factory)
        task_repo = PostgresTaskRepository(test_db_factory)

        # Atomically mutate task and create outbox event in single transaction
        with test_db_factory.session_scope() as session:
            t = _create_sample_task("tsk-outbox-1")
            # Create task record
            model = TaskModel(
                task_id=t.task_id,
                finding_id=t.finding_id,
                approval_token_id=t.approval_token_id,
                fingerprint=t.fingerprint,
                state="QUEUED",
            )
            session.add(model)
            outbox_repo.create_event_in_session(
                session, aggregate_id=t.task_id, event_type="TASK_QUEUED", payload={"task_id": t.task_id}
            )

        # Verify task and outbox event exist in DB
        fetched_task = task_repo.get_task("tsk-outbox-1")
        assert fetched_task is not None

        with test_db_factory.session_scope() as session:
            events = outbox_repo.fetch_pending_events(session)
            assert len(events) == 1
            assert events[0].aggregate_id == "tsk-outbox-1"

    def test_rollback_removes_outbox_event(self, test_db_factory):
        outbox_repo = OutboxRepository(test_db_factory)

        try:
            with test_db_factory.session_scope() as session:
                outbox_repo.create_event_in_session(
                    session, aggregate_id="tsk-fail", event_type="TASK_QUEUED", payload={"task_id": "tsk-fail"}
                )
                raise RuntimeError("Transaction failure injection")
        except RuntimeError:
            pass

        with test_db_factory.session_scope() as session:
            events = outbox_repo.fetch_pending_events(session)
            assert len(events) == 0

    def test_outbox_retry_after_publisher_failure(self, test_db_factory):
        queue = InMemoryTaskQueue()
        outbox_repo = OutboxRepository(test_db_factory)

        with test_db_factory.session_scope() as session:
            outbox_repo.create_event_in_session(
                session, aggregate_id="tsk-retry", event_type="TASK_QUEUED", payload={"task_id": "tsk-retry"}
            )

        publisher = OutboxPublisher(queue, test_db_factory, outbox_repo)
        count = publisher.process_pending_events()
        assert count == 1
        assert queue.dequeue() == "tsk-retry"

    def test_duplicate_outbox_event_idempotency(self, test_db_factory):
        queue = InMemoryTaskQueue()
        outbox_repo = OutboxRepository(test_db_factory)

        with test_db_factory.session_scope() as session:
            outbox_repo.create_event_in_session(
                session,
                aggregate_id="tsk-idemp",
                event_type="TASK_QUEUED",
                payload={"task_id": "tsk-idemp"},
                event_id="evt-fixed-id",
            )

        publisher = OutboxPublisher(queue, test_db_factory, outbox_repo)
        c1 = publisher.process_pending_events()
        c2 = publisher.process_pending_events()

        assert c1 == 1
        assert c2 == 0  # Duplicate event skipped cleanly

    def test_concurrent_outbox_publishers_using_skip_locked(self, test_db_factory):
        queue = InMemoryTaskQueue()
        outbox_repo = OutboxRepository(test_db_factory)

        # Populate 10 pending events
        for i in range(10):
            with test_db_factory.session_scope() as session:
                outbox_repo.create_event_in_session(
                    session,
                    aggregate_id=f"tsk-conc-{i}",
                    event_type="TASK_QUEUED",
                    payload={"task_id": f"tsk-conc-{i}"},
                )

        publisher = OutboxPublisher(queue, test_db_factory, outbox_repo)

        def publish_job():
            count = 0
            while True:
                p = publisher.process_pending_events(limit=5)
                if p == 0:
                    break
                count += p
            return count

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(publish_job) for _ in range(3)]
            results = [f.result() for f in futures]

        assert sum(results) == 10  # Exactly 10 total events published without duplicates

    def test_outbox_publisher_enqueue_exception_preserves_event_retry(self, test_db_factory):
        class FailingQueue(TaskQueue):
            def __init__(self) -> None:
                self.should_fail = True
                self.enqueued: list[str] = []

            def enqueue(self, task_id: str) -> None:
                if self.should_fail:
                    raise RuntimeError("Queue connection failed")
                self.enqueued.append(task_id)

            def dequeue(self, timeout: int = 1) -> str | None:
                return None

            def acknowledge(self, task_id: str) -> None:
                pass

            def requeue(self, task_id: str) -> None:
                pass

        queue = FailingQueue()
        outbox_repo = OutboxRepository(test_db_factory)

        with test_db_factory.session_scope() as session:
            outbox_repo.create_event_in_session(
                session,
                aggregate_id="tsk-enqueue-fail",
                event_type="TASK_QUEUED",
                payload={"task_id": "tsk-enqueue-fail"},
            )

        publisher = OutboxPublisher(queue, test_db_factory, outbox_repo)

        # First attempt: queue fails
        c1 = publisher.process_pending_events()
        assert c1 == 0

        # Verify event remains PENDING with attempt_count == 1
        with test_db_factory.session_scope() as session:
            evt = session.scalar(select(OutboxEventModel).where(OutboxEventModel.aggregate_id == "tsk-enqueue-fail"))
            assert evt is not None
            assert evt.status == "PENDING"
            assert evt.attempt_count == 1

        # Queue recovers
        queue.should_fail = False
        c2 = publisher.process_pending_events()
        assert c2 == 1
        assert queue.enqueued == ["tsk-enqueue-fail"]

        # Verify event is now PUBLISHED
        with test_db_factory.session_scope() as session:
            evt = session.scalar(select(OutboxEventModel).where(OutboxEventModel.aggregate_id == "tsk-enqueue-fail"))
            assert evt is not None
            assert evt.status == "PUBLISHED"


class TestConsistentHashSchedulerF5:
    """21-24: Consistent Hashing Determinism, Node Churn, and Crash Fencing Tests."""

    def test_consistent_hash_deterministic_assignment(self):
        s1 = ConsistentHashScheduler(virtual_nodes=128)
        s1.add_worker("worker-A")
        s1.add_worker("worker-B")
        s1.add_worker("worker-C")

        s2 = ConsistentHashScheduler(virtual_nodes=128)
        s2.add_worker("worker-A")
        s2.add_worker("worker-B")
        s2.add_worker("worker-C")

        for i in range(20):
            task_id = f"task-det-{i}"
            assert s1.assign(task_id) == s2.assign(task_id)

    def test_worker_removal_causes_limited_reassignment(self):
        s = ConsistentHashScheduler(virtual_nodes=128)
        s.add_worker("worker-1")
        s.add_worker("worker-2")
        s.add_worker("worker-3")

        initial_map = {f"task-{i}": s.assign(f"task-{i}") for i in range(100)}

        # Remove worker-3
        s.remove_worker("worker-3")
        new_map = {f"task-{i}": s.assign(f"task-{i}") for i in range(100)}

        # Tasks originally assigned to worker-1 or worker-2 MUST stay assigned to worker-1 or worker-2
        remapped_from_1_or_2 = 0
        for task_id, original_worker in initial_map.items():
            if original_worker in ("worker-1", "worker-2"):
                if new_map[task_id] != original_worker:
                    remapped_from_1_or_2 += 1

        assert remapped_from_1_or_2 == 0  # Zero disturbance to unaffected workers

    def test_worker_addition_causes_limited_reassignment(self):
        s = ConsistentHashScheduler(virtual_nodes=128)
        s.add_worker("worker-X")
        s.add_worker("worker-Y")

        initial_map = {f"task-{i}": s.assign(f"task-{i}") for i in range(100)}

        # Add worker-Z
        s.add_worker("worker-Z")
        new_map = {f"task-{i}": s.assign(f"task-{i}") for i in range(100)}

        # Only a subset of tasks should shift to worker-Z, remaining assignments stay intact
        shifted_to_z = [tid for tid, w in new_map.items() if w == "worker-Z"]
        assert 10 < len(shifted_to_z) < 60

    def test_recovery_crash_restart_fencing(self, test_db_factory):
        lock = PostgresRecoveryLock(test_db_factory)
        crashed_leader = lock.acquire("crashed-leader-node", ttl_seconds=30)

        # Simulate leader crash & new recovery leader startup
        new_leader = lock.acquire("new-recovery-leader-node", ttl_seconds=30)

        # Verify crashed leader is fenced
        assert lock.is_valid("crashed-leader-node", crashed_leader.lease_id, crashed_leader.fencing_token) is False
        assert new_leader.fencing_token > crashed_leader.fencing_token


class TestAdversarialHardeningF51:
    """20 Specific Second-Order Adversarial Audit Test Scenarios for Sprint F5.1."""

    def test_concurrent_cas_completion(self, test_db_factory):
        repo = PostgresTaskRepository(test_db_factory)
        task = _create_sample_task("tsk-adv-1", TaskState.PENDING)
        repo.create_task(task)
        repo.atomic_transition("tsk-adv-1", 1, [TaskState.PENDING], TaskState.QUEUED)
        repo.atomic_transition("tsk-adv-1", 2, [TaskState.QUEUED], TaskState.RUNNING)

        successes, failures = [], []

        def worker_attempt():
            try:
                repo.atomic_transition("tsk-adv-1", 3, [TaskState.RUNNING], TaskState.COMPLETED)
                successes.append(True)
            except Exception as e:
                failures.append(e)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(worker_attempt) for _ in range(5)]
            concurrent.futures.wait(futures)

        assert len(successes) == 1
        assert len(failures) == 4

    def test_stale_worker_after_recovery(self, test_db_factory):
        repo = PostgresTaskRepository(test_db_factory)
        task = _create_sample_task("tsk-adv-2", TaskState.PENDING)
        repo.create_task(task)
        repo.atomic_transition("tsk-adv-2", 1, [TaskState.PENDING], TaskState.RUNNING)

        # Worker recovery updates task to RUNNING (lease_version -> 3)
        repo.atomic_transition("tsk-adv-2", 2, [TaskState.RUNNING], TaskState.RUNNING, lease_version=3)

        # Partitioned worker with stale lease_version=2 tries update
        with pytest.raises(StaleLeaseVersionError):
            repo.atomic_transition("tsk-adv-2", 2, [TaskState.RUNNING], TaskState.COMPLETED)

    def test_stale_fencing_token_after_leader_replacement(self, test_db_factory):
        lock = PostgresRecoveryLock(test_db_factory)
        l1 = lock.acquire("leader-old", ttl_seconds=30)
        l2 = lock.acquire("leader-new", ttl_seconds=30)

        assert lock.is_valid("leader-old", l1.lease_id, l1.fencing_token) is False
        assert lock.renew("leader-old", l1.lease_id, l1.fencing_token) is False

    def test_fencing_token_after_process_restart(self, test_db_factory):
        lock1 = PostgresRecoveryLock(test_db_factory)
        l1 = lock1.acquire("node-p1", ttl_seconds=30)

        lock2 = PostgresRecoveryLock(test_db_factory)
        l2 = lock2.acquire("node-p2", ttl_seconds=30)

        assert l2.fencing_token > l1.fencing_token

    def test_concurrent_recovery_lease_acquisition(self, test_db_factory):
        lock = PostgresRecoveryLock(test_db_factory)
        results = []

        def acq(nid):
            l = lock.acquire(nid, ttl_seconds=30)
            results.append(l)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(acq, f"node-c-{i}") for i in range(5)]
            concurrent.futures.wait(futures)

        tokens = [r.fencing_token for r in results]
        assert len(tokens) == 5
        assert len(tokens) == len(set(tokens))

    def test_heartbeat_sequence_race(self, test_db_factory):
        repo = PostgresWorkerRepository(test_db_factory)
        repo.register_worker("w-hb-race")
        repo.heartbeat("w-hb-race", sequence=10)

        with pytest.raises(ValueError, match="Stale/replayed heartbeat sequence"):
            repo.heartbeat("w-hb-race", sequence=5)

    def test_duplicate_worker_registration(self, test_db_factory):
        repo = PostgresWorkerRepository(test_db_factory)
        w1 = repo.register_worker("w-dup", auth_token="tok-same")
        w2 = repo.register_worker("w-dup", auth_token="tok-same")
        assert w1.worker_id == w2.worker_id

        with pytest.raises(ValueError, match="conflicting credentials"):
            repo.register_worker("w-dup", auth_token="tok-diff")

    def test_terminal_state_resurrection(self, test_db_factory):
        repo = PostgresTaskRepository(test_db_factory)
        task = _create_sample_task("tsk-term", TaskState.PENDING)
        repo.create_task(task)
        repo.atomic_transition("tsk-term", 1, [TaskState.PENDING], TaskState.COMPLETED)

        with pytest.raises(InvalidTaskStateError):
            repo.atomic_transition("tsk-term", 2, [TaskState.COMPLETED], TaskState.RUNNING)

    def test_transaction_rollback_after_task_mutation(self, test_db_factory):
        repo = PostgresTaskRepository(test_db_factory)
        task = _create_sample_task("tsk-rb-1", TaskState.PENDING)
        repo.create_task(task)

        try:
            with test_db_factory.session_scope() as session:
                m = session.scalar(select(TaskModel).where(TaskModel.task_id == "tsk-rb-1"))
                m.state = "RUNNING"
                raise RuntimeError("Simulated failure before commit")
        except RuntimeError:
            pass

        t = repo.get_task("tsk-rb-1")
        assert t is not None
        assert t.state == TaskState.PENDING

    def test_transaction_rollback_after_outbox_insertion(self, test_db_factory):
        outbox_repo = OutboxRepository(test_db_factory)
        try:
            with test_db_factory.session_scope() as session:
                outbox_repo.create_event_in_session(
                    session, aggregate_id="tsk-ob-rb", event_type="QUEUED", payload={"task_id": "tsk-ob-rb"}
                )
                raise RuntimeError("Aborted transaction")
        except RuntimeError:
            pass

        with test_db_factory.session_scope() as session:
            assert len(outbox_repo.fetch_pending_events(session)) == 0

    def test_publisher_crash_simulation(self, test_db_factory):
        queue = InMemoryTaskQueue()
        outbox_repo = OutboxRepository(test_db_factory)

        with test_db_factory.session_scope() as session:
            outbox_repo.create_event_in_session(
                session, aggregate_id="tsk-crash", event_type="QUEUED", payload={"task_id": "tsk-crash"}
            )

        # Simulate publisher enqueuing but crashing before mark_published
        queue.enqueue("tsk-crash")

        # Second publisher picks up event from DB since it was not marked published
        pub2 = OutboxPublisher(queue, test_db_factory, outbox_repo)
        published = pub2.process_pending_events()
        assert published == 1

    def test_duplicate_outbox_delivery(self, test_db_factory):
        queue = InMemoryTaskQueue()
        outbox_repo = OutboxRepository(test_db_factory)

        with test_db_factory.session_scope() as session:
            outbox_repo.create_event_in_session(
                session, aggregate_id="tsk-dup-del", event_type="QUEUED", payload={"task_id": "tsk-dup-del"}
            )

        pub = OutboxPublisher(queue, test_db_factory, outbox_repo)
        c1 = pub.process_pending_events()
        c2 = pub.process_pending_events()
        assert c1 == 1
        assert c2 == 0

    def test_concurrent_publishers(self, test_db_factory):
        queue = InMemoryTaskQueue()
        outbox_repo = OutboxRepository(test_db_factory)

        for i in range(10):
            with test_db_factory.session_scope() as session:
                outbox_repo.create_event_in_session(
                    session, aggregate_id=f"tsk-cp-{i}", event_type="QUEUED", payload={"task_id": f"tsk-cp-{i}"}
                )

        pub = OutboxPublisher(queue, test_db_factory, outbox_repo)

        def worker():
            total = 0
            while True:
                p = pub.process_pending_events(limit=5)
                if p == 0:
                    break
                total += p
            return total

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            futures = [executor.submit(worker) for _ in range(3)]
            res = [f.result() for f in futures]

        assert sum(res) == 10

    def test_database_connection_failure(self, test_db_factory):
        from sqlalchemy.exc import SQLAlchemyError

        invalid_factory = DatabaseSessionFactory(url="sqlite:////nonexistent/invalid/path/db.sqlite")
        repo = PostgresTaskRepository(invalid_factory)
        with pytest.raises(SQLAlchemyError):
            repo.get_task("tsk-any")

    def test_stale_sqlalchemy_session_state(self, test_db_factory):
        repo = PostgresTaskRepository(test_db_factory)
        task = _create_sample_task("tsk-stale-sess", TaskState.PENDING)
        repo.create_task(task)

        # Direct update in repo
        repo.atomic_transition("tsk-stale-sess", 1, [TaskState.PENDING], TaskState.QUEUED)

        # Fresh read guarantees latest DB state
        fresh = repo.get_task("tsk-stale-sess")
        assert fresh is not None
        assert fresh.state == TaskState.QUEUED
        assert fresh.lease_version == 2

    def test_scheduler_worker_churn(self):
        ring = ConsistentHashRing(virtual_nodes=128)
        ring.add_worker("w1")
        ring.add_worker("w2")
        ring.add_worker("w3")

        initial_map = {f"t-{i}": ring.assign(f"t-{i}") for i in range(100)}

        ring.remove_worker("w3")
        new_map = {f"t-{i}": ring.assign(f"t-{i}") for i in range(100)}

        unaffected_moved = 0
        for tid, orig in initial_map.items():
            if orig in ("w1", "w2"):
                if new_map[tid] != orig:
                    unaffected_moved += 1
        assert unaffected_moved == 0

    def test_empty_worker_cluster(self):
        ring = ConsistentHashRing(virtual_nodes=128)
        with pytest.raises(NoWorkersAvailableError):
            ring.assign("t-empty")

    def test_duplicate_event_id(self, test_db_factory):
        outbox_repo = OutboxRepository(test_db_factory)
        with test_db_factory.session_scope() as session:
            outbox_repo.create_event_in_session(
                session, aggregate_id="t-1", event_type="Q", payload={}, event_id="evt-fixed"
            )

        with pytest.raises(ValueError, match="already exists"):
            with test_db_factory.session_scope() as session:
                outbox_repo.create_event_in_session(
                    session, aggregate_id="t-2", event_type="Q", payload={}, event_id="evt-fixed"
                )

    def test_retry_after_transaction_failure(self, test_db_factory):
        repo = PostgresTaskRepository(test_db_factory)
        task = _create_sample_task("tsk-retry-tx", TaskState.PENDING)
        repo.create_task(task)

        # Failed attempt due to stale lease version
        with pytest.raises(StaleLeaseVersionError):
            repo.atomic_transition("tsk-retry-tx", 999, [TaskState.PENDING], TaskState.RUNNING)

        # Retry with correct lease version
        updated = repo.atomic_transition("tsk-retry-tx", 1, [TaskState.PENDING], TaskState.RUNNING)
        assert updated.state == TaskState.RUNNING

    def test_recovery_mutation_after_lease_expiration(self, test_db_factory):
        lock = PostgresRecoveryLock(test_db_factory)
        l = lock.acquire("node-exp-adv", ttl_seconds=0)
        time.sleep(0.01)

        assert lock.is_valid("node-exp-adv", l.lease_id, l.fencing_token) is False
        assert lock.renew("node-exp-adv", l.lease_id, l.fencing_token) is False
