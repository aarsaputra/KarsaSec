import threading
import time
import pytest

from karsasec.observability.metrics import MetricsCollector
from karsasec.observability.prometheus_exporter import PrometheusExporter
from karsasec.observability.tracing import TraceContext, canonicalize_trace_fields
from karsasec.workers.worker_registry import WorkerRegistry
from karsasec.workers.scheduler import ClusterScheduler
from karsasec.workers.cluster_recovery import (
    ClusterRecoveryEngine,
    DistributedRecoveryLock,
    FencedLeaderError,
)
from karsasec.workers.repository import InMemoryTaskRepository
from karsasec.workers.queue import InMemoryTaskQueue, QueueCapacityExceededError
from karsasec.workers.task import (
    RemediationTask,
    TaskState,
    StaleLeaseVersionError,
    InvalidTaskStateError,
)
from karsasec.persistence.audit_repository import InMemoryAuditRepository


def _make_task(
    task_id: str, state: TaskState = TaskState.PENDING, attempts: int = 0, max_attempts: int = 3
) -> RemediationTask:
    return RemediationTask(
        task_id=task_id,
        finding_id="f1",
        approval_token_id="tok1",
        token="secret_token",
        fingerprint=f"fp_{task_id}",
        state=state,
        attempts=attempts,
        max_attempts=max_attempts,
    )


# ---------------------------------------------------------------------------
# Test 1: Forged Worker Heartbeat
# ---------------------------------------------------------------------------
class TestForgedWorkerHeartbeat:
    def test_unregistered_worker_heartbeat_rejected_and_audited(self):
        audit = InMemoryAuditRepository()
        registry = WorkerRegistry(audit_repository=audit)

        # Attempt heartbeat for non-registered worker
        res = registry.heartbeat("forged_worker_999", auth_token="bad_token")
        assert res is False

        # Verify FORGED_WORKER_HEARTBEAT audit event logged
        events = audit.get_events_for_task("sys_forged_worker_999")
        assert len(events) == 1
        assert events[0].event_type == "FORGED_WORKER_HEARTBEAT"
        assert events[0].details["reason"] == "unregistered_worker"


# ---------------------------------------------------------------------------
# Test 2: Worker Impersonation
# ---------------------------------------------------------------------------
class TestWorkerImpersonation:
    def test_registered_worker_heartbeat_with_wrong_token_rejected(self):
        audit = InMemoryAuditRepository()
        registry = WorkerRegistry(audit_repository=audit)
        registry.register("worker-prod-1", hostname="node1", auth_token="valid_secret_123")

        # Impersonator sends heartbeat with wrong token
        res = registry.heartbeat("worker-prod-1", auth_token="attacker_secret_666")
        assert res is False

        # Audit event recorded
        events = audit.get_events_for_task("sys_worker-prod-1")
        assert len(events) == 1
        assert events[0].event_type == "FORGED_WORKER_HEARTBEAT"
        assert events[0].details["reason"] == "invalid_auth_token"


# ---------------------------------------------------------------------------
# Test 3: Duplicate Worker Registration & Registration Concurrency Audit (Scenario 8)
# ---------------------------------------------------------------------------
class TestDuplicateWorkerRegistration:
    def test_duplicate_registration_conflicting_token_raises_error(self):
        registry = WorkerRegistry()
        registry.register("worker-node-1", hostname="host-a", auth_token="secret_a")

        with pytest.raises(ValueError, match="Duplicate worker registration conflict"):
            registry.register("worker-node-1", hostname="host-b", auth_token="secret_b")

    def test_re_registration_same_token_updates_heartbeat(self):
        registry = WorkerRegistry()
        w1 = registry.register("worker-node-1", hostname="host-a", auth_token="secret_a")
        old_hb = w1.last_heartbeat
        time.sleep(0.01)
        w2 = registry.register("worker-node-1", hostname="host-a", auth_token="secret_a")
        assert w2.last_heartbeat >= old_hb

    def test_concurrent_registration_conflicting_tokens(self):
        registry = WorkerRegistry()
        barrier = threading.Barrier(2)
        results = []
        errors = []

        def worker_a():
            barrier.wait()
            try:
                node = registry.register("worker-concurrent", hostname="host1", auth_token="token_A")
                results.append(node)
            except Exception as e:
                errors.append(e)

        def worker_b():
            barrier.wait()
            try:
                node = registry.register("worker-concurrent", hostname="host2", auth_token="token_B")
                results.append(node)
            except Exception as e:
                errors.append(e)

        t1 = threading.Thread(target=worker_a)
        t2 = threading.Thread(target=worker_b)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        assert len(results) == 1
        assert len(errors) == 1
        assert isinstance(errors[0], ValueError)


# ---------------------------------------------------------------------------
# Test 4: Metrics Information Leak & Prometheus Cardinality Audit (Scenario 10)
# ---------------------------------------------------------------------------
class TestMetricsInformationLeak:
    def test_prometheus_metrics_has_zero_forbidden_privacy_strings(self):
        collector = MetricsCollector()
        collector.set_queue_depth(42)
        collector.set_active_workers(3)
        collector.inc_completed_tasks(10)

        exporter = PrometheusExporter(collector)
        output = exporter.generate_metrics_text()

        for forbidden in ("source_code", "unified_diff", "diff", "patch", "token", "credential", "api_key", "secret"):
            assert forbidden not in output.lower(), f"Privacy Leak: Forbidden term '{forbidden}' in /metrics output"

    def test_prometheus_cardinality_rejection_at_metric_registration(self):
        collector = MetricsCollector()
        exporter = PrometheusExporter(collector)

        # 10,000 dynamic task_ids cannot create 10,000 metric labels
        for label in ("task_id", "trace_id", "finding_id", "user_id", "session_id"):
            with pytest.raises(ValueError, match="High-cardinality label"):
                exporter.register_metric("custom_task_metric", [label])

            with pytest.raises(ValueError, match="High-cardinality label"):
                MetricsCollector.validate_labels({label: "12345"})


# ---------------------------------------------------------------------------
# Test 5: Queue Depth Overflow & Atomic Queue Backpressure Race (Scenario 9)
# ---------------------------------------------------------------------------
class TestQueueDepthOverflow:
    def test_large_queue_depth_metrics_handled_safely(self):
        collector = MetricsCollector()
        collector.set_queue_depth(1_000_000_000)
        assert collector.queue_depth == MetricsCollector.MAX_METRIC_VALUE

        collector.set_queue_depth(-50)
        assert collector.queue_depth == 0

    def test_concurrent_producers_queue_capacity_invariant(self):
        max_depth = 50
        queue = InMemoryTaskQueue(max_queue_depth=max_depth)
        producers = 100
        barrier = threading.Barrier(producers)
        successes = []
        failures = []

        def producer(i: int):
            barrier.wait()
            try:
                queue.enqueue(f"task_{i}")
                successes.append(i)
            except QueueCapacityExceededError as e:
                failures.append(e)

        threads = [threading.Thread(target=producer, args=(i,)) for i in range(producers)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(queue.main_queue) <= max_depth
        assert len(successes) == max_depth
        assert len(failures) == producers - max_depth


# ---------------------------------------------------------------------------
# Test 6: Task Reassignment Race & Round Robin Determinism
# ---------------------------------------------------------------------------
class TestTaskReassignmentRace:
    def test_round_robin_scheduler_is_deterministic(self):
        registry = WorkerRegistry()
        registry.register("worker-3", hostname="h3")
        registry.register("worker-1", hostname="h1")
        registry.register("worker-2", hostname="h2")

        scheduler = ClusterScheduler(registry)
        scheduler.reset_counter()

        w1 = scheduler.select_worker("t1")
        w2 = scheduler.select_worker("t2")
        w3 = scheduler.select_worker("t3")
        w4 = scheduler.select_worker("t4")

        assert w1.worker_id == "worker-1"
        assert w2.worker_id == "worker-2"
        assert w3.worker_id == "worker-3"
        assert w4.worker_id == "worker-1"


# ---------------------------------------------------------------------------
# Test 7: Recovery Replay Attack
# ---------------------------------------------------------------------------
class TestRecoveryReplayAttack:
    def test_cluster_recovery_is_idempotent(self):
        registry = WorkerRegistry()
        audit = InMemoryAuditRepository()
        repo = InMemoryTaskRepository()
        queue = InMemoryTaskQueue()
        metrics = MetricsCollector()

        registry.register("worker-dead", hostname="dead_host")
        registry.mark_offline("worker-dead")

        task = _make_task("tsk_orphan_1", state=TaskState.PENDING)
        repo.create_task(task)
        repo.update_task("tsk_orphan_1", state=TaskState.QUEUED)
        queue.dequeue()
        repo.update_task("tsk_orphan_1", state=TaskState.RUNNING)

        assignments = {"tsk_orphan_1": "worker-dead"}
        engine = ClusterRecoveryEngine(registry, repo, queue, metrics_collector=metrics, audit_repository=audit)

        rec1 = engine.recover_orphaned_tasks(assignments)
        assert rec1 == 1
        assert repo.get_task("tsk_orphan_1").state == TaskState.QUEUED

        rec2 = engine.recover_orphaned_tasks(assignments)
        assert rec2 == 0
        assert repo.get_task("tsk_orphan_1").state == TaskState.QUEUED


# ---------------------------------------------------------------------------
# Test 8: Worker Resurrection Attack
# ---------------------------------------------------------------------------
class TestWorkerResurrectionAttack:
    def test_terminal_state_tasks_never_recovered_or_resurrected(self):
        registry = WorkerRegistry()
        repo = InMemoryTaskRepository()
        queue = InMemoryTaskQueue()

        registry.register("worker-dead", hostname="dead_host")
        registry.mark_offline("worker-dead")

        task = _make_task("tsk_completed", state=TaskState.PENDING)
        repo.create_task(task)
        repo.update_task("tsk_completed", state=TaskState.QUEUED)
        queue.dequeue()
        repo.update_task("tsk_completed", state=TaskState.RUNNING)
        repo.update_task("tsk_completed", state=TaskState.COMPLETED)

        assignments = {"tsk_completed": "worker-dead"}
        engine = ClusterRecoveryEngine(registry, repo, queue)

        rec = engine.recover_orphaned_tasks(assignments)
        assert rec == 0
        assert repo.get_task("tsk_completed").state == TaskState.COMPLETED


# ---------------------------------------------------------------------------
# Test 9: Stale Worker Task Completion & Atomic Fencing (Scenarios 4 & 5)
# ---------------------------------------------------------------------------
class TestStaleWorkerCompletionFencing:
    def test_stale_worker_completion_rejected_by_atomic_transition(self):
        repo = InMemoryTaskRepository()
        task = _make_task("tsk_race_1", state=TaskState.PENDING)
        repo.create_task(task)
        repo.update_task("tsk_race_1", state=TaskState.QUEUED)
        repo.update_task("tsk_race_1", state=TaskState.RUNNING)

        # Active lease version is 1
        assert repo.get_task("tsk_race_1").lease_version == 1

        # Simulate recovery bumping lease_version to 2
        repo.get_task("tsk_race_1").increment_lease_version()
        assert repo.get_task("tsk_race_1").lease_version == 2

        # Worker A (with stale lease version 1) attempts atomic transition
        with pytest.raises(StaleLeaseVersionError, match="lease version mismatch"):
            repo.atomic_transition(
                task_id="tsk_race_1",
                expected_lease_version=1,
                expected_states=[TaskState.RUNNING],
                new_state=TaskState.COMPLETED,
            )

        # Final state remains unchanged
        assert repo.get_task("tsk_race_1").state == TaskState.RUNNING

    def test_concurrent_task_completion_only_one_commit_wins(self):
        repo = InMemoryTaskRepository()
        task = _make_task("tsk_concurrent_comp", state=TaskState.PENDING)
        repo.create_task(task)
        repo.update_task("tsk_concurrent_comp", state=TaskState.QUEUED)
        repo.update_task("tsk_concurrent_comp", state=TaskState.RUNNING)

        barrier = threading.Barrier(2)
        outcomes = []
        errors = []

        def worker_commit(worker_name: str):
            barrier.wait()
            try:
                res = repo.atomic_transition(
                    task_id="tsk_concurrent_comp",
                    expected_lease_version=1,
                    expected_states=[TaskState.RUNNING],
                    new_state=TaskState.COMPLETED,
                    receipt_id=f"rcpt_{worker_name}",
                )
                outcomes.append((worker_name, res))
            except Exception as e:
                errors.append((worker_name, e))

        t1 = threading.Thread(target=worker_commit, args=("Worker_A",))
        t2 = threading.Thread(target=worker_commit, args=("Worker_B",))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Exactly 1 success, exactly 1 rejection
        assert len(outcomes) == 1
        assert len(errors) == 1
        assert isinstance(errors[0][1], InvalidTaskStateError)
        assert repo.get_task("tsk_concurrent_comp").state == TaskState.COMPLETED


# ---------------------------------------------------------------------------
# Test 10: Heartbeat Sequence Race & Monotonic Replay (Scenarios 6 & 7)
# ---------------------------------------------------------------------------
class TestHeartbeatSequenceRace:
    def test_concurrent_heartbeats_highest_sequence_wins(self):
        audit = InMemoryAuditRepository()
        registry = WorkerRegistry(audit_repository=audit)
        registry.register("worker-race-seq", hostname="node1", auth_token="token_seq")

        barrier = threading.Barrier(4)
        sequences = [10, 11, 10, 12]
        results = []

        def send_hb(seq: int):
            barrier.wait()
            res = registry.heartbeat("worker-race-seq", auth_token="token_seq", sequence=seq)
            results.append((seq, res))

        threads = [threading.Thread(target=send_hb, args=(s,)) for s in sequences]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        worker = registry.get_worker("worker-race-seq")
        # Final authoritative sequence MUST be 12
        assert worker.heartbeat_sequence == 12

    def test_duplicate_heartbeat_sequence_rejected(self):
        registry = WorkerRegistry()
        registry.register("w1", hostname="h1", auth_token="tok")

        assert registry.heartbeat("w1", auth_token="tok", sequence=5) is True
        assert registry.heartbeat("w1", auth_token="tok", sequence=5) is False  # Duplicate sequence rejected


# ---------------------------------------------------------------------------
# Test 11: Distributed Recovery Lock & Leader Fencing (Scenarios 1, 2, 3, 14, 15)
# ---------------------------------------------------------------------------
class TestRecoveryLeaseFencing:
    def test_recovery_lease_strictly_monotonic_tokens(self):
        lock = DistributedRecoveryLock()
        lease1 = lock.acquire("node_A")
        assert lease1 is not None
        assert lease1.fencing_token == 1

        lock.release("node_A", lease1.lease_id)

        lease2 = lock.acquire("node_B")
        assert lease2 is not None
        assert lease2.fencing_token == 2
        assert lease2.fencing_token > lease1.fencing_token

    def test_expired_recovery_lease_fences_mutation(self):
        registry = WorkerRegistry()
        repo = InMemoryTaskRepository()
        queue = InMemoryTaskQueue()

        registry.register("worker-dead", hostname="dead_host")
        registry.mark_offline("worker-dead")

        task = _make_task("tsk_lease_exp", state=TaskState.PENDING)
        repo.create_task(task)
        repo.update_task("tsk_lease_exp", state=TaskState.QUEUED)
        repo.update_task("tsk_lease_exp", state=TaskState.RUNNING)

        lock = DistributedRecoveryLock()
        # Node A acquires lock with TTL of 0.01 seconds
        lease_a = lock.acquire("node_leader_A", ttl_seconds=0.01)
        time.sleep(0.02)  # Expire lease

        engine = ClusterRecoveryEngine(registry, repo, queue, recovery_lock=lock)

        # Node A attempts recovery after lease expired -> Leader B acquires lock -> Node A fenced
        lease_b = lock.acquire("node_leader_B", ttl_seconds=30.0)
        assert lease_b.fencing_token > lease_a.fencing_token

        with pytest.raises(FencedLeaderError, match="Recovery leader 'node_leader_A' is fenced"):
            engine.recover_orphaned_tasks(
                worker_assignments={"tsk_lease_exp": "worker-dead"},
                recovery_node_id="node_leader_A",
                existing_lease=lease_a,
            )

    def test_concurrent_recovery_lock_acquisition(self):
        lock = DistributedRecoveryLock()
        barrier = threading.Barrier(3)
        leases = []

        def acquire_lock(node_id: str):
            barrier.wait()
            lease = lock.acquire(node_id)
            if lease:
                leases.append((node_id, lease))

        threads = [threading.Thread(target=acquire_lock, args=(f"node_{i}",)) for i in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly 1 leader node acquires lease
        assert len(leases) == 1

    def test_recovery_post_mutation_fencing_triggers_compensating_rollback(self):
        registry = WorkerRegistry()
        repo = InMemoryTaskRepository()
        queue = InMemoryTaskQueue()

        registry.register("worker-dead", hostname="dead_host")
        registry.mark_offline("worker-dead")

        task = _make_task("tsk_rollback_fenced", state=TaskState.PENDING)
        repo.create_task(task)
        repo.update_task("tsk_rollback_fenced", state=TaskState.QUEUED)
        repo.update_task("tsk_rollback_fenced", state=TaskState.RUNNING)

        lock = DistributedRecoveryLock()
        lease_a = lock.acquire("node_leader_A", ttl_seconds=30.0)

        # Preempt lease_a by acquiring for leader_B right before post-mutation check
        original_is_valid = lock.is_valid
        calls = []

        def custom_is_valid(owner_id, lease_id=None, fencing_token=None):
            calls.append(owner_id)
            if len(calls) == 2:  # On second call (post-mutation check), simulate leader_B taking over
                lock.release("node_leader_A", lease_a.lease_id)
                lock.acquire("node_leader_B")
            return original_is_valid(owner_id, lease_id, fencing_token)

        lock.is_valid = custom_is_valid
        engine = ClusterRecoveryEngine(registry, repo, queue, recovery_lock=lock)

        with pytest.raises(FencedLeaderError, match="State rolled back"):
            engine.recover_orphaned_tasks(
                worker_assignments={"tsk_rollback_fenced": "worker-dead"},
                recovery_node_id="node_leader_A",
                existing_lease=lease_a,
            )

        # Verify task was rolled back to RUNNING and lease_version restored to 1
        rolled_back_task = repo.get_task("tsk_rollback_fenced")
        assert rolled_back_task.state == TaskState.RUNNING
        assert rolled_back_task.lease_version == 1

    def test_recovery_queue_failure_triggers_compensating_rollback(self):
        registry = WorkerRegistry()
        repo = InMemoryTaskRepository()
        # Saturate queue to trigger QueueCapacityExceededError on enqueue
        queue = InMemoryTaskQueue(max_queue_depth=1)
        queue.enqueue("blocking_task")

        registry.register("worker-dead", hostname="dead_host")
        registry.mark_offline("worker-dead")

        task = _make_task("tsk_rollback_queue", state=TaskState.PENDING)
        repo.create_task(task)
        repo.update_task("tsk_rollback_queue", state=TaskState.QUEUED)
        repo.update_task("tsk_rollback_queue", state=TaskState.RUNNING)

        engine = ClusterRecoveryEngine(registry, repo, queue)

        with pytest.raises(QueueCapacityExceededError):
            engine.recover_orphaned_tasks({"tsk_rollback_queue": "worker-dead"})

        # Verify task was rolled back to RUNNING and not stuck in QUEUED
        rolled_back_task = repo.get_task("tsk_rollback_queue")
        assert rolled_back_task.state == TaskState.RUNNING
        assert rolled_back_task.lease_version == 1


# ---------------------------------------------------------------------------
# Test 12: Trace Canonicalization & Security Boundary (Scenarios 11, 12, 13)
# ---------------------------------------------------------------------------
class TestTraceSecurityBoundary:
    def test_trace_canonicalization_determinism(self):
        p1 = canonicalize_trace_fields("parent_hash_1", "trc_100", "spn_200", "corr_300")
        p2 = canonicalize_trace_fields("parent_hash_1", "trc_100", "spn_200", "corr_300")
        assert p1 == p2

        h1 = TraceContext.compute_canonical_hash("parent_hash_1", "trc_100", "spn_200", "corr_300")
        h2 = TraceContext.compute_canonical_hash("parent_hash_1", "trc_100", "spn_200", "corr_300")
        assert h1 == h2

    def test_trace_field_tampering_detection(self):
        ctx = TraceContext(trace_id="trc_orig", span_id="spn_orig", correlation_id="corr_orig", parent_hash="ROOT")
        assert ctx.validate_integrity() is True

        # Tampered trace_id
        tampered_trace_id = TraceContext(
            trace_id="trc_TAMPERED",
            span_id=ctx.span_id,
            correlation_id=ctx.correlation_id,
            parent_hash=ctx.parent_hash,
            trace_hash=ctx.trace_hash,
        )
        assert tampered_trace_id.validate_integrity() is False

        # Tampered span_id
        tampered_span_id = TraceContext(
            trace_id=ctx.trace_id,
            span_id="spn_TAMPERED",
            correlation_id=ctx.correlation_id,
            parent_hash=ctx.parent_hash,
            trace_hash=ctx.trace_hash,
        )
        assert tampered_span_id.validate_integrity() is False

    def test_trace_optional_hmac_signature_verification(self):
        secret_key = b"super_secret_cluster_hmac_key_123"
        ctx = TraceContext(trace_id="trc_auth", span_id="spn_auth")

        sig = ctx.compute_hmac_signature(secret_key)
        assert ctx.validate_hmac_signature(sig, secret_key) is True
        assert ctx.validate_hmac_signature(sig, b"wrong_key_456") is False

        headers = ctx.to_headers(secret_key=secret_key)
        assert "X-Trace-Signature" in headers
