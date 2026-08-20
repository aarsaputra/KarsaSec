# Sprint F4.1 — Distributed Systems Adversarial Hardening Audit

## Architectural Audit & Hardening Summary

Sprint F4.1 performed an adversarial architectural hardening pass on the KarsaSec distributed cluster coordination and observability infrastructure. This document provides the final audit review of security invariants, transactional compensating semantics, process-local limitations, and the architectural boundary for Sprint F5 (PostgreSQL & Distributed State Authority).

---

## 1. Security & Distributed Semantics Invariants

| Invariant ID | Security/Distributed Invariant Name | Implementation Mechanism | Enforcement Layer |
| :--- | :--- | :--- | :--- |
| **INV-01** | **Recovery Lease Monotonic Fencing** | `DistributedRecoveryLock` with strictly increasing process-local fencing tokens ($T_{new} > T_{old}$). | `cluster_recovery.py` |
| **INV-02** | **Recovery Lease Pre-Mutation Guard** | `is_valid(recovery_node_id, lease_id, fencing_token)` verified before task state mutation. | `cluster_recovery.py` |
| **INV-03** | **Recovery Lease Post-Mutation & Compensating Guard** | `is_valid()` re-verified after task state mutation prior to queue enqueuing. If fenced, triggers compensating atomic rollback (`RUNNING` state & original `lease_version` restored). | `cluster_recovery.py` |
| **INV-04** | **Task State Atomic Fencing Mutation** | `TaskRepository.atomic_transition()` enforces `expected_lease_version`, `expected_states`, and monotonic `lease_version` increment. | `task.py` & `repository.py` |
| **INV-05** | **Double-Commit / Split-Brain Prevention** | Stale worker commits with obsolete task `lease_version` are rejected via `StaleLeaseVersionError`. | `repository.py` |
| **INV-06** | **Trace Cryptographic Tamper-Detection** | `TraceContext` SHA-256 hash chaining over parent hash, trace ID, span ID, and correlation ID. | `tracing.py` |
| **INV-07** | **Trace Canonical Field Serialization** | `canonicalize_trace_fields()` produces deterministic key-sorted byte representations for hashing. | `tracing.py` |
| **INV-08** | **Trace Optional Authenticated HMAC** | `HMAC-SHA256` signatures (`X-Trace-Signature`) when cluster `secret_key` is configured. Zero default secret fallbacks allowed. | `tracing.py` |
| **INV-09** | **Early Metric Label Cardinality Guard** | `MetricsCollector.validate_labels()` and `PrometheusExporter.register_metric()` reject high-cardinality label keys (`task_id`, `trace_id`, `user_id`, etc.) at registration API level. | `metrics.py` & `prometheus_exporter.py` |
| **INV-10** | **Queue Atomic Backpressure & Rollback Guard** | `InMemoryTaskQueue` performs atomic depth checking under lock. If queue enqueue fails post-mutation, compensating rollback restores task state to `RUNNING`. | `queue.py` & `cluster_recovery.py` |

---

## 2. Final Adversarial Review Findings (F4.1 Completion Standards)

### Audit Point 1: Recovery Post-Mutation Fencing & Compensating Semantics
- **Problem**: Pre-F4.1, if a recovery leader lost its lease *after* task state mutation in repository but *before* queue enqueuing, the task state remained modified without being enqueued (partial recovery state).
- **Resolution & Compensating Transaction**:
  In `ClusterRecoveryEngine.recover_orphaned_tasks()`, if post-mutation `is_valid()` check fails OR if `self._queue.enqueue()` raises an exception (e.g. `QueueCapacityExceededError`), a compensating atomic transition is executed:
  ```python
  self._repo.atomic_transition(
      task_id=task.task_id,
      expected_lease_version=next_task_lease_version,
      expected_states=[target_state],
      new_state=TaskState.RUNNING,
      lease_version=original_lease_version,
      error_message="Recovery rollback: leader fenced post-mutation before enqueue.",
  )
  ```
  This guarantees zero partial recovery states in memory.

### Audit Point 2: Monotonic Fencing Token Persistence & Process Boundary
- **Boundary Statement**:
  > **F4.1 fencing token monotonicity is process-local (resets on process/node restart); persistent distributed fencing tokens monotonically increasing across restarts is deferred to Sprint F5 (PostgreSQL sequence / Redis INCR).**
- **Architecture Mapping**: `DistributedRecoveryLock` enforces strict in-memory monotonicity ($T_{new} > T_{old}$) within process lifetime. Production persistent fencing authority across restarts will be provided by PostgreSQL database sequences in Sprint F5.

### Audit Point 3: HMAC Key Lifecycle & Non-Fallback Guarantee
- **Verification**: `TraceContext.compute_hmac_signature(secret_key: bytes)` and `to_headers(secret_key: bytes | None)` require explicit secret key passing.
- **Guarantee**: Zero hardcoded default fallback secrets exist (e.g., no `os.getenv("TRACE_HMAC_KEY", "default-secret")`). When `secret_key` is `None`, HMAC signing is disabled, operating strictly in integrity-only mode (`X-Trace-Hash`).

### Audit Point 4: Queue/Recovery Partial Failure Consistency Invariants
- **In-Memory Limitation**: In an in-memory queue/repo architecture without dual-write 2PC, state-repository mutations and queue additions are separate calls.
- **Compensating Invariant**: Any failure during `enqueue()` (e.g., queue saturation under heavy backpressure) immediately triggers a compensating repository transaction that reverts the task state back to `RUNNING` and restores `original_lease_version`, preventing queue/state desynchronization.

---

## 3. Process-Local vs Distributed Production Authority Matrix (F4.1 $\rightarrow$ F5 Migration)

```text
                 F4.1 (In-Memory Engine)
                          │
       ┌──────────────────┼──────────────────┐
       ↓                  ↓                  ↓
  fencing lock       concurrency         observability
 (process-local)   (threading.Lock)    (integrity + HMAC)
       │                  │                  │
       └──────────────────┼──────────────────┘
                          ↓
                 Sprint F5 Architecture
                          │
            PostgreSQL Authoritative Engine
                          │
       ┌──────────────────┼──────────────────┐
       ↓                  ↓                  ↓
  atomic CAS        unique state        persistent
 transitions         constraints       fencing sequence
(WHERE v=v_old)    (DB constraints)    (PG SEQUENCE / Redlock)
```

| Component | F4.1 In-Memory Model | Sprint F5 Production Model |
| :--- | :--- | :--- |
| **Worker Registry** | `threading.Lock()` in `WorkerRegistry` | PostgreSQL `workers` table with `UNIQUE(worker_id)` |
| **Recovery Lock** | `DistributedRecoveryLock` (monotonic counter) | Redis (Redlock) or Etcd distributed leases + PG SEQUENCE |
| **Task Fencing Version** | Monotonic integer `task.lease_version` | DB column `lease_version` updated via `UPDATE remediation_tasks SET state=?, lease_version=lease_version+1 WHERE task_id=? AND lease_version=?` |
| **Task Queue** | `InMemoryTaskQueue` with atomic depth check | Redis Streams / PostgreSQL Outbox pattern |
| **Trace Propagation** | HTTP Header `X-Trace-Hash` & `X-Trace-Signature` | Distributed W3C TraceContext headers + Secret Manager HMAC key |

---

## 4. Adversarial Test Matrix Results

All 24 security & observability tests passed successfully:
- `TestForgedWorkerHeartbeat`: Verified unregistered heartbeats are rejected and logged (`FORGED_WORKER_HEARTBEAT`).
- `TestWorkerImpersonation`: Verified forged auth tokens trigger audit events.
- `TestDuplicateWorkerRegistration`: Verified conflicting registration credentials raise `ValueError` without corrupting state.
- `TestMetricsInformationLeak`: Verified 0 forbidden privacy terms in `/metrics` outputs.
- `TestQueueDepthOverflow`: Verified queue capacity limits remain invariant under 100 concurrent producer threads.
- `TestTaskReassignmentRace`: Verified Round-Robin scheduling determinism.
- `TestRecoveryReplayAttack`: Verified cluster recovery idempotency.
- `TestWorkerResurrectionAttack`: Verified terminal state task protection.
- `TestStaleWorkerCompletionFencing`: Verified stale worker commits fail with `StaleLeaseVersionError`.
- `TestHeartbeatSequenceRace`: Verified monotonic sequence ordering under concurrent heartbeats.
- `TestRecoveryLeaseFencing`: Verified leader preemption, monotonic fencing tokens, and `FencedLeaderError` handling.
- `TestRecoveryPostMutationRollback`: Verified compensating rollback restores state and lease version when leader is fenced post-mutation.
- `TestRecoveryQueueFailureRollback`: Verified compensating rollback restores state and lease version when queue enqueue fails.
- `TestTraceSecurityBoundary`: Verified trace canonical serialization, field tampering detection, and HMAC signature validation without default secrets.

**Full Repository Regression Results**: 2,159 / 2,159 PASS (0 failures, 0 errors).
