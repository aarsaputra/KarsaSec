# Sprint F7 — Distributed Task Authority Audit & Specification

## 1. Executive Summary

This document establishes the final security audit and architectural specification for **Sprint F7 — Distributed Task Authority Enforcement** in KarsaSec.

The core goal of F7 is enforcing the predicate:
$$\text{MutationAllowed}(T, W) = \text{WorkerAuthority}(W) \land \text{TaskAuthority}(T, W)$$

Every task state mutation path across the PostgreSQL persistence layer (`PostgresTaskRepository`) has been audited and classified under global lock ordering (`Worker Row FOR UPDATE` $\rightarrow$ `Task Row UPDATE`), preventing stale workers, split-brain recovery races, un-fenced mutations, double retry increments, and terminal state resurrection.

---

## 2. Final Repository-Wide Mutation Audit

### Mutation Summary
- **Total TaskModel Mutation Sites in Codebase**: 5
- **Audited Production Mutation Sites**: 5
- **Authorized Production Mutation Sites**: 5
- **Unauthorized Bypasses Discovered**: 0
- **Bypasses Fixed**: 0

### Production Mutation Inventory Table

| File | Function / Query | State Transition | Authority Category | Authority Validation & Lock Order | CAS / Fencing Predicate | Test Verification |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `postgres_task_repository.py` | `create_task()` | `[NULL] -> PENDING/QUEUED` | `SYSTEM_MUTATION` | System creation | Task ID uniqueness | `test_postgres_authoritative_engine.py` |
| `postgres_task_repository.py` | `assign_task()` | `QUEUED -> RUNNING` | `SCHEDULER_MUTATION` | `Worker Row FOR UPDATE` $\rightarrow$ `Task UPDATE` | `worker.status == 'ONLINE'`, `attempts < max_attempts`, token copy | `test_worker_authority_f7.py`, `test_postgres_authority_f7.py` |
| `postgres_task_repository.py` | `complete_task()` | `RUNNING -> COMPLETED` | `WORKER_MUTATION` | `Worker Row FOR UPDATE` $\rightarrow$ `Task UPDATE` | `WorkerAuthority` (`ONLINE`/`DRAINING`, token match) + `TaskAuthority` (`assigned_worker_id`, token, `lease_version`) | `test_worker_authority_f7.py`, `test_postgres_authority_f7.py` |
| `postgres_task_repository.py` | `record_execution_failure()` | `RUNNING -> QUEUED/FAILED` | `WORKER_MUTATION` | `Worker Row FOR UPDATE` $\rightarrow$ `Task UPDATE` | `WorkerAuthority` + `TaskAuthority`, clears worker metadata on requeue, writes DLQ on exhaustion | `test_worker_authority_f7.py`, `test_postgres_authority_f7.py` |
| `postgres_task_repository.py` | `atomic_transition()` | `RUNNING -> QUEUED/FAILED` | `RECOVERY_MUTATION` | `Task Row UPDATE` (with lease CAS) | `lease_version == expected_lease_version`, `state IN expected_states`, clears metadata when `QUEUED` | `test_recovery_race_f7.py` |

---

## 3. Invariant Verification Matrix

| Invariant ID | Definition | Implementation Mechanism | Test Verification | Result |
| :--- | :--- | :--- | :--- | :--- |
| `INV-F7-AUTH-01` | Worker Authority | `complete_task()` and `record_execution_failure()` lock Worker row `FOR UPDATE` and validate `status IN ('ONLINE', 'DRAINING')` and matching `fencing_token`. | `test_worker_authority_f7.py` | **PASS** |
| `INV-F7-AUTH-02` | Task Ownership Authority | Mutations require `assigned_worker_id == worker_id` and `assigned_worker_fencing_token == fencing_token`. | `test_worker_authority_f7.py` | **PASS** |
| `INV-F6-LOCK-01` | Global Lock Ordering | Path locks `Worker Row FOR UPDATE` before `Task Row UPDATE` to avoid deadlocks. | `test_postgres_authority_f7.py` | **PASS** |
| `INV-F6-RETRY-06` | Single Attempt Increment | `attempts` increments ONLY during `QUEUED -> RUNNING` in `assign_task()`. Failures preserve attempts count. | `test_worker_authority_f7.py`, `test_postgres_authority_f7.py` | **PASS** |
| `INV-F6-DRAIN-01` | Draining Completion | Worker in `DRAINING` status can complete active tasks assigned prior to drain. | `test_worker_authority_f7.py` | **PASS** |
| `INV-F6-DRAIN-02` | Draining Assignment Block | Worker in `DRAINING` status cannot receive new task assignments. | `test_worker_authority_f7.py` | **PASS** |
| `INV-F7-LEASE-01` | Monotonic Lease Version | Requeue / Recovery advances `lease_version` (+1), invalidating stale worker writes. | `test_recovery_race_f7.py` | **PASS** |
| `INV-F7-META-01` | Metadata Cleanup | Transitioning task to `QUEUED` clears `assigned_worker_id` and `assigned_worker_fencing_token` to `NULL`. | `test_postgres_authority_f7.py` | **PASS** |
| `INV-F6-DLQ-01` | DLQ Atomicity & Uniqueness | Attempt exhaustion inserts `DeadLetterEventModel` with `UNIQUE(task_id)` constraint in same SQL transaction. | `test_postgres_authority_f7.py` | **PASS** |
| `INV-F7-TERM-01` | Terminal State Immutability | `COMPLETED`, `FAILED`, and `CANCELLED` states cannot be mutated or resurrected to active states. | `test_worker_authority_f7.py` | **PASS** |
| `INV-F6-METRIC-01` | Observability Cardinality | Authority rejection telemetry (`STALE_WORKER_FENCED`, etc.) logs structured events without secret leakage or unbounded labels. | `test_prometheus_metrics.py` | **PASS** |

---

## 4. Operational & Architecture Recommendations

1. **Deadlock Freedom Scope**: The `Worker Row FOR UPDATE` $\rightarrow$ `Task Row UPDATE` lock ordering applies strictly to application mutation paths that adhere to this ordering convention. External ad-hoc SQL operations should follow the same lock order.
2. **PostgreSQL Authoritative Source**: Process-local thread locks (`threading.Lock()`) are used exclusively in `InMemoryTaskRepository` for local unit tests. In distributed production deployments, PostgreSQL transactions and row locks are the single source of truth.
