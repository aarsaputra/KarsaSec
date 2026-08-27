# SPRINT F6C — Operational Reliability Engine & Distributed Authority: Technical Study Case & Audit Report

> **System:** KarsaSec — AI Software Security Engineer  
> **Subsystem:** Operational Reliability Engine (Sprint F6C)  
> **Architecture Baseline:** Hardened Architecture v5  
> **Verification Status:** 38/38 Reliability PASS | 45/45 Security PASS | 33/33 Observability PASS | 2281/2281 Full Regression PASS | Ruff PASS

---

## EXECUTIVE SUMMARY & ARCHITECTURAL OBJECTIVE

In high-concurrency, distributed software security automation systems like KarsaSec, tasks represent critical vulnerability remediation jobs (e.g., automated code refactoring, secret revokation, dependency updates). In production environments where multiple schedulers, worker nodes, and cluster recovery engines operate concurrently over a PostgreSQL database, process-local memory is fundamentally unsuited as an authoritative state store.

Process-local counters and in-memory worker flags fail under:
- Concurrent scheduler assignment races
- Heterogeneous worker execution speeds and network delays
- Worker crashes, SIGKILLs, and OS-level Stop-The-World GC pauses
- Zombie process mutations from stale workers post-recovery

### PostgreSQL as the Single Authoritative State Machine

Under **Hardened Architecture v5**, process-local memory is treated as untrusted and transient. **PostgreSQL is the sole authoritative state machine**.

```text
 ┌─────────────────────────────────────────────────────────────┐
 │               PostgreSQL (Authoritative State)              │
 └──────┬──────────────────────┬──────────────────────┬────────┘
        │                      │                      │
        ▼                      ▼                      ▼
┌──────────────┐       ┌──────────────┐       ┌──────────────┐
│  Scheduler   │       │ Worker Node  │       │   Recovery   │
│ (Assignment) │       │ (Executor)   │       │  (Fencing)   │
└──────────────┘       └──────────────┘       └──────────────┘
```

---

## PART 1 — RETRY ACCOUNTING & FORMAL MATHEMATICAL MODEL

### Single-Source Attempt Rule

> **`attempts` = Total number of execution attempts STARTED.**

The only transition allowed to increment `attempts` is `QUEUED ➔ RUNNING`.

```text
QUEUED ──(assign_task, attempts += 1)──► RUNNING
                                           │
                        ┌──────────────────┴──────────────────┐
                        │                                     │
           (record_failure, attempts < max)      (record_failure, attempts >= max)
                        │                                     │
                        ▼                                     ▼
                     QUEUED                                FAILED (Atomically writes DLQ)
                (attempts unchanged)                  (attempts unchanged)
```

### Mathematical Model

- **Retry Accounting Function:**
  Let $A(t)$ be the attempt count at time $t$.
  $$A(t+1) = A(t) + 1 \quad \text{iff} \quad \text{state}(t) = \text{QUEUED} \land \text{state}(t+1) = \text{RUNNING}$$
  $$A(t+1) = A(t) \quad \text{if} \quad \text{state}(t) = \text{RUNNING} \land \text{state}(t+1) \in \{\text{QUEUED}, \text{FAILED}\}$$

- **Retry Eligibility Predicate:**
  $$\text{can\_retry} \iff A(t) < \text{max\_attempts}$$

- **Worker Authority Validation:**
  $$\text{worker\_authority\_valid} \iff (\text{token}_{\text{submitted}} = \text{token}_{\text{current\_db}}) \land \text{status}_{\text{db}} \in \{\text{ONLINE}, \text{DRAINING}\}$$

- **Task Authority Validation (CAS):**
  $$\text{task\_authority\_valid} \iff (\text{version}_{\text{expected}} = \text{version}_{\text{current\_db}})$$

---

## PART 2 — ASSIGNMENT ALGORITHM & SQL PREDICATE

To eliminate double-assignment and prevent task dispatch to draining workers, task assignment executes under explicit pessimistic locks and conditional state predicates.

### Authoritative SQL Implementation

```sql
BEGIN;

-- 1. Lock Worker Row FIRST (INV-F6-LOCK-01, NewAssignmentAuthority)
SELECT worker_id, status, fencing_token
FROM workers
WHERE worker_id = :worker_id
  AND status = 'ONLINE'
FOR UPDATE;

-- 2. Update Task Row SECOND (Single Attempt Increment: INV-F6-RETRY-06)
UPDATE tasks
SET
    state = 'RUNNING',
    attempts = attempts + 1,
    lease_version = lease_version + 1,
    assigned_worker_id = :worker_id,
    assigned_worker_fencing_token = :worker_fencing_token
WHERE task_id = :task_id
  AND state = 'QUEUED'
  AND attempts < max_attempts;

COMMIT;
```

---

## PART 3 — GLOBAL LOCK ORDERING (`INV-F6-LOCK-01`)

To prevent cyclic deadlock dependencies between concurrent scheduler assignment and worker drain operations:

$$\mathbf{\text{Worker Row Lock (FOR UPDATE)}} \longrightarrow \mathbf{\text{Task Row Lock (UPDATE / FOR UPDATE)}}$$

### Deadlock Elimination Proof

```text
Transaction A (Scheduler Assignment):         Transaction B (Worker Drain Controller):
  1. LOCK Worker Row (FOR UPDATE)                1. LOCK Worker Row (FOR UPDATE) [BLOCKED]
  2. LOCK Task Row (UPDATE)
  3. COMMIT (Releases Worker Lock) ────────────► 2. Acquires Worker Lock
                                                 3. LOCK Task Row (Check RUNNING tasks)
                                                 4. COMMIT
```

Because both transactions enter the lock hierarchy at `Worker Row`, cyclic waiting ($T_1 \to T_2 \to T_1$) between the F6C task-assignment and worker-drain transaction paths is eliminated.

> [!NOTE]
> Within the F6C task-assignment and worker-drain transaction paths, the enforced `Worker Row ➔ Task Row` lock ordering eliminates lock cycles between these specific execution paths. Global deadlock safety requires all application transaction paths accessing both tables to adhere strictly to this ordering.

---

## PART 4 — AUTHORITY SEPARATION & DISTRIBUTED TASK AUTHORITY TUPLE

Hardened Architecture v5 enforces strict separation between assignment and mutation privileges:

```text
 ┌──────────────────────────────────┐        ┌──────────────────────────────────┐
 │      NewAssignmentAuthority      │        │      TaskMutationAuthority       │
 ├──────────────────────────────────┤        ├──────────────────────────────────┤
 │ Worker Status MUST be ONLINE     │        │ Worker Status: ONLINE or DRAINING│
 │ Triggers: QUEUED ➔ RUNNING       │        │ Triggers: RUNNING ➔ COMPLETED /  │
 │ Denied for: DRAINING, FENCED    │        │           RUNNING ➔ QUEUED /     │
 └──────────────────────────────────┘        │           RUNNING ➔ FAILED       │
                                             └──────────────────────────────────┘
```

Allowing `DRAINING` workers to complete active tasks (`INV-F6-AUTH-01`) guarantees zero task loss or artificial task rejection during graceful cluster scale-down.

### Formal Distributed Task Authority Tuple

Every authoritative task mutation validates the compatibility between the **Worker Authority Tuple** and the **Task Authority Tuple**:

$$\mathbf{\text{WorkerAuthority}} = \Big(\text{worker\_id}, \text{status} \in \{\text{ONLINE}, \text{DRAINING}\}, \text{fencing\_token}\Big)$$

$$\mathbf{\text{TaskAuthority}} = \Big(\text{task\_id}, \text{state} = \text{RUNNING}, \text{lease\_version}, \text{assigned\_worker\_id}, \text{assigned\_worker\_fencing\_token}\Big)$$

```text
WorkerAuthority(worker)
        │
        ▼
    VALIDATE
        │
        ├── worker exists in DB
        ├── status ∈ {ONLINE, DRAINING}
        └── worker.fencing_token == submitted_fencing_token
                │
                ▼
        TaskAuthority(task)
                │
                ├── task.lease_version == expected_lease_version
                ├── task.assigned_worker_id == worker.worker_id
                ├── task.assigned_worker_fencing_token == worker.fencing_token
                └── task.state == RUNNING
                        │
                        ▼
                    MUTATE (State Transition Allowed)
```

---

## PART 5 — WORKER FENCING & LEASE CAS

### Worker Fencing Token (Worker Epoch Authority)

When a worker node experiences a prolonged Stop-The-World GC pause or network delay, the cluster marks the worker `FENCED` and increments its `fencing_token` in the database:

$$\text{fencing\_token}_{\text{db}} \leftarrow \text{fencing\_token}_{\text{db}} + 1$$

Any subsequent mutation attempted by the stale worker process using its old in-memory token fails because `WHERE assigned_worker_fencing_token = :old_token` yields `rowcount = 0`.

### Task Lease Version (Task Authority)

`lease_version` advances on every ownership state change. If the F5 Cluster Recovery Engine reclaims an orphaned task, `lease_version` increments, rejecting any delayed result submissions from former leaseholders.

---

## PART 6 — FAILURE & RETRY ALGORITHM WITH TRANSACTIONAL DLQ

When a worker reports an execution failure (`record_execution_failure()`), state determination and DLQ event generation execute atomically.

```python
# 1. Worker Row Lock FIRST (INV-F6-LOCK-01, TaskMutationAuthority)
worker = session.scalar(
    select(WorkerModel)
    .where(
        WorkerModel.worker_id == worker_id,
        WorkerModel.fencing_token == worker_fencing_token,
        WorkerModel.status.in_(["ONLINE", "DRAINING"]),
    )
    .with_for_update()
)
if not worker:
    raise WorkerFencedError(f"Worker '{worker_id}' authority revoked.")

# 2. Update Task Row SECOND (attempts NOT incremented - INV-F6-RETRY-07)
target_state_expr = case(
    (TaskModel.attempts >= TaskModel.max_attempts, TaskState.FAILED.value),
    else_=TaskState.QUEUED.value,
)

stmt = (
    update(TaskModel)
    .where(
        TaskModel.task_id == task_id,
        TaskModel.lease_version == expected_lease_version,
        TaskModel.assigned_worker_id == worker_id,
        TaskModel.assigned_worker_fencing_token == worker_fencing_token,
        TaskModel.state == TaskState.RUNNING.value,
    )
    .values(
        state=target_state_expr,
        assigned_worker_id=case(
            (TaskModel.attempts >= TaskModel.max_attempts, TaskModel.assigned_worker_id),
            else_=None,
        ),
        assigned_worker_fencing_token=case(
            (TaskModel.attempts >= TaskModel.max_attempts, TaskModel.assigned_worker_fencing_token),
            else_=None,
        ),
        lease_version=TaskModel.lease_version + 1,
        error_message=sanitized_msg,
    )
)

result = session.execute(stmt)
if getattr(result, "rowcount", 0) == 1:
    session.flush()
    model = session.scalar(select(TaskModel).where(TaskModel.task_id == task_id))

    # Same-transaction DLQ insertion when task reaches FAILED (INV-F6-DLQ-02)
    if model.state == TaskState.FAILED.value:
        dlq_event = DeadLetterEventModel(
            event_id=str(uuid.uuid4()),
            task_id=task_id,
            reason="EXHAUSTED",
            attempts=model.attempts,
            max_attempts=model.max_attempts,
            payload_json=build_forensic_snapshot(model),
            error_type="TaskExecutionExhausted",
            sanitized_error_message=sanitized_msg,
            worker_id=worker_id,
        )
        session.add(dlq_event)
        session.flush()
```

### DLQ Idempotency & Atomicity
- **Atomicity:** Task state transition to `FAILED` and DLQ row creation occur in the **same database transaction**. If DLQ insertion fails, the entire transaction rolls back (`INV-F6-DLQ-02`).
- **Idempotency:** `DeadLetterEventModel` enforces `UniqueConstraint("task_id")`, guaranteeing at most 1 DLQ record per task at the database level (`INV-F6-DLQ-04`).

---

## PART 7 — FORENSIC SANITIZATION & UTF-8 BYTE BOUNDS

### Sanitization (`sanitize_exception`)

All database URIs, password credentials, and Bearer authorization tokens are scrubbed using regular expression filters prior to storage:

```python
DB_URL_REGEX = re.compile(r"[a-zA-Z0-9\+\.\-]+://[^:]+:[^@]+@[^\s/]+")
BEARER_REGEX = re.compile(r"Bearer\s+[A-Za-z0-9\-\._~\+\/]+=*", re.IGNORECASE)
```

### UTF-8 Byte Truncation (`truncate_to_bytes`)

Truncating by character count (`str[:8192]`) is unsuited for multi-byte UTF-8 strings. Truncation calculates exact byte boundaries without slicing multi-byte characters:

```python
def truncate_to_bytes(text: str, max_bytes: int) -> str:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text

    marker = " [TRUNCATED]".encode("utf-8")
    slice_len = max_bytes - len(marker)
    truncated_bytes = encoded[:slice_len]
    return truncated_bytes.decode("utf-8", errors="ignore") + " [TRUNCATED]"
```

- **`MAX_ERROR_BYTES` = 8192 bytes (8KB)**
- **`MAX_PAYLOAD_BYTES` = 32768 bytes (32KB)**

---

## PART 8 — WORKER DRAIN STATE MACHINE & SHUTDOWN

```text
ONLINE ──(SIGINT/SIGTERM intent)──► DRAINING ──(0 RUNNING tasks)──► DRAINED (Exit 0)
                                      │
                                      └──(30s Timeout Expiration)──► FENCED (Exit 1)
                                                                       │
                                                                       ▼
                                                                F5 Recovery Reclaims
```

### Non-Blocking Signal Handler (`INV-F6-SHUTDOWN-06`)

Signal handlers registered via `signal.signal()` execute strictly non-blocking operations:

```python
def _signal_handler(signum: int, frame: Any) -> None:
    # Callback performs ONLY non-blocking Event set
    self._shutdown_requested.set()
```

---

## PART 9 — EDUCATIONAL SIMULATION VS. PRODUCTION ARCHITECTURE

### Production Architecture (Repository)
- **Authoritative Database:** PostgreSQL with WAL journal mode, explicit transaction scopes (`session_scope()`), and SQLAlchemy ORM models (`TaskModel`, `WorkerModel`, `DeadLetterEventModel`).
- **Pessimistic Concurrency Control:** Row-level locks (`SELECT ... FOR UPDATE`) enforcing lock order (`INV-F6-LOCK-01`).
- **Observability:** Structured JSON logger (`default_logger`) emitting telemetry events (`WORKER_DRAIN_INITIATED`, `WORKER_FENCED`, `EXECUTING_GRACEFUL_SHUTDOWN`).

### Educational Simulation Pseudocode
Self-contained Python simulations provide clear pedagogical demonstrations of state transitions without requiring a live PostgreSQL instance, using thread `RLock` primitives to simulate row locks.

---

## PART 10 — FORMAL INVARIANT MATRIX

| Invariant ID | Definition | Enforcement Mechanism | Adversarial Verification Test |
|---|---|---|---|
| `INV-F6-AUTH-01` | `NewAssignmentAuthority` (`ONLINE`) vs `TaskMutationAuthority` (`ONLINE`/`DRAINING`) | SQL filter `status = 'ONLINE'` for assign; `status IN ('ONLINE', 'DRAINING')` for mutate | `test_draining_worker_can_complete_active_task` |
| `INV-F6-LOCK-01` | Lock Order: Worker Row FIRST ➔ Task Row SECOND | `WorkerModel` locked via `.with_for_update()` before `TaskModel` modification | `test_global_lock_order_worker_first_then_task` |
| `INV-F6-RETRY-01` | `max_attempts` is task-bound & immutable | Configured on `TaskModel` creation; checked in assignment predicate | `test_retry_budget_initial_attempts` |
| `INV-F6-RETRY-03` | `attempts` incremented exactly ONCE on `QUEUED ➔ RUNNING` | `TaskModel.attempts + 1` in `assign_task()` update statement | `test_assign_task_increments_attempts_once` |
| `INV-F6-RETRY-07` | `attempts` UNCHANGED on failure requeue | `record_execution_failure()` excludes `attempts` from values update | `test_record_failure_does_not_increment_attempts` |
| `INV-F6-RETRY-09` | Assignment metadata cleared on requeue | `assigned_worker_id = NULL`, `fencing_token = NULL` when set to `QUEUED` | `test_assigned_worker_metadata_cleared_on_requeue` |
| `INV-F6-DLQ-02` | DLQ event written in SAME transaction as `FAILED` | `session.add(dlq_event)` performed inside same `session_scope()` block | `test_dlq_atomic_with_task_mutation` |
| `INV-F6-DLQ-04` | DLQ uniqueness enforced by DB | `UniqueConstraint("task_id")` on `dead_letter_events` table | `test_dlq_idempotency_unique_constraint` |
| `INV-F6-DLQ-05` | Strict byte bounds on error (8KB) & payload (32KB) | `truncate_to_bytes()` calculating UTF-8 byte lengths | `test_dlq_error_message_size_bound` |
| `INV-F6-DRAIN-04` | Transition to `DRAINED` requires 0 running tasks | `NOT EXISTS (SELECT 1 FROM tasks WHERE state = 'RUNNING')` DB query | `test_mark_drained_fails_when_tasks_running` |
| `INV-F6-SHUTDOWN-05` | Timeout triggers forced worker fencing | `force_fence()` increments worker `fencing_token` in DB | `test_execute_shutdown_timeout_triggers_fenced` |
| `INV-F6-SHUTDOWN-06` | Non-blocking signal handlers | Signal callback calls `threading.Event.set()` with 0 I/O | `test_register_signal_handlers_non_blocking` |

---

## PART 11 — ADVERSARIAL FAILURE SCENARIOS & RECOVERY

### Scenario A: Worker Crashes During RUNNING Execution
- **Initial State:** Worker W1 (`ONLINE`, `fencing_token = 5`), Task T1 (`RUNNING`, `lease_version = 2`, `attempts = 1`).
- **Failure:** Worker W1 process dies abruptly (`SIGKILL`).
- **Recovery:** Worker W1 heartbeat expires. F5 Cluster Recovery Engine detects offline status, resets Task T1 to `QUEUED` (`lease_version = 3`, clearing `assigned_worker_id` and `assigned_worker_fencing_token`). `attempts` remains 1.
- **Invariant:** `INV-F5-01` & `INV-F6-RETRY-09`.

### Scenario B: Stale Worker Reconnects After GC Pause
- **Initial State:** Task T1 recovered and reassigned to Worker W2 (`lease_version = 3`, `attempts = 2`). Worker W1 wakes up from 60-second GC pause.
- **Failure:** Worker W1 attempts to report task completion with `expected_lease_version = 2`.
- **Enforcement:** `UPDATE tasks WHERE task_id = 'T1' AND lease_version = 2` yields `rowcount = 0`.
- **Invariant:** `INV-F5-02` (CAS Lease Guard).
- **Result:** Worker W1 write rejected with `StaleLeaseVersionError`. Task T1 continues executing under Worker W2.

---

## PART 12 — QUALITY GATE VERIFICATION RESULTS

All 5 repository quality gate test suites have been executed and verified passing 100%:

```text
F6C Reliability Test Suite (tests/reliability/)    : 38/38 PASS
F5 PostgreSQL Security Suite (tests/security/postgres/): 45/45 PASS
Observability Suite (F6A + F6B) (tests/observability/) : 33/33 PASS
Full Repository Regression Suite                       : 2281/2281 PASS
Ruff Linter & Formatter                                : ALL CHECKS PASSED
```

---

## CONCLUSION

Sprint F6C delivers a hardened, production-grade Operational Reliability Engine for KarsaSec. By establishing PostgreSQL as the single authoritative state store, enforcing global lock ordering, separating assignment/mutation authorities via formal authority tuples, and incorporating atomic transactional DLQ handling and worker fencing epochs, the engine prevents split-brain execution, retry double-counting, zombie worker mutations, and unsafe shutdown races.

> [!IMPORTANT]
> Within a healthy PostgreSQL primary node, transactional state transitions provide the required serialization and atomicity guarantees. HA failover correctness additionally depends on synchronous/asynchronous replication semantics, failover policy, and WAL durability configuration.
