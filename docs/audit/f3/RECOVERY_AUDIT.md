# Phase 6 — Startup Recovery Engine Audit

## Audit Target
`karsasec/persistence/recovery.py` (`StartupRecoveryEngine`) and `karsasec/persistence/task_repository.py` (`find_expired_running_tasks`)

## Objective
Verify that `StartupRecoveryEngine` safely handles crash recovery by targeting ONLY tasks in `RUNNING` state with expired leases, while NEVER touching terminal states (`COMPLETED`, `FAILED`, `CANCELLED`).

---

## 1. SQL Filter Query Audit (`task_repository.py`, Line 181-189)

```python
stmt = select(TaskModel).where(
    TaskModel.state == "RUNNING",
    TaskModel.lease_started_at.is_not(None),
    text(
        f"EXTRACT(EPOCH FROM (NOW() - lease_started_at)) > {int(lease_timeout_seconds)}"
    ),
)
```

### Analysis
1. **Targeting**: Query strictly restricts matching rows to `TaskModel.state == "RUNNING"`.
2. **Lease Condition**: Requeuing requires `NOW() - lease_started_at > lease_timeout_seconds`.

---

## 2. Transition Rules Matrix

| Initial State | Lease Status | Max Attempts Status | Target Transition State | Allowed? | Code Line Reference |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `RUNNING` | Expired (>300s) | `attempts < max_attempts` | `FAILED_RETRYABLE` -> `QUEUED` | **YES** | `recovery.py:66-71` |
| `RUNNING` | Expired (>300s) | `attempts >= max_attempts`| `FAILED` | **YES** | `recovery.py:87-91` |
| `COMPLETED` | Any | Any | **UNTOUCHED** | **FORBIDDEN** | Excluded by DB WHERE clause |
| `FAILED` | Any | Any | **UNTOUCHED** | **FORBIDDEN** | Excluded by DB WHERE clause |
| `CANCELLED` | Any | Any | **UNTOUCHED** | **FORBIDDEN** | Excluded by DB WHERE clause |
| `PENDING` | Any | Any | **UNTOUCHED** | **FORBIDDEN** | Excluded by DB WHERE clause |

---

## 3. Re-entrancy & Replay Protection

### Re-entrancy Audit
If `StartupRecoveryEngine.recover_running_tasks()` is executed multiple times in rapid succession:
1. The first run updates matched `RUNNING` tasks to `QUEUED` (or `FAILED`).
2. Subsequent runs execute `find_expired_running_tasks()`, which queries `TaskModel.state == "RUNNING"`.
3. Since the state is now `QUEUED` or `FAILED`, 0 rows match on second execution.
4. The recovery operation is 100% idempotent and immune to replay.

---

## 4. Adversarial Test Verification
- `TestStartupRecovery.test_recovery_engine_requeues_running_task_with_expired_lease`: Passed.
- `TestStartupRecovery.test_exhausted_task_marked_failed_not_requeued`: Passed.
- `TestPhase8AdversarialScenarios.test_4_lease_recovery_replay`: Passed.
- `TestPhase8AdversarialScenarios.test_7_task_resurrection_attack`: Passed.

---

## 5. Formal Recovery Audit Verdict

```text
STATUS: PASS
```

**Reasoning**: `StartupRecoveryEngine` exclusively targets stale `RUNNING` tasks with expired wall-clock leases. Task resurrection from terminal states (`COMPLETED`/`FAILED`/`CANCELLED`) is impossible. Replay attacks are structurally mitigated by state transition atomicity.
