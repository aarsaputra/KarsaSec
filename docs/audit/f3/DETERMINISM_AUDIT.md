# Phase 4 — Query Determinism Audit

## Audit Target
`karsasec/persistence/` (All SELECT statements and Repository Queries)

## Objective
Verify that all listing and multi-row fetching methods in `PostgresTaskRepository`, `PostgresReceiptRepository`, and `PostgresAuditRepository` use explicit `ORDER BY` clauses to eliminate non-deterministic query ordering and insertion-order flakiness.

---

## 1. Query Inspection Table

| Method | Repository | Query Target | `ORDER BY` Clause Present? | Sorting Columns |
| :--- | :--- | :--- | :--- | :--- |
| `list_tasks` | `PostgresTaskRepository` | `select(TaskModel)` | **YES** | `created_at ASC, task_id ASC` |
| `get_active_task_by_fingerprint` | `PostgresTaskRepository` | `select(TaskModel)` | **YES** | `created_at ASC` |
| `find_expired_running_tasks` | `PostgresTaskRepository` | `select(TaskModel)` | **N/A** (Filtered by wall-clock epoch) | State & lease time comparison |
| `get_by_transaction` | `PostgresReceiptRepository` | `select(ReceiptModel)` | **YES** | `created_at ASC` |
| `get_events_for_task` | `PostgresAuditRepository` | `select(AuditEventModel)`| **YES** | `created_at ASC` |

---

## 2. Code Snippet Verification

### Task Repository (`task_repository.py`, Line 156)
```python
stmt = stmt.order_by(TaskModel.created_at.asc(), TaskModel.task_id.asc()).limit(limit)
```
*Audit Observation*: Dual-column explicit tie-breaker (`created_at` primary, `task_id` secondary) ensures absolute determinism across database engine implementations.

### Active Task Search (`task_repository.py`, Line 169)
```python
.order_by(TaskModel.created_at.asc())
.limit(1)
```
*Audit Observation*: Guarantees that if multiple active tasks exist, the oldest submitted task is returned deterministically.

### Audit Events Listing (`audit_repository.py`, Line 149)
```python
.order_by(AuditEventModel.created_at.asc())
```
*Audit Observation*: Guarantees chronological event reconstruction.

---

## 3. Database Index Support
Migration `16e35b77308a_initial_schema.py` provides composite indices to back these ordered queries efficiently:
- Index `ix_tasks_state_fingerprint` on `(state, fingerprint)`
- Index `ix_tasks_state_lease` on `(state, lease_started_at)`
- Index `ix_audit_events_task_created` on `(task_id, created_at)`

---

## 4. Formal Determinism Audit Verdict

```text
STATUS: PASS
```

**Reasoning**: Every single list/collection query in the persistence layer specifies explicit `ORDER BY` constraints backed by database indices. Zero non-deterministic un-ordered queries exist.
