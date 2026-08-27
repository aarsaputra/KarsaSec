# F9 Baseline Contract Reconciliation & Architecture Decision Report

**Branch:** `fix/f9-repository-contract`  
**Date:** 2026-08-20  
**Authoritative Persistence Contract:** PostgreSQL TaskRepository (`karsasec/persistence/postgres_task_repository.py`)  

---

## 1. Executive Summary & Problem Context

During the Sprint F10 Phase 5 Security Audit, the Distributed AI Gateway achieved a 100% pass rate (19/19 security scenarios) with strict zero-modification enforcement on legacy F9 modules. However, the release gate remained **BLOCKED** due to pre-existing contract incompatibilities between the production `PostgresTaskRepository` implementation and legacy recovery/reliability test suites (`tests/recovery`, `tests/reliability`).

### Root Cause Analysis
1. **Missing Repository Methods:** The recovery test suite (`tests/recovery/test_disaster_recovery.py`, `tests/reliability/f7/test_worker_authority_f7.py`) expected `PostgresTaskRepository` to expose high-level transactional worker lifecycle methods (`assign_task()`, `complete_task()`, `record_execution_failure()`).
2. **Missing Transactional Event Staging:** Legacy tests expected `PostgresTaskRepository.create_task()`, `assign_task()`, `complete_task()`, and `record_execution_failure()` to automatically stage corresponding entries into `TaskAuditLogModel` (via `TaskAuditLedger.record_transition`) and `OutboxEventModel` (via `TransactionalOutbox.stage_event`) within the open database transaction.
3. **Deduplication Identity Mismatch:** `AuditReplayEngine.rebuild_outbox_from_audit()` expected outbox events to carry deterministic deduplication keys (e.g. `task_created_<id>`, `task_assigned_<id>_<v>`, `task_completed_<id>_<v>`, `task_failure_<id>_<v>`).

---

## 2. Reconciliation & Implementation Matrix

To restore full test suite pass rates without compromising PostgreSQL authority guarantees or introducing breaking changes to production services, the following canonical repository contract was implemented in `PostgresTaskRepository`:

| Method | State Transition | Fencing & Token Handling | Audit Ledger Event | Outbox Event & Deduplication Key |
|---|---|---|---|---|
| `create_task()` | `NONE` -> `QUEUED` / `PENDING` | Sets initial `lease_version` (1) | `record_transition(previous="NONE", reason="TASK_CREATED")` | `stage_event(event_type="TASK_CREATED", dedup_key="task_created_<id>")` |
| `assign_task()` | `QUEUED` -> `RUNNING` | Increments `attempts` & `lease_version`, checks worker status (`ONLINE`) | `record_transition(previous=prev_state, new="RUNNING", reason="TASK_ASSIGNED")` | `stage_event(event_type="TASK_ASSIGNED", dedup_key="task_assigned_<id>_<v>")` |
| `complete_task()` | `RUNNING` -> `COMPLETED` | Validates `expected_lease_version` & worker fencing token | `record_transition(previous="RUNNING", new="COMPLETED", reason="TASK_COMPLETED")` | `stage_event(event_type="TASK_COMPLETED", dedup_key="task_completed_<id>_<v>")` |
| `record_execution_failure()` | `RUNNING` -> `FAILED` (if attempts >= max) or `QUEUED` (retryable) | Increments `lease_version`. On exhaustion, creates `DeadLetterEventModel` record. | `record_transition(reason="TASK_FAILED" or "TASK_RETRIED")` | `stage_event(event_type="TASK_FAILED" or "TASK_RETRIED", dedup_key="task_failure_<id>_<v>" or "task_transition_<id>_<v>")` |
| `atomic_transition()` | CAS State Transition | Enforces SQL `WHERE lease_version = expected AND state IN (...)` | `record_transition(reason="ATOMIC_TRANSITION")` | `stage_event(dedup_key="task_transition_<id>_<v>")` |

---

## 3. Security & Authority Invariants Preservation

The contract reconciliation strictly adheres to all established security and distributed system invariants:

1. **PostgreSQL Authority (INV-F5-01, INV-F5-02):**  
   All state transitions, worker lease version increments, and fencing token validations execute atomically within PostgreSQL session transaction scopes using `SELECT ... FOR UPDATE` row locking. No process-local memory or non-authoritative worker state override PostgreSQL authority.
2. **Worker Fencing & Drain Safety (INV-F6-SHUTDOWN-05, INV-F7-W01):**  
   - `assign_task()` rejects assignment if worker status is `DRAINING`, `DRAINED`, `FENCED`, or `OFFLINE` (raises `InvalidWorkerStateError`).
   - `complete_task()` and `record_execution_failure()` reject mutations if the worker's active fencing token in PostgreSQL exceeds the submitted token, or if the worker is marked `FENCED` or `OFFLINE` (raises `WorkerFencedError`).
3. **Privacy Boundary Preservation (R7-R9):**  
   No source code, raw patches, LLM prompts, credentials, or bearer tokens are persisted in `tasks`, `audit_events`, `outbox_events`, or `dead_letter_events`. Only SHA-256 fingerprints, metadata, sanitized error messages (<= 8KB), and state identifiers are recorded.
4. **F9 Protected Infrastructure Integrity:**  
   Zero modifications were made to `karsasec/recovery/`, `karsasec/events/audit_ledger.py`, or `karsasec/events/outbox.py`. All changes are concentrated in the repository persistence interface layer (`karsasec/persistence/postgres_task_repository.py`, `karsasec/persistence/task_repository.py`, `karsasec/workers/repository.py`).

---

## 4. Verification Suite Results

All test suites were executed sequentially on the reconciled repository:

| Test Suite | Command | Result |
|---|---|---|
| Recovery Test Suite | `pytest tests/recovery -v` | **15/15 PASS** |
| Reliability & Fencing Suite | `pytest tests/reliability -v` | **48/48 PASS** |
| Postgres Authority F7 Suite | `pytest tests/security/postgres/f7/test_postgres_authority_f7.py -v` | **3/3 PASS** |
| Events & Audit Ledger Suite | `pytest tests/events -v` | **8/8 PASS** |
| F10 Phase 5 Adversarial Audit | `pytest tests/ai/test_f10_phase5_*.py -v` | **21/21 PASS** |
| Entire Repository Test Suite | `pytest -q` | **2419/2419 PASS** |

---

## 5. Conclusion & Recommendation

The contract gap between `PostgresTaskRepository` and the recovery/reliability test requirements is fully resolved. The F9 baseline immutability and PostgreSQL authoritative invariants are preserved, and the entire repository test suite (2419/2419 tests) passes with zero errors.

**Release Gate Recommendation:** ✅ **UNBLOCKED / READY FOR MERGE**
