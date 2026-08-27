# Sprint F8 — Transactional Eventing & Audit Consistency Audit

## 1. Executive Summary

This document specifies the technical security audit and implementation proof for **Sprint F8 — Transactional Eventing, Outbox Reliability & Security Audit** in KarsaSec.

Sprint F8 guarantees that all task state transitions (`TASK_CREATED`, `TASK_ASSIGNED`, `TASK_COMPLETED`, `TASK_FAILED`, `TASK_RECOVERED`) generate an outbox event record and an append-only audit log entry within the **SAME** PostgreSQL database transaction (`INV-F8-OUTBOX-01`).

Furthermore, F8 incorporates **Publisher Lease Fencing** (`INV-F8-PUBLISH-04`), **Tamper-Evident Cryptographic Hash Chains** (`INV-F8-AUDIT-05`), **Per-Task Event Sequence Ordering** (`INV-F8-ORDER-03`), and **Recovery Replay Protection** (`INV-F8-REPLAY-06`).

---

## 2. Invariants Verification Matrix

| Invariant ID | Definition / Guarantee | Implementation Mechanism | Test Verification | Result |
| :--- | :--- | :--- | :--- | :--- |
| `INV-F8-OUTBOX-01` | **Transactional Atomicity** | `PostgresTaskRepository` stages `OutboxEventModel` and writes `TaskAuditLogModel` inside active session transaction. Rollback cancels all three. | `test_outbox_atomicity.py` | **PASS** |
| `INV-F8-EVENT-02` | **At-Least-Once & Idempotency** | `ReliableEventPublisher` tracks processed event IDs and verifies SHA-256 `event_hash`. Duplicate publishes produce no side effects. | `test_duplicate_publish.py` | **PASS** |
| `INV-F8-ORDER-03` | **Per-Task Sequence Ordering** | `lease_version` drives `aggregate_sequence` for per-task sequence ordering (`QUEUED` $\rightarrow$ `RUNNING` $\rightarrow$ `COMPLETED`). Global timeline uses `(created_at, event_id)`. | `test_event_ordering.py` | **PASS** |
| `INV-F8-PUBLISH-04` | **Publisher Lease Fencing** | `TransactionalOutbox.claim_pending_events` acquires rows via `FOR UPDATE SKIP LOCKED`, stamping `claimed_by` and `publisher_lease_token`. | `test_duplicate_publish.py` | **PASS** |
| `INV-F8-AUDIT-05` | **Tamper-Evident Audit Chain** | `TaskAuditLedger` computes SHA-256 hash chains (`previous_event_hash` $\rightarrow$ `event_hash`). `verify_chain_integrity()` detects tampered or modified log rows. | `test_audit_integrity.py` | **PASS** |
| `INV-F8-REPLAY-06` | **Recovery Replay Protection** | Outbox events use `deduplication_key` (`task_<action>_<task_id>_<lease_version>`) to prevent duplicate event staging during recovery retries. | `test_recovery_replay.py` | **PASS** |

---

## 3. Architecture & Data Structures

### Outbox Schema (`outbox_events` table)
- `event_id`: `String(128)` Primary event identifier (`evt_<uuid>`)
- `aggregate_id`: `String(128)` Task or Worker ID
- `aggregate_type`: `String(64)` Domain aggregate classification (`TASK`, `WORKER`)
- `event_type`: `String(64)` Event action (`TASK_CREATED`, `TASK_ASSIGNED`, `TASK_COMPLETED`, `TASK_FAILED`, `TASK_STATE_CHANGED`)
- `payload`: `Text` JSON serialized event payload
- `event_hash`: `String(64)` SHA-256 hash of payload and aggregate attributes
- `deduplication_key`: `String(128)` Unique constraint for replay protection
- `aggregate_sequence`: `Integer` Sequence version driven by `lease_version`
- `status`: `String(32)` (`PENDING`, `CLAIMED`, `PUBLISHED`, `FAILED`)
- `claimed_by`: `String(128)` Active publisher ID
- `claimed_at`: `DateTime(timezone=True)` Claim timestamp
- `publisher_lease_token`: `String(128)` Publisher lease token
- `attempt_count`: `Integer` Delivery attempt counter
- `published_at`: `DateTime(timezone=True)` Publish completion timestamp

### Tamper-Evident Audit Schema (`task_audit_log` table)
- `task_id`: `String(128)` Index
- `previous_state`: `String(32)` State before transition
- `new_state`: `String(32)` State after transition
- `worker_id`: `String(128)` Assignee worker ID
- `fencing_token`: `Integer` Worker fencing token
- `lease_version`: `Integer` Task lease version
- `reason`: `String(256)` Human-readable / system state change reason
- `previous_event_hash`: `String(64)` Cryptographic hash of preceding audit entry for this task
- `event_hash`: `String(64)` SHA-256 hash of `[task_id, prev_hash, prev_state, new_state, worker_id, fencing_token, lease_version, reason]`

---

## 4. Verification Results

- `tests/events/test_outbox_atomicity.py`: **2/2 PASS**
- `tests/events/test_duplicate_publish.py`: **2/2 PASS**
- `tests/events/test_event_ordering.py`: **1/1 PASS**
- `tests/events/test_recovery_replay.py`: **1/1 PASS**
- `tests/events/test_audit_integrity.py`: **2/2 PASS**
- **Total F8 Event Security Suite**: **8/8 PASS**
