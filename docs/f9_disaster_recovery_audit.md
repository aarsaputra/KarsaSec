# Sprint F9 — Distributed Snapshot, Checkpoint & Disaster Recovery Audit

## Executive Summary

Sprint F9 completes the implementation of a production-grade Distributed Snapshot, Checkpoint, and Disaster Recovery Engine for KarsaSec. Built upon the tamper-evident transactional eventing foundation of Sprint F8, Sprint F9 guarantees deterministic state reconstruction, point-in-time recovery (PITR) boundary safety, original event identity preservation, and multi-tier fencing following database crashes or restores.

---

## Authoritative Invariants (`INV-F9-SNAP-01` to `INV-F9-RECOVERY-13`)

| Invariant ID | Description | Architectural Enforcement Mechanism | Status |
| :--- | :--- | :--- | :--- |
| `INV-F9-SNAP-01` | **Deterministic Snapshot** | `SnapshotManager.create_snapshot()` orders task aggregates ascendantly by `task_id` and produces canonical JSON. | **VERIFIED** |
| `INV-F9-RECOVERY-02` | **Cluster Restart Safety** | Rebuilds outbox and state transitions using unique deduplication keys to eliminate duplicate logical tasks. | **VERIFIED** |
| `INV-F9-AUDIT-03` | **Audit Ledger Authority** | `AuditReplayEngine` reconstructs task states directly from the cryptographic hash chain in `TaskAuditLogModel`. | **VERIFIED** |
| `INV-F9-REPLAY-04` | **Idempotent Replay** | `AuditReplayEngine.replay_events()` uses upsert/CAS logic; multiple executions produce bit-for-bit identical state. | **VERIFIED** |
| `INV-F9-HASH-05` | **Merkle-Lite Root Hash** | Composite Root Hash = `SHA256(snapshot_hash + ":" + audit_head_hash + ":" + outbox_head_hash)` validating complete aggregate state. | **VERIFIED** |
| `INV-F9-VERSION-06` | **Schema Version Safety** | Restores check `schema_version == CURRENT_SCHEMA_VERSION`; rejects incompatible schema versions with `SchemaMismatchError`. | **VERIFIED** |
| `INV-F9-FENCE-07` | **Recovery Lease Fencing** | Atomic `UPDATE recovery_checkpoints` with `recovery_lease_token` prevents split-brain recovery across node clusters. | **VERIFIED** |
| `INV-F9-PURITY-08` | **Pure Replay Enforcement** | Reconstructs state from `Snapshot + Audit Ledger` without reading mutable DB state. | **VERIFIED** |
| `INV-F9-RECOVERY-09` | **Fail-Closed Partial Restore** | Detects missing audit ledger or persistence tables during recovery and raises `PartialRecoveryError`. | **VERIFIED** |
| `INV-F9-RECOVERY-10` | **Point-In-Time Boundary** | Snapshots record `max_lease_version`, `max_outbox_sequence`, and `audit_chain_head`; replay strictly processes events *after* boundary. | **VERIFIED** |
| `INV-F9-RECOVERY-11` | **Snapshot Generation Fencing** | Monotonic `snapshot_generation` tracking; attempts to restore older generation numbers are rejected with `SnapshotFencingError`. | **VERIFIED** |
| `INV-F9-RECOVERY-12` | **Pre-Replay Audit Validation** | Mandatory execution of `verify_chain_integrity()` across all aggregate audit logs before state mutation. | **VERIFIED** |
| `INV-F9-RECOVERY-13` | **Deterministic Replay** | Repeated restore operations ($1\times, 10\times, 100\times$) produce bit-for-bit identical final state hashes. | **VERIFIED** |

---

## Architectural Mechanisms & Fail-Closed Sequence

### Pre-Mutation Fail-Closed Sequence
To prevent partial database mutation in the event of snapshot corruption or audit tampering, recovery operations execute in strict fail-closed order:
1. `verify_restore_integrity()`: Confirm presence and readability of all ORM models (`TaskModel`, `TaskAuditLogModel`, `OutboxEventModel`, `RecoveryCheckpointModel`).
2. `verify_snapshot()`: Verify canonical JSON snapshot payload structure and re-compute Merkle-lite root hash.
3. `verify_audit_chain()`: Cryptographically verify audit log hash linkage (`genesis → ... → audit_chain_head`) for all task streams.
4. `load_snapshot()`: Enforce `snapshot_generation` fencing and schema version validation before clearing existing state.
5. `replay_events()`: Replay audit entries strictly post-boundary onto `TaskModel` records.
6. `rebuild_outbox_from_audit()`: Reconstruct outbox events with **original event identity** (`event_id`, `deduplication_key`, `aggregate_sequence`, `event_hash`).

---

## Quality Gate Verification Summary

| Gate | Suite Name | Test Count | Result |
| :--- | :--- | :---: | :---: |
| **F9 Disaster Recovery** | `pytest tests/recovery/ -v` | **13 / 13** | **PASS** |
| **F8 Event Security** | `pytest tests/events/ -v` | **8 / 8** | **PASS** |
| **F7 Reliability** | `pytest tests/reliability/ -v` | **48 / 48** | **PASS** |
| **F5 PostgreSQL Security** | `pytest tests/security/postgres/ -v` | **48 / 48** | **PASS** |
| **Observability** | `pytest tests/observability/ -v` | **33 / 33** | **PASS** |
| **Full Regression** | `pytest -q` | **2315 / 2315** | **PASS** |
| **Ruff Formatting** | `ruff format --check karsasec tests` | **784 Files** | **PASS** |
| **Ruff Linting** | `ruff check karsasec tests` | **Clean** | **PASS** |
