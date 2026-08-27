# Sprint F9 — Security Baseline & Protected Recovery Contract

## 1. Baseline Status

```text
F9 STATUS: COMPLETE
F9 FINAL AUDIT: PASS
VERIFIED baseline: 13/13 F9, 8/8 F8, 48/48 F7, 48/48 F5, 33/33 Observability, 2315/2315 Full Regression
LINT: Ruff format PASS | Ruff check PASS
FINDINGS: 0 | BYPASSES: 0
```

This security baseline is **LOCKED** and **FROZEN**. The 13 invariants defined herein represent non-negotiable distributed-systems contracts for the KarsaSec platform.

---

## 2. Security Guarantees & Formal Invariants

| Invariant ID | Guarantee | Enforcement Mechanism | Failure Exception |
| :--- | :--- | :--- | :--- |
| `INV-F9-SNAP-01` | **Deterministic Snapshot** | `SnapshotManager.create_snapshot()` orders task records ascendantly by `task_id` and formats payload using canonical JSON (`sort_keys=True`, `separators=(',', ':')`). | `SnapshotIntegrityError` |
| `INV-F9-RECOVERY-02` | **Cluster Restart Safety** | `AuditReplayEngine.rebuild_outbox_from_audit()` preserves original `event_id`, `deduplication_key`, `aggregate_sequence`, and `event_hash`. Outbox table enforces UNIQUE constraint on `deduplication_key`. | `OutboxDuplicationError` |
| `INV-F9-AUDIT-03` | **Audit Ledger Authority** | `AuditReplayEngine.replay_events()` reconstructs state purely from `TaskAuditLogModel` ordered chronologically without reading mutable `TaskModel` state as an input source. | `AuditCorruptionError` |
| `INV-F9-REPLAY-04` | **Idempotent Replay** | Replaying the exact audit log stream repeatedly ($1\times, 10\times, 100\times$) results in bit-for-bit identical aggregate task states. | `ReplayStateMismatchError` |
| `INV-F9-HASH-05` | **Merkle-Lite Root Hash** | `SnapshotManager.verify_snapshot()` recomputes snapshot payload SHA-256 and Merkle-lite root hash (`SHA256(snapshot_hash + ":" + audit_head_hash + ":" + outbox_head_hash)`). | `SnapshotIntegrityError` |
| `INV-F9-VERSION-06` | **Schema Version Safety** | `SnapshotManager.load_snapshot()` verifies `snapshot_data["schema_version"] == CURRENT_SCHEMA_VERSION` (1) before mutation. | `SchemaMismatchError` |
| `INV-F9-FENCE-07` | **Recovery Lease Fencing** | `RecoveryCheckpoint.restore_checkpoint()` executes atomic SQL `UPDATE ... WHERE checkpoint_id = :id AND (recovery_lease_token = :token OR recovery_lease_token IS NULL)` with rowcount verification. | `RecoveryFencingError` |
| `INV-F9-PURITY-08` | **Pure Replay Enforcement** | Static call graph analysis confirms zero reads from mutable task state influence state transformation during replay. | `StatePurityViolation` |
| `INV-F9-RECOVERY-09` | **Fail-Closed Partial Restore** | `AuditReplayEngine.verify_restore_integrity()` scalar reads `TaskModel`, `TaskAuditLogModel`, `OutboxEventModel`, and `RecoveryCheckpointModel` tables. | `PartialRecoveryError` |
| `INV-F9-RECOVERY-10` | **Point-In-Time Boundary** | Snapshots record `max_lease_version`, `max_outbox_sequence`, and `audit_chain_head`. Event replay strictly skips entries up to `audit_chain_head` and replays subsequent entries. | `BoundaryMismatchError` |
| `INV-F9-RECOVERY-11` | **Snapshot Generation Fencing** | `SnapshotManager.load_snapshot()` queries latest `RecoveryCheckpointModel.snapshot_generation` and rejects older generation numbers. | `SnapshotFencingError` |
| `INV-F9-RECOVERY-12` | **Pre-Replay Audit Validation** | `AuditReplayEngine.verify_audit_chain()` verifies cryptographic hash linkage (`genesis → ... → audit_chain_head`) for all task streams before any task state mutation. | `AuditCorruptionError` |
| `INV-F9-RECOVERY-13` | **Deterministic Replay** | Executing 100 consecutive restoration cycles produces identical final state root hashes and bit-for-bit canonical snapshot representations. | `NonDeterministicStateError` |

---

## 3. Protected Execution Sequence

Recovery execution must strictly adhere to the following pre-mutation fail-closed pipeline:

```text
verify_restore_integrity()
        ↓ (Verifies presence & readability of all 4 persistence tables)
recovery fencing
        ↓ (Atomic conditional UPDATE on RecoveryCheckpointModel with token check)
verify_snapshot()
        ↓ (Validates snapshot JSON structure & re-computes Merkle-lite root hash)
verify_audit_chain()
        ↓ (Cryptographically validates audit chain from genesis across all tasks)
schema validation
        ↓ (Confirms schema_version == CURRENT_SCHEMA_VERSION)
snapshot generation fencing
        ↓ (Confirms snapshot_generation >= latest persisted generation)
FIRST MUTATION
        ↓ (session.execute(delete(TaskModel)) & insert snapshot task entries)
snapshot restoration
        ↓ (Populates initial TaskModel records from snapshot payload)
boundary replay
        ↓ (Replays audit events occurring strictly after audit_chain_head)
outbox reconstruction
        ↓ (Rebuilds OutboxEventModel entries preserving original identity)
final deterministic verification
        ↓ (Confirms state integrity)
commit
        ↓ (Transaction committed atomically)
```

---

## 4. Mutation Boundary Safety Contract

> **CRITICAL RULE**: No destructive recovery mutation (such as `delete(TaskModel)` or state overwrites) may occur before all pre-flight integrity (`verify_restore_integrity`), fencing (`recovery_lease_token`), snapshot hash integrity (`verify_snapshot`), cryptographic audit chain (`verify_audit_chain`), schema version (`schema_version`), and generation fencing (`snapshot_generation`) validations pass.

---

## 5. Protected Subsystems & Files

The following codebase areas are designated as **Security-Sensitive Baseline Components**:

```text
karsasec/recovery/
    snapshot.py
    replay.py
    checkpoint.py
    __init__.py

karsasec/persistence/models.py
karsasec/events/audit_ledger.py
karsasec/events/outbox.py
karsasec/persistence/postgres_task_repository.py
tests/recovery/
```

Any pull request or architectural change modifying these components MUST execute the complete F9 recovery suite (`pytest tests/recovery/ -v`) and the full system regression suite (`pytest -q`), maintaining 100% pass rates across all 13 invariants.
