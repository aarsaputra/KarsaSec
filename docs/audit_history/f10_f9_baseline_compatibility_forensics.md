# F10/F9 Baseline Compatibility Forensic Report

**Date**: 2026-08-20  
**Target Repository**: `karsasec`  
**Status**: **F10 Security Audit PASS — Release Gate BLOCKED by F9 baseline compatibility**  

---

## Executive Summary

This forensic report investigates the incompatibility between the existing `tests/recovery/` test suite and the baseline PostgreSQL task repository (`karsasec/persistence/postgres_task_repository.py`) on clean `git HEAD`.

Key Findings:
1. **F10 Security Correctness**: All F10 Phase 5 adversarial security suites (`tests/ai/test_f10_phase5_adversarial_*.py`) pass **19/19 (100%)**.
2. **Strict F9 Immutability**: All protected F9 paths (`karsasec/recovery/`, `karsasec/events/audit_ledger.py`, `karsasec/events/outbox.py`, `karsasec/persistence/postgres_task_repository.py`) are strictly unmodified (`git diff` is empty).
3. **Forensic Root Cause**: The 7 failures in `tests/recovery/` are **NOT** caused by F10 code. They stem from a historical contract mismatch in `postgres_task_repository.py` at `git HEAD`, which lacks `assign_task()` and automatic outbox/audit log staging upon task creation.
4. **F10 Isolation**: The F10 AI Provider Gateway operates independently of `PostgresTaskRepository.assign_task()`.

---

## Protected Baseline Verification

Verification command executed on repository root:

```bash
git diff --name-only -- \
  karsasec/recovery/ \
  karsasec/events/audit_ledger.py \
  karsasec/events/outbox.py \
  karsasec/persistence/postgres_task_repository.py
```

**Observed Result**:
`<empty>` (0 modified files across all protected F9 paths).

---

## Observed Recovery Failures

Execution of `pytest tests/recovery -v` on clean `git HEAD` yields 7 failures:

| Test Case | Failure Type | Exact Exception / Error |
| :--- | :--- | :--- |
| `TestDisasterRecoveryEndToEndF9.test_full_disaster_recovery_restores_task_state_and_outbox` | `AttributeError` | `'PostgresTaskRepository' object has no attribute 'assign_task'` |
| `TestRecoveryDeterminismF9.test_repeated_restore_produces_identical_state_hash` | `AttributeError` | `'PostgresTaskRepository' object has no attribute 'assign_task'` |
| `TestSnapshotBoundaryReplayF9.test_replay_respects_boundary_marker` | `AttributeError` | `'PostgresTaskRepository' object has no attribute 'assign_task'` |
| `TestAuditChainValidationF9.test_corrupted_audit_chain_blocks_replay` | `AssertionError` | `assert audit_entry is not None` (`None is not None`) |
| `TestF9SecurityBaselineContract.test_pre_mutation_boundary_prevents_task_deletion_on_audit_corruption` | `AssertionError` | `assert audit_row is not None` (`None is not None`) |
| `TestOutboxRebuildF9.test_outbox_wipe_and_rebuild_success` | `AssertionError` | `assert rebuilt_count == 2` (`0 == 2`) |
| `TestRebuildOriginalEventIdentityF9.test_outbox_rebuild_preserves_original_event_identity` | `AssertionError` | `assert orig_evt is not None` (`None is not None`) |

---

## Repository Contract Analysis

A comparative matrix of the repository methods and behaviors expected by the test suite versus what is present in `git HEAD`:

| Method / Behavior | Expected By | Present At HEAD | Historical Baseline | Classification |
| :--- | :--- | :---: | :---: | :--- |
| `create_task()` | `TaskRepository` interface | **YES** | **YES** | Standard repository method |
| `get_task()` | `TaskRepository` interface | **YES** | **YES** | Standard repository method |
| `update_task()` | `TaskRepository` interface | **YES** | **YES** | Standard repository method |
| `atomic_transition()` | F5 PostgreSQL Authority | **YES** | **YES** | Standard atomic state transition |
| `assign_task()` | `tests/recovery/` | **NO** | **NO** in `d6d2888` | Missing contract method |
| Auto Audit Staging in `create_task` | `tests/recovery/` audit tests | **NO** | **NO** in `d6d2888` | Missing audit side-effect |
| Auto Outbox Staging in `create_task` | `tests/recovery/` outbox tests | **NO** | **NO** in `d6d2888` | Missing outbox side-effect |

---

## Git History Evidence

1. Commit `d6d2888` (`chore: save state prior to type checking fix in outbox publisher test`) introduced `karsasec/persistence/postgres_task_repository.py`.
2. In commit `d6d2888`, `PostgresTaskRepository` implemented:
   - `create_task`, `get_task`, `update_task`, `atomic_transition`, `get_active_task_by_fingerprint`, `list_tasks`.
3. `PostgresTaskRepository` in commit `d6d2888` did **not** include `assign_task` or automatic outbox/audit staging in `create_task`.
4. The base abstract class `TaskRepository` (`karsasec/workers/repository.py`) also does **not** declare `assign_task()`.

---

## F9 Historical Contract vs Current HEAD Contract

- **`karsasec/workers/repository.py` (`TaskRepository`)**:
  Defines abstract methods `create_task`, `get_task`, `update_task`, `atomic_transition`, `get_active_task_by_fingerprint`, `list_tasks`.
- **`karsasec/persistence/postgres_task_repository.py` (`PostgresTaskRepository`)**:
  Implements the exact interface declared in `TaskRepository`.
- **`tests/recovery/`**:
  Written assuming an extended repository implementation that includes worker assignment helper methods (`assign_task`) and automatic outbox/audit event emission inside `create_task()`.

---

## Root Cause Classification

The 7 recovery failures fall into 2 root cause categories:

1. **Category 1: Missing Method Error (3 failures)**
   - Tests call `self.repo.assign_task()`.
   - `PostgresTaskRepository` on `git HEAD` does not implement `assign_task()`.
2. **Category 2: Cascading Audit/Outbox Staging Mismatch (4 failures)**
   - Tests assume `create_task()` automatically writes rows to `TaskAuditLogModel` and `OutboxEventModel`.
   - In `git HEAD`, `create_task()` only persists `TaskModel`. Audit logging and outbox staging are handled via explicit service calls (`TaskAuditLedger.record_transition` and `TransactionalOutbox.stage_event`).

**Classification**: **Pre-Existing F9 Baseline Contract Incompatibility** (Category 3 / 4). It is NOT an F10-induced regression.

---

## F10 Dependency Analysis

A codebase static analysis of `karsasec/ai/` confirms:
1. `karsasec/ai/` contains **0 references** to `PostgresTaskRepository`.
2. `karsasec/ai/` contains **0 references** to `assign_task`.
3. F10 AI services (`AIBudgetService`, `AIRequestStateService`, `ProviderRouter`, `AIEventService`) interact with persistence via dedicated models (`AIBudgetModel`, `AIRequestModel`, `AIProviderAttemptModel`) and standard `TransactionalOutbox`/`TaskAuditLedger` APIs.

The F10 AI Provider Gateway is **100% independent** from the missing `assign_task` repository contract.

---

## Security Impact

- **F10 Invariants**: Fully preserved. 19/19 adversarial tests pass.
- **F9 Immutability**: 100% intact. Zero modifications to protected files.
- **Operational Risk & Contract Gap**: F10 does not depend on the missing contract gap and the F10 adversarial suite is 19/19 PASS. However, because `tests/recovery` fails on clean HEAD, operational impact on F9 production recovery workflows remains unverified until F9 contract reconciliation is executed.

---

## Recommended Remediation

To resolve the release gate blockage without violating F9 immutability:
1. Create a dedicated F9 baseline reconciliation branch (`fix/f9-repository-contract`).
2. Implement `assign_task()` and audit/outbox helper bindings in `PostgresTaskRepository` in that dedicated change.
3. Validate that `pytest tests/recovery` passes on that branch.
4. Merge the reconciliation branch into `main`.

---

## Release Gate Recommendation

```text
F10 Phase 5 Security Verification:
PASS (19/19 adversarial tests PASS)

F9 Baseline Immutability:
PASS (0 files modified in protected paths)

F10 Release Readiness:
BLOCKED

Blocking Issue:
F9 git HEAD PostgresTaskRepository is incompatible with the existing recovery-test contract.

Required Next Action:
Reconcile the F9 baseline repository contract in a dedicated F9 maintenance change before final release tag.
```
