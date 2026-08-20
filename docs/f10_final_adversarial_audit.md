# Sprint F10 — Final Adversarial Security Audit & F9 Immutability Report

**Date**: 2026-08-20  
**Target Repository**: `karsasec`  
**Status**: **BLOCKED (F9 Baseline Incompatibility / F10 Security Invariants PASS)**  

---

## Executive Summary

This report documents the final adversarial security verification for **Sprint F10: Distributed AI Provider Gateway, Cost Router & Token-Budget Fencing Engine**.

Following strict user guidelines:
1. **Zero modifications** were permitted or retained in frozen F9 protected paths (`karsasec/recovery/`, `karsasec/events/audit_ledger.py`, `karsasec/events/outbox.py`, `karsasec/persistence/postgres_task_repository.py`).
2. All F10 Phase 5 adversarial security suites (`tests/ai/test_f10_phase5_*.py`) were executed against an unmodified F9 baseline tree.

---

## 1. Protected F9 Baseline Working Tree Verification

```bash
git diff --name-only -- \
  karsasec/recovery/ \
  karsasec/events/audit_ledger.py \
  karsasec/events/outbox.py \
  karsasec/persistence/postgres_task_repository.py
```

**Observed Output**:
`<empty>` (0 files modified)

---

## 2. Phase 5 Test Coverage & Domain Verification

| Audit Domain | Test File | Test Method | Status |
| :--- | :--- | :--- | :--- |
| **Budget Fencing & Concurrency** | `test_f10_phase5_adversarial_budget.py` | `test_100_concurrent_workers_budget_reservation_boundary` | **PASS** |
| | | `test_concurrent_state_transition_cas_winner` | **PASS** |
| | | `test_mixed_operations_atomic_consistency` | **PASS** |
| | | `test_budget_accounting_rejects_negative_and_floating_point` | **PASS** |
| **Crash Boundaries A–J** | `test_f10_phase5_adversarial_crash.py` | `test_crash_boundary_a_through_j_rollback_atomicity` | **PASS** |
| | | `test_retry_after_crash_is_clean_and_idempotent` | **PASS** |
| **Router Determinism** | `test_f10_phase5_adversarial_determinism.py` | `test_routing_determinism_under_concurrent_registration_permutations` | **PASS** |
| | | `test_repeated_routing_100x_trials_are_100_percent_deterministic` | **PASS** |
| **Outbox & Audit Events** | `test_f10_phase5_adversarial_events.py` | `test_ai_event_lifecycle_sequence_monotonicity` | **PASS** |
| | | `test_audit_ledger_hash_chain_verification` | **PASS** |
| **Idempotency** | `test_f10_phase5_adversarial_idempotency.py` | `test_duplicate_event_staging_returns_existing_event` | **PASS** |
| | | `test_duplicate_request_creation_idempotent_and_conflict_rejection` | **PASS** |
| **Provider Router Failover** | `test_f10_phase5_adversarial_router.py` | `test_registry_order_invariance` | **PASS** |
| | | `test_failover_sequence_excludes_failed_providers` | **PASS** |
| | | `test_unhealthy_and_unknown_providers_are_bypassed` | **PASS** |
| | | `test_cost_ceiling_filters_expensive_providers` | **PASS** |
| **Secret Isolation** | `test_f10_phase5_adversarial_secrets.py` | `test_ai_event_service_rejects_credential_fuzz_patterns` | **PASS** |
| | | `test_attempt_ledger_rejects_unbounded_error_strings` | **PASS** |
| | | `test_zero_raw_secrets_in_all_persistence_tables` | **PASS** |
| **F9 Baseline Immutability** | `test_f10_phase5_f9_regression.py` | `test_f9_protected_files_are_unmodified` | **PASS** |
| | | `test_f9_recovery_suite_passes` | **BLOCKED** |

---

## 3. Crash Boundaries A–J Forensic Matrix

| Boundary | Pipeline Stage | Crash Injection Point | Durable State after Abort | Idempotent Retry | Budget Untainted | Outbox Events Staged | Verification Result |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :---: |
| **A** | Request Creation | Immediately post `AIRequestStateService.create_request` | None (`AIRequestModel` deleted) | YES | YES | 0 | **PASS** |
| **B** | Budget Reservation | Post `reserve_budget` mutation | None | YES | YES (0 reserved) | 0 | **PASS** |
| **C** | RESERVED Transition | Post status set to `RESERVED` | None | YES | YES | 0 | **PASS** |
| **D** | Provider Selection | Post router provider selection & state set to `ROUTED` | None | YES | YES | 0 | **PASS** |
| **E** | Attempt Creation | Post `AIProviderAttemptModel` insertion | None (`0 attempts`) | YES | YES | 0 | **PASS** |
| **F** | Provider Execution | Before HTTP/API call invocation | None | YES | YES | 0 | **PASS** |
| **G** | Response Persistence | Post response parsing before budget commit | None | YES | YES | 0 | **PASS** |
| **H** | Budget Commit | Post `commit_execution` calculation | None | YES | YES (0 used) | 0 | **PASS** |
| **I** | Event Staging | Post `stage_budget_committed` in outbox | None | YES | YES | 0 | **PASS** |
| **J** | Pre-Transaction Commit | Immediately prior to `session.commit()` | None | YES | YES | 0 | **PASS** |

---

## 4. Root Cause Analysis: F9 Baseline Recovery Incompatibility

When `karsasec/persistence/postgres_task_repository.py` is kept strictly at its baseline git HEAD (0 diff), `pytest tests/recovery` yields 7 failures:
- `AttributeError: 'PostgresTaskRepository' object has no attribute 'assign_task'`
- `AssertionError: assert orig_evt is not None` (due to missing outbox/audit staging in baseline task creation)

As per security baseline rules, **F9 code MUST NOT be modified to make tests pass**. Therefore, Sprint F10 Phase 5 is formally reported as **BLOCKED** due to baseline task repository contract incompleteness in git HEAD.
