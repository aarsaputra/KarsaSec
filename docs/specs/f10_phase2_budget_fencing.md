# Sprint F10 Phase 2 Specification: Atomic Token Budget Fencing & AI Request State Machine

## 1. Overview

Sprint F10 Phase 2 establishes a database-authoritative execution layer for AI requests, token budget fencing, and request state machine lifecycle transitions. It provides crash-safe, race-free financial and token accounting across multi-worker distributed clusters.

---

## 2. Architecture & Service Boundaries

Phase 2 introduces four core modules within `karsasec/ai/`:

1. **`karsasec/ai/exceptions.py`**: Bounded, explicit exception taxonomy (`TokenBudgetExceededError`, `BudgetAccountingError`, `AIRequestStateConflictError`, `InvalidAIRequestStateTransitionError`, `AIRequestNotFoundError`, `AIRequestIdempotencyConflictError`).
2. **`karsasec/ai/state_machine.py`**: State vocabulary definition (`CREATED`, `RESERVED`, `ROUTED`, `IN_FLIGHT`, `PROVIDER_FAILED`, `COMPLETED`, `FAILED`, `CANCELLED`), transition rules, and terminal state checks.
3. **`karsasec/ai/budget.py` (`AIBudgetService`)**: Authoritative token reservation, commit, and release operations using atomic CAS SQL updates.
4. **`karsasec/ai/request.py` (`AIRequestStateService`)**: Request creation, semantic idempotency validation, state transitions, execution commit, and reservation release.

All financial and token mutations operate strictly inside caller-controlled SQL transactions (zero internal `session.commit()` calls).

---

## 3. Atomic SQL Statements

### 3.1 Token Reservation (`INV-F10-BUDGET-01`)
```sql
UPDATE ai_budgets
SET reserved_tokens = reserved_tokens + :request_tokens,
    updated_at = :now
WHERE budget_id = :budget_id
  AND (used_tokens + reserved_tokens + :request_tokens) <= token_limit;
```
*Verification*: `rowcount == 1`. If `rowcount == 0`, raises `TokenBudgetExceededError`.

### 3.2 Token & Cost Commit (`INV-F10-BUDGET-09`)
```sql
UPDATE ai_budgets
SET reserved_tokens = reserved_tokens - :reserved_tokens,
    used_tokens = used_tokens + :actual_tokens,
    used_cost_micro_units = used_cost_micro_units + :actual_cost_micro_units,
    updated_at = :now
WHERE budget_id = :budget_id
  AND reserved_tokens >= :reserved_tokens
  AND (used_cost_micro_units + :actual_cost_micro_units) <= cost_limit_micro_units;
```

### 3.3 Token Release (`INV-F10-BUDGET-10`)
```sql
UPDATE ai_budgets
SET reserved_tokens = reserved_tokens - :tokens_to_release,
    updated_at = :now
WHERE budget_id = :budget_id
  AND reserved_tokens >= :tokens_to_release;
```

### 3.4 Request State Transition (`INV-F10-STATE-07`)
```sql
UPDATE ai_requests
SET status = :new_status,
    updated_at = :now
WHERE request_id = :request_id
  AND status = :expected_status;
```

---

## 4. State Machine Vocabulary & Transitions (`INV-F10-STATE-06`)

```text
CREATED
  ├──> RESERVED
  ├──> CANCELLED
  └──> FAILED

RESERVED
  ├──> ROUTED
  ├──> CANCELLED
  └──> FAILED

ROUTED
  ├──> IN_FLIGHT
  ├──> PROVIDER_FAILED
  ├──> FAILED
  └──> CANCELLED

IN_FLIGHT
  ├──> COMPLETED (Terminal)
  ├──> PROVIDER_FAILED
  ├──> FAILED (Terminal)
  └──> CANCELLED (Terminal)

PROVIDER_FAILED
  ├──> ROUTED
  ├──> FAILED (Terminal)
  └──> CANCELLED (Terminal)
```

Terminal states: `COMPLETED`, `FAILED`, `CANCELLED`. Transitions originating from terminal states or invalid targets raise `InvalidAIRequestStateTransitionError`.

---

## 5. Idempotency & Crash Recovery (`INV-F10-IDEMPOTENCY-04`, `INV-F10-CRASH-13`)

1. **Semantic Identity Verification (`INV-F10-IDEMPOTENCY-05`)**:
   - `create_request()` requires `request_id`, `task_id`, `budget_id`, `prompt_hash`, and `context_hash`.
   - If `request_id` exists with identical metadata, returns existing record.
   - If `request_id` exists with mismatched metadata (different task/budget/hashes), raises `AIRequestIdempotencyConflictError`.
2. **Worker Crash Retry Safety**:
   - If a worker crashes after reservation (`status == RESERVED`), a retry with the same `request_id` detects active reservation and returns without double-reserving budget.
   - Retrying completion or release operations on terminal states is idempotent.

---

## 6. Formal Invariant Traceability

| Invariant ID | Description | Implementation Point | Test Enforcement |
| :--- | :--- | :--- | :--- |
| `INV-F10-BUDGET-01` | Atomic Token Budget Fencing | `AIBudgetService.reserve_tokens` | `test_basic_token_reservation`, `test_budget_exhaustion_rejected` |
| `INV-F10-BUDGET-02` | Atomic Cost Budget Fencing | `AIBudgetService.commit_tokens` (micro-units) | `test_commit_tokens_and_cost` |
| `INV-F10-BUDGET-03` | No Negative Accounting | Single conditional CAS updates | `test_negative_values_rejected`, `test_double_release_fails_or_noop` |
| `INV-F10-IDEMPOTENCY-04` | Durable Request Idempotency | `AIRequestStateService.get_request` boundary | `test_double_reservation_idempotent_no_double_charge` |
| `INV-F10-IDEMPOTENCY-05` | Atomic Request Creation | `AIRequestStateService.create_request` | `test_request_creation_conflict_on_metadata_mismatch` |
| `INV-F10-STATE-06` | Strict Request State Machine | `state_machine.py` | `test_invalid_state_transition_rejected`, `test_valid_state_transitions_allowed` |
| `INV-F10-STATE-07` | Atomic State Transitions | `AIRequestStateService.transition_status` | `test_db_conditional_state_transition` |
| `INV-F10-BUDGET-08` | Reservation / Request State Consistency | `AIRequestStateService.reserve_budget` | `test_basic_token_reservation` |
| `INV-F10-BUDGET-09` | Commit Token Accounting | `AIRequestStateService.commit_execution` | `test_commit_tokens_and_cost` |
| `INV-F10-BUDGET-10` | Reservation Release | `AIRequestStateService.release_reservation` | `test_release_tokens` |
| `INV-F10-CONCURRENCY-11` | No Lost Update | ThreadPool CAS queries | `test_concurrent_reservation_no_lost_update` (120 threads) |
| `INV-F10-CONCURRENCY-12` | Single-Winner State Transition | Conditional status CAS | `test_single_winner_concurrent_state_transition` (50 threads) |
| `INV-F10-CRASH-13` | Crash-Safe Recovery | Session disconnect simulation | `test_crash_retry_recovery_simulation` |
| `INV-F10-AUDIT-14` | No Raw Secret Persistence | Hashes and taxonomy strings | `test_sha256_hash_field_length_and_requiredness` |

---

## 7. Verification Results

- **Phase 2 Budget Tests**: 9 / 9 **PASS** (`tests/ai/test_f10_phase2_budget_fencing.py`)
- **Phase 2 State Machine Tests**: 6 / 6 **PASS** (`tests/ai/test_f10_phase2_state_machine.py`)
- **Phase 2 Idempotency Tests**: 6 / 6 **PASS** (`tests/ai/test_f10_phase2_idempotency.py`)
- **Phase 2 Concurrency Tests**: 2 / 2 **PASS** (`tests/ai/test_f10_phase2_concurrency.py`)
- **F9 Recovery Baseline Tests**: 15 / 15 **PASS** (`tests/recovery/`)
- **Full Regression Suite**: 2354 / 2354 **PASS**
- **Ruff Format & Lint**: **PASS**
- **Protected F9 Files Modified**: **0**
