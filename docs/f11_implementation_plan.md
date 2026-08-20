# Sprint F11 — Implementation Plan: AI Gateway Resilience & Provider Execution Security

**Date**: 2026-08-20
**Target Repository**: `karsasec`
**Status**: In Progress (F11.1, F11.2, F11.3 & F11.4 Complete)

---

## Component Breakdown & Implementation Roadmap

```text
F11.1 Provider Execution Boundary [COMPLETED - 7a59d71]
  ↓
F11.2 Hard Timeout Isolation [COMPLETED - 5899c37]
  ↓
F11.3 Failure Classification Engine [COMPLETED - d72ce7f]
  ↓
F11.4 Bounded Retry Engine [COMPLETED - INV-F11-RETRY-02/03, INV-F11-BACKOFF-04, ADV-02/03/04/10 PASS]
  ↓
F11.5 Circuit Breaker Engine [NEXT]
  ↓
F11.6 Distributed Rate Limiter
  ↓
F11.7 Provider Concurrency Guard
  ↓
F11.8 SSRF & Transport Security Policy
  ↓
F11.9 Resource, Secret & Metrics Hardening
  ↓
F11.10 Adversarial Security Test Suite
```

---

### Progress Record

#### F11.1: Provider Execution Boundary
- **Files Modified**: `karsasec/ai/execution.py` `[NEW]`, `tests/ai/test_f11_phase5_execution_boundary.py` `[NEW]`
- **Status**: **COMPLETE** (Commit `7a59d71`)

#### F11.2: Hard Timeout Isolation
- **Target Invariants**: `INV-F11-TIMEOUT-01`
- **Target Adversarial Test**: `ADV-01` (`test_hard_timeout_aborts_hanging_worker`)
- **Files Modified**: `karsasec/ai/execution.py` `[UPDATED]`, `tests/ai/test_f11_phase5_execution_boundary.py` `[UPDATED]`
- **Status**: **COMPLETE** (Commit `5899c37`)

#### F11.3: Deterministic Failure Classification Engine
- **Target Invariants**: `INV-F11-FAILURE-15`
- **Target Adversarial Tests**: `ADV-17` (`test_malformed_response_json_failure_classification`), `ADV-20` (`test_circuit_breaker_does_not_trip_on_4xx_client_errors`)
- **Files Modified**: `karsasec/ai/provider.py` `[UPDATED]`, `karsasec/ai/failure_classifier.py` `[NEW]`, `tests/ai/test_f11_phase5_failure_classifier.py` `[NEW]`
- **Status**: **COMPLETE** (Commit `d72ce7f`)

#### F11.4: Bounded Retry & Backoff Engine
- **Target Invariants**: `INV-F11-RETRY-02`, `INV-F11-RETRY-03`, `INV-F11-BACKOFF-04`
- **Target Adversarial Tests**: `ADV-02` (`test_retry_storm_exponential_backoff_and_cap`), `ADV-03` (`test_retry_amplification_bounded_at_max_attempts`), `ADV-04` (`test_concurrent_retry_idempotency_locking`), `ADV-10` (`test_duplicate_attempt_creation_rejection`)
- **Files Modified**: `karsasec/ai/retry.py` `[NEW]`, `karsasec/ai/execution.py` `[UPDATED]`, `tests/ai/test_f11_phase5_retry.py` `[NEW]`
- **Verification**: Verified hard limit $N_{max} \le 3$, failure eligibility integration with `FailureClassifier`, exponential backoff with full jitter capped at 30s, atomic database uniqueness locking on `(request_id, attempt_number)`, budget safety, and idempotency.
- **Status**: **COMPLETE**

---

## Frozen Component Immutability Guarantee

The following files are strictly **FROZEN** and remain **0 diff**:
- `karsasec/recovery/`
- `karsasec/events/audit_ledger.py`
- `karsasec/events/outbox.py`
