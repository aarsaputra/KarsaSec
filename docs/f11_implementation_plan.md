# Sprint F11 — Implementation Plan: AI Gateway Resilience & Provider Execution Security

**Date**: 2026-08-20  
**Target Repository**: `karsasec`  
**Status**: In Progress (F11.1 & F11.2 Complete)  

---

## Component Breakdown & Implementation Roadmap

```text
F11.1 Provider Execution Boundary [COMPLETED - 7a59d71]
  ↓
F11.2 Hard Timeout Isolation [COMPLETED - INV-F11-TIMEOUT-01, ADV-01 PASS]
  ↓
F11.3 Failure Classification Engine [NEXT]
  ↓
F11.4 Bounded Retry Engine
  ↓
F11.5 Circuit Breaker Engine
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
- **Verification**: `ADV-01` passes in 0.05s. Hanging coroutine task receives `asyncio.CancelledError` signal (`executor.cancelled == True`), reservation tokens released cleanly, status transitions to `FAILED`, taxonomy mapped to `ATTEMPT_ERROR_TIMEOUT`.
- **Status**: **COMPLETE**

---

## Frozen Component Immutability Guarantee

The following files are strictly **FROZEN** and remain **0 diff**:
- `karsasec/recovery/`
- `karsasec/events/audit_ledger.py`
- `karsasec/events/outbox.py`
