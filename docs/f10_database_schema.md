# Sprint F10 — Database Schema & ORM Model Specification

## 1. Overview

This document specifies the persistent database foundation for **Sprint F10 — Distributed AI Provider Gateway, Cost Router & Token-Budget Fencing Engine**.

Phase 1 introduces three normalized ORM models into KarsaSec's PostgreSQL persistence layer (`karsasec/persistence/models.py`):
1. **`AIBudgetModel`** (`ai_budgets`): Authoritative tenant token and financial budget ledger.
2. **`AIRequestModel`** (`ai_requests`): Durable AI request and crash-safe idempotency boundary.
3. **`AIProviderAttemptModel`** (`ai_provider_attempts`): Provider execution attempt ledger.

---

## 2. Model Specifications

### 2.1 `AIBudgetModel` (`ai_budgets`)

Stores authoritative token and cost allocations for tenants. All financial values are strictly represented in **integer micro-units** ($1.00 = 1,000,000 micro-units) to prevent floating-point rounding errors.

| Field Name | Type | Constraints | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `budget_id` | `String(128)` | **PRIMARY KEY** | None | Unique budget identifier |
| `tenant_id` | `String(128)` | Non-Null, Indexed | None | Organization/Tenant ID |
| `token_limit` | `BigInteger` | Non-Null, `CHECK >= 0` | `1,000,000` | Maximum token allocation |
| `used_tokens` | `BigInteger` | Non-Null, `CHECK >= 0` | `0` | Committed consumed tokens |
| `reserved_tokens` | `BigInteger` | Non-Null, `CHECK >= 0` | `0` | Active in-flight reserved tokens |
| `cost_limit_micro_units` | `BigInteger` | Non-Null, `CHECK >= 0` | `10,000,000` | Maximum cost in micro-units ($10.00) |
| `used_cost_micro_units` | `BigInteger` | Non-Null, `CHECK >= 0` | `0` | Committed cost in micro-units |
| `created_at` | `DateTime(tz)` | Non-Null | `_utcnow()` | Record creation timestamp |
| `updated_at` | `DateTime(tz)` | Non-Null | `_utcnow()` | Record modification timestamp |

---

### 2.2 `AIRequestModel` (`ai_requests`)

Represents the durable request identity and state machine. The primary key `request_id` acts as the **durable idempotency boundary** preventing duplicate token charges across worker crashes.

| Field Name | Type | Constraints | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `request_id` | `String(128)` | **PRIMARY KEY** | None | Idempotent request boundary |
| `task_id` | `String(128)` | **FK** (`tasks.task_id`), Indexed | None | Parent task reference |
| `budget_id` | `String(128)` | **FK** (`ai_budgets.budget_id`), Indexed | None | Charged budget reference |
| `prompt_hash` | `String(64)` | Non-Null | None | SHA-256 digest of canonical prompt |
| `context_hash` | `String(64)` | Non-Null | None | SHA-256 digest of canonical context |
| `status` | `String(32)` | Non-Null, Indexed, `CHECK IN (...)` | `"CREATED"` | Request state machine status |
| `reserved_tokens` | `BigInteger` | Non-Null, `CHECK >= 0` | `0` | Request token reservation |
| `committed_tokens` | `BigInteger` | Non-Null, `CHECK >= 0` | `0` | Actual committed tokens |
| `actual_cost_micro_units` | `BigInteger` | Non-Null, `CHECK >= 0` | `0` | Actual request cost |
| `selected_provider_id` | `String(64)` | Nullable | `None` | Selected provider (e.g. `anthropic`) |
| `selected_model_id` | `String(64)` | Nullable | `None` | Selected model (e.g. `claude-3-5-sonnet`) |
| `created_at` | `DateTime(tz)` | Non-Null | `_utcnow()` | Request creation timestamp |
| `updated_at` | `DateTime(tz)` | Non-Null | `_utcnow()` | Request modification timestamp |

#### State Machine Vocabulary
Valid values for `status`:
- `"CREATED"`
- `"RESERVED"`
- `"ROUTED"`
- `"IN_FLIGHT"`
- `"PROVIDER_FAILED"`
- `"COMPLETED"` (Terminal)
- `"FAILED"` (Terminal)
- `"CANCELLED"` (Terminal)

---

### 2.3 `AIProviderAttemptModel` (`ai_provider_attempts`)

Records execution attempts for provider failover and debugging. Implements a database-level `UNIQUE(request_id, attempt_number)` constraint.

| Field Name | Type | Constraints | Default | Description |
| :--- | :--- | :--- | :--- | :--- |
| `attempt_id` | `String(128)` | **PRIMARY KEY** | None | Unique attempt ID |
| `request_id` | `String(128)` | **FK** (`ai_requests.request_id`), Indexed | None | Parent request reference |
| `attempt_number` | `Integer` | Non-Null, `CHECK > 0` | None | Sequential attempt index (1, 2, ...) |
| `provider_id` | `String(64)` | Non-Null, Indexed | None | Attempted provider ID |
| `model_id` | `String(64)` | Non-Null | None | Attempted model ID |
| `status` | `String(32)` | Non-Null, Indexed, `CHECK IN (...)` | `"IN_FLIGHT"` | Attempt status |
| `input_tokens` | `BigInteger` | Non-Null, `CHECK >= 0` | `0` | Provider input token usage |
| `output_tokens` | `BigInteger` | Non-Null, `CHECK >= 0` | `0` | Provider output token usage |
| `error_class` | `String(128)` | Nullable | `None` | Bounded error taxonomy string |
| `created_at` | `DateTime(tz)` | Non-Null | `_utcnow()` | Attempt start timestamp |
| `updated_at` | `DateTime(tz)` | Non-Null | `_utcnow()` | Attempt completion timestamp |

---

## 3. Relationships & Conceptual Graph

```text
TaskModel (1) ───< ai_requests (0..N) >─── (1) AIRequestModel
                                                   │
                                                   ├─── (1) AIBudgetModel
                                                   │
                                                   └─── (0..N) AIProviderAttemptModel
```

All foreign keys configure `ondelete="CASCADE"` to ensure relational cleanups without orphaned records.

---

## 4. Financial & Privacy Security Boundaries

1. **Integer Micro-Unit Financial Accounting**:
   - Floating-point data types (`Float`, `Double`) are prohibited.
   - All cost limits and consumption numbers are stored in integer micro-units ($1.00 = 1,000,000 micro-units).
2. **Zero Secret Persistence**:
   - API keys, bearer tokens, authorization headers, raw prompts, raw completions, and raw credentials MUST NOT be persisted in any column.
   - `prompt_hash` and `context_hash` store SHA-256 hex digests strictly.
   - `error_class` stores bounded error taxonomy strings (e.g. `TIMEOUT`, `RATE_LIMIT`, `PROVIDER_UNAVAILABLE`).

---

## 5. Migration & Test Database Compatibility

Models are integrated into `Base.metadata` in `karsasec/persistence/models.py`. Schema creation uses standard SQLAlchemy DDL generation (`Base.metadata.create_all()`) supporting both PostgreSQL in production and SQLite in test environments.
