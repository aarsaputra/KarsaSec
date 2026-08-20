# Sprint F10 Phase 3 Specification: Deterministic Cost-Aware AI Provider Router

## 1. Overview

Sprint F10 Phase 3 implements a **deterministic, cost-aware AI provider routing layer** on top of the
Phase 2 token budget fencing and request state machine contracts. The router enforces explicit financial,
capability, and health constraints without introducing any new budget accounting authority.

**Authority boundary (INV-F10-ROUTER-09):**
```text
AIRequestStateService
        │
        ├── AIBudgetService  ← sole authority for ai_budgets
        │
        └── ProviderRouter   ← routing & attempt ledger only
                │
                ├── ProviderRegistry
                ├── ProviderHealthRegistry
                └── Pricing (integer-only)
```

---

## 2. Provider Contract

`ProviderDescriptor` (`karsasec/ai/provider.py`) is an **immutable frozen dataclass** containing:

| Field | Type | Contract |
| :--- | :--- | :--- |
| `provider_id` | `str` | Non-empty identifier |
| `model_id` | `str` | Non-empty model identifier |
| `capabilities` | `frozenset[str]` | Required capabilities (e.g. `chat`, `code`) |
| `priority` | `int ≥ 0` | Lower value = higher routing preference |
| `input_price_micro_units` | `int ≥ 0` | Cost per input token in integer micro-units |
| `output_price_micro_units` | `int ≥ 0` | Cost per output token in integer micro-units |
| `health` | `str` | One of `HEALTHY`, `DEGRADED`, `UNAVAILABLE` |

**Security contracts enforced at construction time:**
- Negative prices are rejected.
- `UNKNOWN` health is **not** a valid descriptor state (use `UNAVAILABLE` explicitly).
- No API keys, bearer tokens, or credentials may appear in any field.

---

## 3. Deterministic Routing Algorithm (INV-F10-ROUTER-01)

Provider selection runs through a strict **6-stage pipeline** on every routing pass:

```text
All registered providers (stable sorted by provider_id, model_id)
        │
[Stage 1] Exclusion list (prior failed attempts)
        │
[Stage 2] Capability compatibility
          required_capabilities ⊆ provider.capabilities
        │
[Stage 3] Health eligibility
          UNKNOWN → rejected (fail-closed, INV-F10-ROUTER-05)
          UNAVAILABLE → rejected
          DEGRADED → eligible only if allow_degraded=True
        │
[Stage 4] Cost ceiling (INV-F10-ROUTER-03/04)
          estimated_cost ≤ max_request_cost_micro_units
          Unknown/negative pricing → rejected (fail-closed)
        │
[Stage 5] Priority sort (lower value = higher preference)
        │
[Stage 6] Stable lexical tie-break: (provider_id ASC, model_id ASC)
        │
        ▼
  Selected Provider
```

**Guarantees:**
- Same input always produces the same output (INV-F10-ROUTER-01).
- Registration order never influences selection (INV-F10-ROUTER-07).
- `random.choice()`, `random.shuffle()`, wall-clock time, and iteration order are **never used**.

---

## 4. Cost Calculation (INV-F10-ROUTER-03, INV-F10-ROUTER-04)

```text
estimated_cost_micro_units =
    estimated_input_tokens  * input_price_micro_units
  + estimated_output_tokens * output_price_micro_units
```

- All values are **non-negative integers** (micro-units: $1.00 = 1,000,000).
- Float arithmetic is **strictly prohibited** — the pricing engine asserts the result is an `int`.
- Negative token counts raise `PricingError` before any calculation.
- Providers whose pricing is missing or negative are rejected (fail-closed, INV-F10-ROUTER-04).

---

## 5. Provider Health States (INV-F10-ROUTER-05)

| State | Routing Eligibility |
| :--- | :--- |
| `HEALTHY` | Always eligible |
| `DEGRADED` | Eligible only when `RoutingPolicy.allow_degraded=True` |
| `UNAVAILABLE` | Always rejected |
| `UNKNOWN` | Always rejected — fail-closed (provider never registered in health registry) |

**Authority Scope:** `ProviderHealthRegistry` state is **process-local** and authoritative for
routing eligibility only. It has **no authority** over token accounting or budget decisions.
If distributed health authority is required, replace the health backend with a PostgreSQL-backed
lease or shared KV store.

---

## 6. Failover Algorithm (INV-F10-ROUTER-02, INV-F10-ROUTER-10)

```text
Attempt 1:
  Router → select_provider(policy, excluded=frozenset())
  → Provider A selected
  → record_attempt(attempt_number=1)
  → Provider A fails

Attempt 2:
  Router → select_provider(policy, excluded={(provider_a_id, model_a_id)})
  → Provider B selected
  → record_attempt(attempt_number=2)
  → Provider B succeeds
```

**Attempt numbering:** `attempt_number = len(excluded) + 1` — strictly 1-indexed and monotonically
increasing (INV-F10-ROUTER-10). The `UNIQUE(request_id, attempt_number)` database constraint is
the authoritative deduplication guard (INV-F10-ROUTER-08).

---

## 7. Attempt Error Taxonomy (INV-F10-ROUTER-09, Security)

`error_class` in `AIProviderAttemptModel` must be one of these bounded strings:

| Error Class | Description |
| :--- | :--- |
| `TIMEOUT` | Request exceeded provider timeout |
| `RATE_LIMIT` | Provider rate limit hit |
| `AUTHENTICATION_FAILED` | Credential validation failed |
| `PROVIDER_UNAVAILABLE` | Provider unreachable |
| `INVALID_REQUEST` | Malformed or rejected request |
| `NETWORK_ERROR` | Network connectivity failure |
| `UNKNOWN_PROVIDER_ERROR` | Unclassified provider error |

**Security:** Raw exception payloads, API keys, bearer tokens, and credential-like strings are
explicitly rejected by `record_attempt()`. Attempting to store them raises `InvalidAttemptError`.

---

## 8. Modules

| Module | Purpose |
| :--- | :--- |
| `karsasec/ai/provider.py` | `ProviderDescriptor`, health states, error taxonomy constants |
| `karsasec/ai/provider_registry.py` | `ProviderRegistry` — descriptor store |
| `karsasec/ai/health.py` | `ProviderHealthRegistry` — process-local health state |
| `karsasec/ai/pricing.py` | Integer-only cost estimation engine |
| `karsasec/ai/routing_policy.py` | `RoutingPolicy` — frozen routing constraint dataclass |
| `karsasec/ai/router.py` | `ProviderRouter` — deterministic selection + attempt ledger |

---

## 9. Formal Invariant Traceability

| Invariant ID | Description | Implementation Point | Test Enforcement |
| :--- | :--- | :--- | :--- |
| `INV-F10-ROUTER-01` | Deterministic Provider Selection | `ProviderRouter.select_provider` 6-stage pipeline | `test_same_input_produces_identical_selection`, `test_repeated_routing_100x_deterministic` |
| `INV-F10-ROUTER-02` | Deterministic Failover | Excluded set + `select_provider` | `test_primary_failure_deterministic_fallback`, `test_repeated_failover_identical_ordering` |
| `INV-F10-ROUTER-03` | Cost Ceiling Enforcement | `is_within_cost_ceiling()` in Stage 4 | `test_cost_above_ceiling_rejected`, `test_exact_cost_ceiling_accepted` |
| `INV-F10-ROUTER-04` | Unknown Pricing Fails Closed | `PricingError` in Stage 4 | `test_pricing_estimation_negative_tokens_rejected` |
| `INV-F10-ROUTER-05` | Unknown Health Fails Closed | `HEALTH_UNKNOWN` → excluded in Stage 3 | `test_unknown_health_rejected`, `test_unavailable_provider_rejected` |
| `INV-F10-ROUTER-06` | Capability Compatibility | Subset check in Stage 2 | `test_capability_mismatch_rejected` |
| `INV-F10-ROUTER-07` | Stable Tie-Breaking | `sort_key = (priority, provider_id, model_id)` | `test_equal_priority_stable_lexical_tie_break`, `test_different_registration_order_identical_selection` |
| `INV-F10-ROUTER-08` | Provider Attempt Identity | `record_attempt()` with DB UNIQUE constraint | `test_unique_attempt_numbers_enforced`, `test_attempt_numbers_increment_across_failovers` |
| `INV-F10-ROUTER-09` | No Process-Local Financial Authority | Router never calls `session.execute` on `ai_budgets` | `test_router_does_not_touch_budget_counters`, `test_budget_not_debited_by_routing_decision` |
| `INV-F10-ROUTER-10` | Failover Attempt Ordering | `attempt_number = len(excluded) + 1` | `test_repeated_failover_identical_ordering`, `test_attempt_numbers_increment_across_failovers` |

---

## 10. Verification Results

- `tests/ai/test_f10_phase3_provider_registry.py`: **10 / 10 PASS**
- `tests/ai/test_f10_phase3_router_determinism.py`: **6 / 6 PASS**
- `tests/ai/test_f10_phase3_cost_routing.py`: **6 / 6 PASS**
- `tests/ai/test_f10_phase3_health_failover.py`: **8 / 8 PASS**
- `tests/ai/test_f10_phase3_attempt_identity.py`: **6 / 6 PASS**
- `tests/ai/test_f10_phase3_adversarial.py`: **6 / 6 PASS**
- **Phase 3 Total: 42 / 42 PASS**
- `tests/ai/` (all phases): **79 / 79 PASS**
- `tests/recovery/` (F9 baseline): **15 / 15 PASS**
- **Full Regression: 2396 / 2396 PASS**
- **Ruff Format & Lint: PASS**
- **F9 Protected Recovery/Audit/Outbox Files Modified: 0**

---

## 11. Concurrency Model & SQLite Disclaimer

Phase 3 unit tests use **SQLite in-memory** for functional correctness and determinism verification.
Per the established project standard (user requirement from Phase 3 approval):

> Unit tests may use SQLite; concurrency/security proof for PostgreSQL must use PostgreSQL-backed tests.

The `UNIQUE(request_id, attempt_number)` constraint proof (`test_unique_attempt_numbers_enforced`)
demonstrates the DB-level deduplication contract. Full distributed concurrent attempt number uniqueness
proof requires a PostgreSQL-backed test suite (Phase 5 adversarial audit scope).
