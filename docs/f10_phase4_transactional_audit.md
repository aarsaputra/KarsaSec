# Sprint F10 Phase 4 — Transactional Outbox & Audit Integration Architecture

## 1. Executive Summary

Sprint F10 Phase 4 integrates the AI request execution lifecycle (`karsasec/ai/`) with KarsaSec's authoritative, transactional event staging (`TransactionalOutbox`) and tamper-evident audit ledger (`TaskAuditLedger`).

All 14 formal invariants (`INV-F10-AUDIT-01` through `INV-F10-AUDIT-14`) have been implemented and verified with 0 modifications to protected Sprint F9 recovery components.

---

## 2. Event Architecture & Lifecycle Mapping

Eight logical AI request lifecycle events are staged within active database transactions:

| Event Type | Logical Transition | Staged By | Audit Chain Integration |
| :--- | :--- | :--- | :--- |
| `AI_BUDGET_RESERVED` | Token reservation approved | `AIEventService.stage_budget_reserved()` | Yes (`CREATED` -> `RESERVED`) |
| `AI_PROMPT_GENERATED` | Prompt & context hashes prepared | `AIEventService.stage_prompt_generated()` | Outbox only (Hashes only) |
| `AI_PROVIDER_SELECTED` | Router selected provider/model | `AIEventService.stage_provider_selected()` | Outbox only (Attempt identity) |
| `AI_PROVIDER_FAILED` | Router/Provider attempt failed | `AIEventService.stage_provider_failed()` | Yes (`ROUTED` -> `PROVIDER_FAILED`) |
| `AI_RESPONSE_RECEIVED` | Provider response tokens received | `AIEventService.stage_response_received()` | Outbox only (Bounded tokens) |
| `AI_BUDGET_COMMITTED` | Actual tokens/cost committed | `AIEventService.stage_budget_committed()` | Yes (`IN_FLIGHT` -> `COMPLETED`) |
| `AI_BUDGET_RELEASED` | Reserved tokens returned | `AIEventService.stage_budget_released()` | Yes (`RESERVED` -> `CANCELLED`) |
| `AI_BUDGET_EXHAUSTED` | Token limit exceeded | `AIEventService.stage_budget_exhausted()` | Outbox only (Requested vs Available) |

---

## 3. Security & Isolation Guarantees

### Secret Isolation (INV-F10-AUDIT-04)
- **Prohibited:** Raw prompts, system prompts, completion text, LLM outputs, API keys (`sk-...`), Bearer tokens, Authorization headers, raw exception tracebacks (`str(exception)`).
- **Enforced:** SHA-256 hex strings for content identification (`prompt_hash`, `context_hash`). Any credential-like prefix in event parameters triggers an immediate `AIEventSecurityError`.

### Bounded Error Taxonomy (INV-F10-AUDIT-08)
Provider failure events accept ONLY bounded error class strings:
- `TIMEOUT`
- `RATE_LIMIT`
- `AUTHENTICATION_FAILED`
- `PROVIDER_UNAVAILABLE`
- `INVALID_REQUEST`
- `NETWORK_ERROR`
- `UNKNOWN_PROVIDER_ERROR`
- `COST_LIMIT`

### Transaction Boundary (INV-F10-AUDIT-02, INV-F10-AUDIT-03)
- `AIEventService` contains **zero** `session.commit()` calls.
- Caller owns transaction lifecycle. If caller raises or rolls back, state mutations, budget counter updates, outbox events, and audit ledger rows roll back atomically.

### Idempotency & Deduplication (INV-F10-AUDIT-09)
Outbox events use `deduplication_key` derived via SHA-256:
```python
deduplication_key = SHA-256(f"{aggregate_type}:{aggregate_id}:{event_type}:{stable_identity}")
```
Re-staging the same event during retries returns the existing staged `OutboxEventModel` without creating duplicate side effects.

### Deterministic Serialization (INV-F10-AUDIT-13)
All event payloads are serialized using canonical JSON:
```python
json.dumps(payload, sort_keys=True, separators=(",", ":"))
```

---

## 4. Invariant Traceability Matrix

| Invariant ID | Verification Test | Result |
| :--- | :--- | :--- |
| `INV-F10-AUDIT-01` | `test_stage_budget_reserved`, `test_stage_budget_committed` | PASS |
| `INV-F10-AUDIT-02` | `test_no_internal_session_commit_in_event_service` | PASS |
| `INV-F10-AUDIT-03` | `test_transaction_rollback_removes_state_budget_and_events` | PASS |
| `INV-F10-AUDIT-04` | `test_api_keys_rejected_in_all_event_fields`, `test_invalid_hash_lengths_rejected` | PASS |
| `INV-F10-AUDIT-05` | `test_stage_provider_selected`, `test_stage_response_received` | PASS |
| `INV-F10-AUDIT-06` | `test_happy_path_event_ordering`, `test_failover_retry_event_ordering` | PASS |
| `INV-F10-AUDIT-07` | `test_different_attempt_ids_produce_distinct_events` | PASS |
| `INV-F10-AUDIT-08` | `test_raw_exception_strings_rejected_in_provider_failed` | PASS |
| `INV-F10-AUDIT-09` | `test_retry_returns_existing_staged_event` | PASS |
| `INV-F10-AUDIT-10` | `test_adv_budget_exhaustion_does_not_coexist_with_committed` | PASS |
| `INV-F10-AUDIT-11` | `test_adv_budget_accounting_is_never_mutated_by_events` | PASS |
| `INV-F10-AUDIT-12` | `test_ai_events_maintain_hash_chain_integrity` | PASS |
| `INV-F10-AUDIT-13` | `test_adv_canonical_json_serialization_is_deterministic` | PASS |
| `INV-F10-AUDIT-14` | `git diff --name-only -- karsasec/recovery/` (0 modified) | PASS |

---

## 5. Test Summary

- **Phase 4 test suite:** 23 / 23 PASSED
- **Events test suite:** 8 / 8 PASSED
- **Recovery test suite:** 15 / 15 PASSED
- **AI total test suite:** 102 / 102 PASSED
- **Full regression suite:** 2419 / 2419 PASSED
- **Ruff format & check:** PASS
