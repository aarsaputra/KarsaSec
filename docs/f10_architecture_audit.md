# Sprint F10 — Architecture Audit & Technical Blueprint

## 1. Executive Summary

This architecture audit evaluates KarsaSec's existing AI abstractions, persistence substrate, eventing mechanics, and security boundaries to prepare for **Sprint F10 — Distributed AI Provider Gateway, Cost Router & Token-Budget Fencing Engine**.

The objective of Sprint F10 is to bridge KarsaSec's AI layer (`karsasec/ai/`) with the hardened distributed PostgreSQL execution layer established in Sprints F4–F9.

---

## 2. Existing AI Architecture Analysis

### 2.1 Provider Abstractions (`karsasec/ai/explainer/agent.py` & `karsasec/ai/remediation/provider.py`)
- **`LLMProviderProtocol`**: A simple protocol defining `def generate(self, system_prompt: str, user_prompt: str) -> str`.
- **`MockLLMProvider`**: In-memory deterministic mock used for unit testing.
- **`LLMPatchProvider`**: Wrapper around patch generation strategies that delegates to `LLMProviderProtocol` or falls back to template synthesis.
- **Gaps**: No provider health monitoring, no token tracking, no cost metrics, no rate limiting, no provider priority/failover router, and no database persistence.

### 2.2 Persistence Substrate (`karsasec/persistence/models.py`)
- **Existing Models**: `TaskModel`, `WorkerModel`, `RecoveryLeaseModel`, `OutboxEventModel`, `TaskAuditLogModel`, `ReceiptModel`, `AuditEventModel`, `RecoveryCheckpointModel`.
- **Gaps**: Zero database models for AI budgets, token reservations, provider pricing, or AI request state machines.

### 2.3 Eventing & Audit Subsystem (`karsasec/events/`)
- **`TransactionalOutbox`**: Stages events inside PostgreSQL transactions (`OutboxEventModel`).
- **`TaskAuditLedger`**: Append-only cryptographic hash-chained audit log (`TaskAuditLogModel`).
- **Integration Strategy**: All AI execution events must stage transactionally in `OutboxEventModel` and `TaskAuditLogModel` without introducing parallel event mechanisms.

### 2.4 Configuration (`karsasec/config.py`)
- **Current LLM Settings**: `default_llm_model: str = "gemini-2.5-flash"`.
- **Gaps**: Lacks explicit multi-provider pricing models, micro-unit cost thresholds, and token budget policies.

---

## 3. Identified Distributed System & Security Risks

1. **TOCTOU Budget Race**: In-memory or non-atomic SQL budget checks allow parallel workers to overspend allocated token budgets.
2. **Double Charging on Worker Crash**: If a worker crashes after receiving an LLM response but before persisting state, retrying could re-reserve and double-charge tokens.
3. **Non-Deterministic Routing**: Using random selection or unordered dictionary iteration for fallback providers creates non-reproducible execution paths.
4. **Secret Exposure in Audit/Logs**: Provider API keys or raw credentials could leak into transactional outbox payloads, audit ledger entries, or Prometheus metrics.
5. **Unbounded Metric Cardinality**: Recording raw `request_id`, `prompt_hash`, or exception strings in Prometheus metrics causes memory exhaustion.

---

## 4. Proposed Sprint F10 Target Architecture

```text
               AI Remediation / RCA Agent
                           │
                           ▼
          Canonical AI Context Serialization
               (json.dumps + SHA256)
                           │
                           ▼
        PostgreSQL Atomic Token Budget Fencer
     (UPDATE ai_budgets SET used_tokens = ...)
                           │
                           ▼
          Deterministic Cost-Aware Router
  (Health Check → Cost Micro-Units → Policy Priority)
                           │
                           ▼
             Transactional Outbox & Audit
(AI_PROMPT_GENERATED, AI_RESPONSE_RECEIVED, etc.)
```

### 4.1 Proposed Database Schema & ORM Models
To satisfy `INV-F10-BUDGET-01` through `INV-F10-RECOVERY-02`, we define normalized persistence models in `karsasec/persistence/models.py`:

1. **`AIBudgetModel`**:
   - `budget_id` (PK, String(128))
   - `tenant_id` (String(128), index)
   - `token_limit` (BigInteger, default=1,000,000)
   - `used_tokens` (BigInteger, default=0)
   - `reserved_tokens` (BigInteger, default=0)
   - `cost_limit_micro_units` (BigInteger, default=10,000,000)  # $10.00 in micro-units
   - `used_cost_micro_units` (BigInteger, default=0)

2. **`AIRequestModel`**:
   - `request_id` (PK, String(128))
   - `task_id` (String(128), ForeignKey, index)
   - `budget_id` (String(128), ForeignKey, index)
   - `prompt_hash` (String(64), nullable=False)
   - `context_hash` (String(64), nullable=False)
   - `status` (String(32), default="CREATED", index)  # State Machine
   - `reserved_tokens` (BigInteger, default=0)
   - `committed_tokens` (BigInteger, default=0)
   - `actual_cost_micro_units` (BigInteger, default=0)
   - `selected_provider_id` (String(64), nullable=True)
   - `selected_model_id` (String(64), nullable=True)

3. **`AIProviderAttemptModel`**:
   - `attempt_id` (PK, String(128))
   - `request_id` (String(128), ForeignKey, index)
   - `attempt_number` (Integer, default=1)
   - `provider_id` (String(64), nullable=False)
   - `model_id` (String(64), nullable=False)
   - `status` (String(32), default="IN_FLIGHT")
   - `input_tokens` (Integer, default=0)
   - `output_tokens` (Integer, default=0)
   - `error_class` (String(128), nullable=True)

---

### 4.2 AI Request State Machine (`INV-F10-CONCURRENCY-02`)

```text
[CREATED]
    │
    ▼ (reserve_tokens atomic CAS)
[RESERVED]
    │
    ▼ (select_provider deterministic router)
[ROUTED]
    │
    ▼ (provider attempt started)
[IN_FLIGHT] ───(attempt failed, retry eligible)──► [PROVIDER_FAILED]
    │                                                   │
    │ (success)                                         └── (fallback) ──► [ROUTED]
    ▼
[COMPLETED] ──► (commit_tokens atomic CAS)
```

---

### 4.3 Atomic Token Budget Fencing (`INV-F10-BUDGET-01` & `INV-F10-BUDGET-02`)

All budget reservations and token commits MUST be executed via atomic SQL statements with rowcount verification (`rowcount == 1`):

```python
# Atomic Token Reservation
stmt = (
    update(AIBudgetModel)
    .where(
        AIBudgetModel.budget_id == budget_id,
        AIBudgetModel.used_tokens + AIBudgetModel.reserved_tokens + request_tokens <= AIBudgetModel.token_limit,
    )
    .values(
        reserved_tokens=AIBudgetModel.reserved_tokens + request_tokens,
        updated_at=func.now(),
    )
)
result = session.execute(stmt)
if result.rowcount == 0:
    raise TokenBudgetExceededError(f"Token budget '{budget_id}' exceeded or exhausted.")
```

---

### 4.4 Deterministic Provider Router & Cost Accounting (`INV-F10-ROUTER-01` to `INV-F10-ROUTER-03`)

- **Cost Representation**: Financial figures are stored as integer micro-units ($1.00 = 1,000,000 micro-units) to eliminate floating point rounding errors.
- **Provider Priority Evaluation**: Evaluated in strict deterministic order:
  1. Policy Priority List (e.g. `anthropic` → `openai` → `ollama` → `vllm`).
  2. Health Verification (Circuit breaker status check).
  3. Cost Threshold Verification (Estimated request cost $\le$ maximum allowed request budget).
  4. Fail-Closed Default (If pricing or health is unknown, provider is rejected with `ProviderUnavailableError`).

---

### 4.5 Prompt & Context Hashing (`INV-F10-SNAP-01`)

Canonical prompt payloads are generated via `json.dumps(payload, sort_keys=True, separators=(',', ':'))` and hashed via SHA-256 (`context_hash`). Any semantic difference produces a distinct hash; whitespace/dictionary order differences produce identical hashes.

---

### 4.6 Transactional Outbox & Audit Integration (`INV-F10-AUDIT-01`)

AI lifecycle events stage transactionally via `TransactionalOutbox.stage_event()` and `TaskAuditLedger.record_transition()`:
- `AI_BUDGET_RESERVED`
- `AI_PROMPT_GENERATED`
- `AI_PROVIDER_SELECTED`
- `AI_PROVIDER_FAILED`
- `AI_RESPONSE_RECEIVED`
- `AI_BUDGET_COMMITTED`
- `AI_BUDGET_RELEASED`
- `AI_BUDGET_EXHAUSTED`

---

## 5. Phase 0 Verification

Running verification on existing test suites to confirm complete system stability before starting Phase 1:

```bash
pytest tests/recovery/ -v
pytest -q
ruff format --check karsasec tests
ruff check karsasec tests
```

---

## 6. Architecture Audit Status

Phase 0 Architecture Audit is **COMPLETE**. No production code modifications have been made. Ready for user review before proceeding to **Phase 1 (Database Schema & ORM Models)**.
