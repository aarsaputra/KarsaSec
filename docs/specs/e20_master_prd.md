# Master PRD — Sprint E20: Autonomous Security Operations

## 1. Executive Summary

Sprint E20 introduces **Autonomous Security Operations** with strict circuit breakers, blast radius boundaries, action budgets, and mandatory Shadow-Mode operational mode.

```text
E9–E19 Baseline
       ↓
  E20 Autonomous Security Operations
     ├── Circuit Breaker Engine
     ├── Action Proposal Engine
     └── Shadow-Mode Ledger
```

---

## 2. Circuit Breaker & Operational Parameters (§3.5)

- `max_auto_block_per_window`: Maximum automated blocking actions allowed within evaluation window (Default: 5).
- `action_budget`: Maximum total autonomous operations allowed per session (Default: 10).
- `time_budget_seconds`: Maximum time allowed per autonomous action cycle (Default: 30s).
- `retry_budget`: Maximum retry attempts on failed actions (Default: 2).

---

## 3. Invariants & Security Guarantees

1. **INV-E20-AO-01 (Shadow-Mode Default)**: Autonomous actions MUST generate an `ActionProposal` for human review by default unless shadow-mode is explicitly completed (§3.3).
2. **INV-E20-AO-02 (Circuit Breaker Enforcement)**: Exceeding `max_auto_block_per_window` or `action_budget` immediately triggers circuit trip, halting further automated actions.
3. **INV-E20-AO-03 (Fail-Closed Default)**: Invalid proposal state or missing budget configuration trips circuit breaker.
4. **INV-E20-AO-04 (Zero Upstream Mutation)**: E9–E19 code remains 100% frozen.
