# Phase 7 — Mutation Oracle Integrity Audit Report (G5.3)

## Audit Overview
Audit of `karsasec/benchmark/mutation_runner.py` and `tests/benchmark/test_g5_external_mutation_integrity.py`.

---

## 1. Dynamic Execution Requirements
- **Baseline Verdict**: Computed strictly via `detector.analyze_blind(original_code)`.
- **Mutated Verdict**: Computed strictly via `detector.analyze_blind(mutated_code)`.
- **Dynamic Transition Evaluation**:
  `is_killed` is determined strictly by comparing live `baseline_verdict` against live `mutated_verdict`.

---

## 2. Invariant Audit Matrix

| Transition Pattern | Dynamic Baseline | Dynamic Mutated | Expected Oracle Outcome | Result |
|:---|:---:|:---:|:---:|:---:|
| **Source Removal** | `VULNERABLE` | `SAFE` | `KILLED` | **PASS** |
| **Sanitizer Removal** | `SAFE` | `VULNERABLE` | `KILLED` | **PASS** |
| **Unproven Wrapper Modify** | `UNKNOWN` | `UNKNOWN` | `SURVIVED` | **PASS** |
| **Same Safe Output** | `SAFE` | `SAFE` | `SURVIVED` | **PASS** |

---

## 3. Epistemic Safety Verification (`INV-G5.3-06`)
- `UNKNOWN -> UNKNOWN` transitions strictly evaluate to **`SURVIVED`** (`is_killed = False`).
- The mutation oracle NEVER assumes `expected_transition` shortcut overrides over live detector execution.
