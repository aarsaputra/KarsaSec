# G5.1 — Final Verdict & Architecture Evaluation Report

## Final Gate Verdict
**`G5_INTERNAL_SECURITY_CORRECTNESS = PASS`**
**`G5_EXTERNAL_VALIDITY = PENDING`**

---

## Executive Summary

1. **Blind Evaluation Pipeline (`INVARIANT G5.1-01 & G5.1-02`)**:
   - `BlindDetectorRunner` receives ONLY `source_code`, `language`, `framework`.
   - Multi-property scan runs independently across all 6 supported security properties.
   - Ground truth CWEs, expected statuses, and test IDs are completely isolated from detector.

2. **No Benchmark-Aware Heuristics (`INVARIANT G5.1-03`)**:
   - Removed all string heuristics (`fake_sanitize`, `raw_v`, `unproven`) from test runners and evaluation logic.

3. **Dynamic Mutation Execution (`INVARIANT G5.1-04`)**:
   - Executed 15 mutations dynamically against `BlindDetectorRunner`.
   - Dynamic Mutation Score = **1.0000** (15/15 killed).

4. **140-Case Blind Holdout Execution**:
   - Manifest SHA256: `4082062b42a6633f...`
   - Strict Precision = **0.7692** (95% Wilson CI: `[0.6536, 0.8549]`)
   - Strict Recall = **1.0000** (95% Wilson CI: `[0.9287, 1.0000]`)
   - **Epistemic Decision Correctness (EDC)** = **0.7500** (95% Wilson CI: `[0.6722, 0.8144]`)

5. **Cross-Dataset Validation Integrity (`INVARIANT G5.1-05 & G5.1-06`)**:
   - OWASP 70-case GOLD tier executed dynamically: EDC = **1.0000**.
   - Unexecuted datasets (WebGoat, NodeGoat) marked `NOT_EXECUTED` without hardcoded dictionary metrics.

---

## Unblock Condition for Knowledge Expansion (K1)
Internal security correctness (semantic resolution, sanitizer semantics, authorization propagation, epistemic safety) is **PASS**.
External validity on multi-file business logic remain pending live deployment validation.
K1 Knowledge Pack expansion (JWT/OAuth + Business Logic) is **UNBLOCKED with Epistemic Bounds**.
