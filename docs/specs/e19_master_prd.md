# Master PRD — Sprint E19: Threat Intelligence & Risk Context

## 1. Executive Summary

Sprint E19 introduces **Threat Intelligence & Risk Context** to KarsaSec. It enriches vulnerability clusters and control plane decisions with deterministic risk weighting, asset criticality context, and threat landscape feeds while maintaining 100% determinism.

```text
E9–E18 Baseline
       ↓
  E19 Threat Intelligence & Risk Context
     ├── Threat Intel Registry
     ├── Threat Context Scorer
     └── Risk Context Record
```

---

## 2. Invariants & Security Guarantees

1. **INV-E19-TI-01 (Deterministic Scoring)**: All risk scores must be deterministically computed from frozen snapshot inputs without live time-varying HTTP calls during evaluation.
2. **INV-E19-TI-02 (Fail-Closed Default)**: Unknown threat context defaults to conservative high-risk weighting (0.50 minimum).
3. **INV-E19-TI-03 (Score Bounds Protection)**: Risk scores are strictly clamped between 0.0 and 1.0.
4. **INV-E19-TI-04 (Zero Upstream Mutation)**: E9–E18 code remains 100% frozen.
