# Phase 10 — Statistical Validity Report (G5.3)

## Statistical Metric Summary

All point estimates are reported alongside sample sizes ($N$) and exact 95% Wilson Score Confidence Intervals.

---

## Executed Dataset Results

### 1. OWASP Benchmark v1.2 (GOLD Tier, $N=70$)
- **Strict Precision**: 1.0000 (95% Wilson CI: `[0.9011, 1.0000]`, $N=35$)
- **Strict Recall**: 1.0000 (95% Wilson CI: `[0.9011, 1.0000]`, $N=35$)
- **False Positive Rate (FPR)**: 0.0000 (95% Wilson CI: `[0.0000, 0.0989]`)
- **Specificity**: 1.0000 (95% Wilson CI: `[0.9011, 1.0000]`)
- **Epistemic Decision Correctness (EDC)**: **1.0000** (95% Wilson CI: `[0.9472, 1.0000]`, $N=70$)

### 2. DVWA Benchmark (BRONZE Tier, $N=24$)
- **Strict Precision**: 1.0000 (95% Wilson CI: `[0.7818, 1.0000]`, $N=14$)
- **Strict Recall**: 1.0000 (95% Wilson CI: `[0.7818, 1.0000]`, $N=14$)
- **False Positive Rate (FPR)**: 0.2000 (95% Wilson CI: `[0.0362, 0.5185]`, $N=10$)
- **Specificity**: 0.8000 (95% Wilson CI: `[0.4815, 0.9638]`, $N=10$)
- **Epistemic Decision Correctness (EDC)**: **0.9167** (95% Wilson CI: `[0.7415, 0.9768]`, $N=24$)

---

## Scientific Framing Statement
> "These statistics describe observed performance on the evaluated dataset artifacts (OWASP Benchmark subset and DVWA manifest) and do not establish universal accuracy across unexecuted real-world web applications."
