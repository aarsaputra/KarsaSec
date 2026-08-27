# G5.1 — Statistical Validity & Metrics Report

## Audit Purpose
Provide rigorous statistical definitions separating Detection Recall/Precision from Epistemic Decision Correctness (EDC), with 95% Wilson Confidence Intervals (**INVARIANT G5.1-07 & G5.1-08**).

---

## 1. Metric Definitions

- **Strict Precision**:
  $$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$$
- **Strict Recall**:
  $$\text{Recall} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$
- **Epistemic Decision Correctness (EDC)**:
  $$\text{EDC} = \frac{\text{correct\_TP} + \text{correct\_TN} + \text{correct\_UNKNOWN} + \text{correct\_CONFLICT}}{N}$$

---

## 2. 140-Case Blind Holdout Statistical Metrics

| Metric | Sample Size ($N$) | Point Estimate | 95% Wilson Lower | 95% Wilson Upper |
|:---|:---:|:---:|:---:|:---:|
| **Strict Precision** | 65 | 0.7692 | 0.6536 | 0.8549 |
| **Strict Recall** | 50 | 1.0000 | 0.9287 | 1.0000 |
| **False Positive Rate (FPR)** | 50 | 0.3000 | 0.1882 | 0.4411 |
| **Specificity** | 50 | 0.7000 | 0.5589 | 0.8118 |
| **Epistemic Decision Correctness (EDC)** | 140 | **0.7500** | **0.6722** | **0.8144** |

---

## 3. Scientific Framing Statement

> "These statistics describe observed performance on the evaluated holdout dataset and do not establish universal real-world accuracy."
