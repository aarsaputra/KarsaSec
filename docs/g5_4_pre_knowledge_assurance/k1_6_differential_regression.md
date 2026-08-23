# K1.6 Independent Differential Regression Audit Report

## 1. Executive Summary (`INV-K1.6-02`)
The differential validation engine (`karsasec/benchmark/k1_differential.py`) evaluated normalized finding identity $D_{\text{current}}(\text{source}) == \text{Baseline}_{\text{K1.4\_independent}}(\text{source})$ across all 40 original certification fixtures. Baseline findings were constructed directly from the certified K1.4 ground-truth manifest specifications without relying on `analyze_k1()` execution during validation.

## 2. Independent Differential Matrix

| Metric | Independent Baseline Count | Current Count | Added Findings | Removed Findings | Status |
|:---|---:|---:|---:|---:|:---:|
| True Positives (TP) | 22 | 22 | 0 | 0 | **EQUIVALENT** |
| True Negatives (TN) | 18 | 18 | 0 | 0 | **EQUIVALENT** |
| False Positives (FP) | 0 | 0 | 0 | 0 | **EQUIVALENT** |
| False Negatives (FN) | 0 | 0 | 0 | 0 | **EQUIVALENT** |

## 3. Verification Result
- **Added Findings**: 0
- **Removed Findings**: 0
- **Differential Status**: 100% **EQUIVALENT**

Verified via `tests/benchmark/test_k1_6_differential_regression.py`.
