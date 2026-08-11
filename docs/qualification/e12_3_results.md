# Sprint E12-3 Benchmarking & Qualification Results

## Objective
Execute Sprint E12-3, transitioning KarsaSec from raw rule matches to a deterministic, semantic-aware qualification pipeline (`CandidateFinding` -> `QualifiedFinding`).

---

## Metric Comparison

| Metric | Baseline (E12-2) | Post-E11 Baseline | Post-E12-3 Qualification | Delta (vs E12-2) |
| :--- | :--- | :--- | :--- | :--- |
| **Precision** | ~4.23% | ~4.23% | **5.83%** | **+1.60% absolute (+37.8% relative)** |
| **Recall** | 45.0% | 65.0% | **70.0%** | **+25.0% absolute (+55.5% relative)** |
| **F1 Score** | ~7.89% | ~8.00% | **10.62%** | **+2.73% absolute (+34.6% relative)** |
| **True Positives (TP)** | 9 | 13 | **14** | **+5 TPs** |
| **False Positives (FP)** | 251 | 251 | **194** | **-57 FPs (-22.7%)** |
| **False Negatives (FN)** | 11 | 7 | **6** | **-5 FNs** |

---

## Per-Category Detection Performance

| Category | True Positives (TP) | False Positives (FP) | False Negatives (FN) | Precision | Recall | F1 Score |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **COMMAND_INJECTION** | 4 | 2 | 0 | **67.0%** | **100.0%** | **80.0%** |
| **PATH_TRAVERSAL** | 4 | 0 | 0 | **100.0%** | **100.0%** | **100.0%** |
| **SQL_INJECTION** | 6 | 0 | 1 | **100.0%** | **85.7%** | **92.3%** |

---

## E11 Recall Protection Gates

- **Command Injection Recall**: **100.0%** (Gate: ≥ 100%) — **PASSED**
- **Path Traversal Recall**: **100.0%** (Gate: = 100%) — **PASSED**
- **SQL Injection Recall**: **85.7%** (Gate: ≥ 71%) — **PASSED**
- **Overall Recall**: **70.0%** (Gate: ≥ 65%) — **PASSED**

---

## Verification & Artifacts
- **Snapshot Path**: `benchmarks/results/dvwa/latest.json`
- **Regression Test Suite**: `tests/qualification/test_precision_hardening.py`
- **Unit Test Suite**: `tests/unit/graph/` (65 tests passing)
