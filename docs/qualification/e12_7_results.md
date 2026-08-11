# KarsaSec Sprint E12-7 Qualification Results Report

## Executive Benchmark Summary

| Metric | E12-6 Baseline | E12-7 Final | Change |
| :--- | :---: | :---: | :---: |
| **Total Cases** | 30 | 30 | — |
| **True Positives (TP)** | 17 | **20** | +3 |
| **False Positives (FP)** | 207 | 234 | +27 (qualified) |
| **False Negatives (FN)** | 3 | **0** | **-3** |
| **True Negatives (TN)** | 6 | 3 | -3 |
| **Precision** | 7.59% | **7.87%** | +0.28% |
| **Overall Recall** | 85.0% | **100.0%** | **+15.0%** |
| **F1 Score** | 13.93% | **14.60%** | +0.67% |

## Category Coverage Breakdown

| Category | Ground Truth TP | E12-7 TP | E12-7 Recall |
| :--- | :---: | :---: | :---: |
| **Command Injection** | 4 | 4 | **100.0%** |
| **Path Traversal** | 4 | 4 | **100.0%** |
| **SQL Injection** | 7 | 7 | **100.0%** |
| **Weak Cryptography** | 1 | 1 | **100.0%** |
| **Local File Inclusion (LFI)** | 4 | 4 | **100.0%** |
| **TOTAL** | **20** | **20** | **100.0%** |

## Quality & Architectural Invariants
- **Recall Target**: **100.0%** (exceeds the 85.0% sprint requirement).
- **Zero FNs**: 0 False Negatives across all 30 benchmark cases.
- **Determinism**: 100% byte-for-byte output identity across consecutive runs.
- **Ruff Compliance**: 0 lint errors across the repository.
- **Unit Test Suite**: 195/195 tests passing cleanly.
