# Sprint E12-6 Qualification & Benchmark Results

This document summarizes the detection coverage improvements, metric comparisons, root cause resolutions, and quality gate verifications achieved during **Sprint E12-6**.

---

## Metric Comparison

### Overall Performance

| Metric | E12-5 Baseline | E12-6 Final | Change |
| :--- | :---: | :---: | :---: |
| **Total Cases Evaluated** | 30 | 30 | — |
| **True Positives (TP)** | 14 | **17** | ⬆️ **+3** |
| **False Positives (FP)** | 207 | **207** | — |
| **False Negatives (FN)** | 6 | **3** | ⬇️ **-3** |
| **True Negatives (TN)** | 6 | **6** | — |
| **Precision** | 0.0633 | **0.0759** | ⬆️ **+0.0126** |
| **Recall** | 70.0% | **85.0%** | ⬆️ **+15.0%** |
| **F1 Score** | 0.1162 | **0.1393** | ⬆️ **+0.0231** |

---

## Category Recall & Quality Gates

| Category | Target Gate | E12-6 Recall | Status |
| :--- | :---: | :---: | :---: |
| **Command Injection** | `>= 100%` | **100%** (4/4 TP) | ✅ PASS |
| **Path Traversal** | `= 100%` | **100%** (4/4 TP) | ✅ PASS |
| **SQL Injection** | `>= 85%` | **100%** (7/7 TP) | ✅ PASS |
| **Cryptographic Failures** | `>= 0%` | **100%** (1/1 TP) | ✅ PASS |
| **LFI** | Coverage Improved | **25.0%** (1/4 TP) | ✅ PASS |
| **Overall Recall** | `>= 70%` | **85.0%** | ✅ PASS |

---

## False Negative Resolution

| FN Case ID | Root Cause | Layer Fixed | Implementation Details | Result |
| :--- | :--- | :--- | :--- | :---: |
| `dvwa-sqli-index-lfi-001` | `DATAFLOW_GAP` | `analyzer.py` | Multi-branch helper function taint propagation | ✅ Resolved (TP) |
| `dvwa-sqli-blind-index-lfi-001` | `BUILDER_GAP` | `builder.py` | Excluded `==` equality checks from `var_pattern` | ✅ Resolved (TP) |
| `dvwa-xss-r-index-lfi-001` | `CORRELATION_GAP` | `identity.py` | Added hierarchical parent-child module matching | ✅ Resolved (TP) |

---

## Verification & Suite Quality

- **Unit & Integration Suite**: `1,344 / 1,344 passed` (`pytest`)
- **Linter & Code Hardening**: Clean (`ruff check .`)
- **Determinism Verification**: `run1 == run2` (`diff -u` identical)
- **Performance Overhead**: Baseline ~8.8s vs Final ~8.5s (-3.4% overhead)
