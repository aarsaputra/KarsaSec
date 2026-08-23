# K1.5 Baseline Non-Degradation & Regression Audit Report

## 1. Ground-Truth 40-Case Performance
- **Original 40 Cases**: 22 TP, 18 TN, 0 FP, 0 FN (1.0000 Precision, 1.0000 Recall)
- **External Benchmarks**: OWASP Benchmark v1.2 (1.0000 Precision / 1.0000 Recall) and DVWA (1.0000 Precision / 1.0000 Recall) maintained 0% regression.

## 2. F9 Protected Components Zero-Diff Audit
- `karsasec/recovery/`: 0 modified files
- `karsasec/events/audit_ledger.py`: 0 modified files
- `karsasec/events/outbox.py`: 0 modified files

## 3. Original Corpus Lock Audit
- `benchmarks/k1/manifest.json`: 0 modified files
- `benchmarks/k1/holdout_manifest.json`: 0 modified files
- `benchmarks/k1/development/`, `validation/`, `holdout/`: 0 modified files
